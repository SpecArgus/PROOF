"""Bounded supervisor for the isolated OpenAPI validator worker."""

from __future__ import annotations

import base64
import json
import os
import signal
import subprocess
import sys
import threading
import time
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any, BinaryIO

from proof_core.input_closure import InputClosure

PROTOCOL_VERSION = 1
WORKER_NAME = "openapi-spec-validator"
WORKER_VERSION = "0.9.0"
MAX_REQUEST_BYTES = 32 * 1024 * 1024
MAX_EMITTED_DIAGNOSTICS = 100
MAX_OBSERVED_DIAGNOSTICS = 2_048
MAX_VALIDATOR_WALL_SECONDS = 5.0
MAX_PROCESS_OUTPUT_BYTES = 1024 * 1024
_READ_CHUNK = 64 * 1024


class WorkerFailure(RuntimeError):
    """A validator process failure that must not be treated as scan success."""

    def __init__(self, code: str, kind: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.kind = kind

    def to_dict(self) -> dict[str, str]:
        return {"code": self.code, "kind": self.kind, "message": str(self)}


@dataclass(frozen=True, slots=True)
class WorkerLimits:
    """Inclusive protocol and process limits for one validator invocation."""

    max_diagnostics: int = 100
    timeout_seconds: float = MAX_VALIDATOR_WALL_SECONDS
    max_stdout_bytes: int = MAX_PROCESS_OUTPUT_BYTES
    max_stderr_bytes: int = MAX_PROCESS_OUTPUT_BYTES
    max_output_bytes: int = MAX_PROCESS_OUTPUT_BYTES

    def __post_init__(self) -> None:
        if (
            isinstance(self.max_diagnostics, bool)
            or not isinstance(self.max_diagnostics, int)
            or not 0 <= self.max_diagnostics <= MAX_EMITTED_DIAGNOSTICS
        ):
            raise ValueError(
                "max_diagnostics must be an integer between 0 and "
                f"{MAX_EMITTED_DIAGNOSTICS}"
            )
        if (
            isinstance(self.timeout_seconds, bool)
            or not isinstance(self.timeout_seconds, (int, float))
            or not 0 < self.timeout_seconds <= MAX_VALIDATOR_WALL_SECONDS
        ):
            raise ValueError(
                "timeout_seconds must be greater than 0 and at most "
                f"{MAX_VALIDATOR_WALL_SECONDS:g}"
            )
        for name in ("max_stdout_bytes", "max_stderr_bytes", "max_output_bytes"):
            value = getattr(self, name)
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or not 1 <= value <= MAX_PROCESS_OUTPUT_BYTES
            ):
                raise ValueError(
                    f"{name} must be an integer between 1 and "
                    f"{MAX_PROCESS_OUTPUT_BYTES}"
                )


@dataclass(frozen=True, slots=True)
class ValidatorDiagnostic:
    source: str | None
    line: int | None
    column: int | None
    pointer: str | None
    code: str
    severity: str
    kind: str
    message: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "line": self.line,
            "column": self.column,
            "pointer": self.pointer,
            "code": self.code,
            "severity": self.severity,
            "kind": self.kind,
            "message": self.message,
        }


@dataclass(frozen=True, slots=True)
class ValidatorResult:
    entrypoint: str
    manifest_digest: str
    outcome: str
    diagnostics: tuple[ValidatorDiagnostic, ...]
    diagnostics_observed: int
    diagnostics_truncated: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "entrypoint": self.entrypoint,
            "manifestDigest": self.manifest_digest,
            "outcome": self.outcome,
            "diagnostics": [item.to_dict() for item in self.diagnostics],
            "stats": {
                "diagnosticsObserved": self.diagnostics_observed,
                "diagnosticsEmitted": len(self.diagnostics),
                "diagnosticsTruncated": self.diagnostics_truncated,
            },
        }


@dataclass(slots=True)
class _PipeCapture:
    limit: int
    data: bytearray
    exceeded: threading.Event
    budget: _OutputBudget


@dataclass(slots=True)
class _OutputBudget:
    limit: int
    observed: int
    lock: threading.Lock
    exceeded: threading.Event


class _DuplicateKeyError(ValueError):
    pass


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKeyError(key)
        result[key] = value
    return result


def _reject_constant(token: str) -> None:
    raise ValueError(token)


def _compact_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _build_request(
    closure: InputClosure,
    entrypoint: str,
    limits: WorkerLimits,
) -> bytes:
    value = {
        "protocolVersion": PROTOCOL_VERSION,
        "operation": "validate",
        "entrypoint": entrypoint,
        "manifest": closure.manifest.to_dict(),
        "resources": [
            {
                "path": item.path,
                "content": base64.b64encode(item.content).decode("ascii"),
                "digest": item.digest,
            }
            for item in closure.resources
        ],
        "limits": {"maxDiagnostics": limits.max_diagnostics},
    }
    raw = _compact_json(value)
    if len(raw) > MAX_REQUEST_BYTES:
        raise WorkerFailure(
            "worker.request-limit",
            "limit",
            "The validator request exceeds the process protocol byte limit.",
        )
    return raw


def _child_environment() -> dict[str, str]:
    allowed = (
        "COMSPEC",
        "LANG",
        "LC_ALL",
        "PATH",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "TMPDIR",
        "WINDIR",
    )
    environment = {name: os.environ[name] for name in allowed if name in os.environ}
    environment.update(
        {
            "NO_PROXY": "*",
            "OPENAPI_SPEC_VALIDATOR_SCHEMA_VALIDATOR_BACKEND": "jsonschema",
            "PYTHONHASHSEED": "0",
            "PYTHONUTF8": "1",
        }
    )
    return environment


def _capture_pipe(stream: BinaryIO, capture: _PipeCapture) -> None:
    try:
        while chunk := stream.read(_READ_CHUNK):
            remaining = capture.limit - len(capture.data)
            if remaining > 0:
                capture.data.extend(chunk[:remaining])
            if len(chunk) > remaining:
                capture.exceeded.set()
            with capture.budget.lock:
                capture.budget.observed += len(chunk)
                if capture.budget.observed > capture.budget.limit:
                    capture.budget.exceeded.set()
    finally:
        stream.close()


def _write_request(stream: BinaryIO, request: bytes) -> None:
    try:
        stream.write(request)
        stream.flush()
    except BrokenPipeError, OSError:
        pass
    finally:
        stream.close()


def _terminate_process_tree(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    if os.name == "nt":
        system_root = os.environ.get("SystemRoot")
        if not system_root:
            process.kill()
            return
        taskkill = os.path.join(system_root, "System32", "taskkill.exe")
        try:
            subprocess.run(
                [taskkill, "/PID", str(process.pid), "/T", "/F"],
                check=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5,
            )
        except OSError, subprocess.SubprocessError:
            process.kill()
    else:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except OSError, ProcessLookupError:
            process.kill()


def _invoke_worker(
    request: bytes,
    limits: WorkerLimits,
    command: Sequence[str],
) -> tuple[int, bytes, bytes]:
    creationflags = (
        getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) if os.name == "nt" else 0
    )
    try:
        process = subprocess.Popen(
            list(command),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=_child_environment(),
            creationflags=creationflags,
            start_new_session=os.name != "nt",
        )
    except OSError as error:
        raise WorkerFailure(
            "worker.dependency",
            "dependency",
            "The validator worker process could not be started.",
        ) from error
    assert process.stdin is not None
    assert process.stdout is not None
    assert process.stderr is not None

    output_budget = _OutputBudget(
        limits.max_output_bytes, 0, threading.Lock(), threading.Event()
    )
    stdout = _PipeCapture(
        limits.max_stdout_bytes, bytearray(), threading.Event(), output_budget
    )
    stderr = _PipeCapture(
        limits.max_stderr_bytes, bytearray(), threading.Event(), output_budget
    )
    threads = [
        threading.Thread(
            target=_capture_pipe, args=(process.stdout, stdout), daemon=True
        ),
        threading.Thread(
            target=_capture_pipe, args=(process.stderr, stderr), daemon=True
        ),
        threading.Thread(
            target=_write_request, args=(process.stdin, request), daemon=True
        ),
    ]
    for thread in threads:
        thread.start()

    deadline = time.monotonic() + float(limits.timeout_seconds)
    failure: WorkerFailure | None = None
    while process.poll() is None:
        if (
            stdout.exceeded.is_set()
            or stderr.exceeded.is_set()
            or output_budget.exceeded.is_set()
        ):
            failure = WorkerFailure(
                "worker.output-limit",
                "limit",
                "The validator worker exceeded its captured output limit.",
            )
            _terminate_process_tree(process)
            break
        if time.monotonic() >= deadline:
            failure = WorkerFailure(
                "worker.timeout",
                "timeout",
                "The validator worker exceeded its wall-time limit.",
            )
            _terminate_process_tree(process)
            break
        time.sleep(0.005)

    try:
        return_code = process.wait(timeout=5)
    except subprocess.TimeoutExpired as error:
        process.kill()
        process.wait(timeout=5)
        if failure is None:
            failure = WorkerFailure(
                "worker.termination",
                "process",
                "The validator worker could not be terminated cleanly.",
            )
        termination_error = error
    else:
        termination_error = None
    for thread in threads:
        thread.join(timeout=5)
    if failure is None and (
        stdout.exceeded.is_set()
        or stderr.exceeded.is_set()
        or output_budget.exceeded.is_set()
    ):
        failure = WorkerFailure(
            "worker.output-limit",
            "limit",
            "The validator worker exceeded its captured output limit.",
        )
    if failure is not None:
        if termination_error is not None:
            raise failure from termination_error
        raise failure
    return return_code, bytes(stdout.data), bytes(stderr.data)


def _require_string(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 8_192:
        raise WorkerFailure(
            "worker.protocol",
            "protocol",
            f"The validator response has an invalid {name} field.",
        )
    return value


def _require_nullable_int(value: Any, name: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise WorkerFailure(
            "worker.protocol",
            "protocol",
            f"The validator response has an invalid {name} field.",
        )
    return value


def _parse_diagnostic(value: Any) -> ValidatorDiagnostic:
    expected = {
        "source",
        "line",
        "column",
        "pointer",
        "code",
        "severity",
        "kind",
        "message",
    }
    if not isinstance(value, dict) or set(value) != expected:
        raise WorkerFailure(
            "worker.protocol",
            "protocol",
            "The validator emitted a malformed diagnostic.",
        )
    source = value["source"]
    if source is not None:
        source = _require_string(source, "diagnostic source")
        path = PurePosixPath(source)
        if path.is_absolute() or path.as_posix() != source or ".." in path.parts:
            raise WorkerFailure(
                "worker.protocol",
                "protocol",
                "The validator emitted a non-portable diagnostic source.",
            )
    pointer = value["pointer"]
    if pointer is not None and (
        not isinstance(pointer, str)
        or len(pointer) > 8_192
        or (pointer and not pointer.startswith("/"))
    ):
        raise WorkerFailure(
            "worker.protocol",
            "protocol",
            "The validator emitted an invalid diagnostic pointer.",
        )
    line = _require_nullable_int(value["line"], "diagnostic line")
    column = _require_nullable_int(value["column"], "diagnostic column")
    if (line is None) != (column is None):
        raise WorkerFailure(
            "worker.protocol",
            "protocol",
            "The validator emitted an incomplete diagnostic coordinate.",
        )
    message = _require_string(value["message"], "diagnostic message")
    if any(ord(character) < 32 or ord(character) == 127 for character in message):
        raise WorkerFailure(
            "worker.protocol",
            "protocol",
            "The validator emitted control characters in a diagnostic message.",
        )
    return ValidatorDiagnostic(
        source=source,
        line=line,
        column=column,
        pointer=pointer,
        code=_require_string(value["code"], "diagnostic code"),
        severity=_require_string(value["severity"], "diagnostic severity"),
        kind=_require_string(value["kind"], "diagnostic kind"),
        message=message,
    )


def _parse_response(
    raw: bytes,
    *,
    entrypoint: str,
    manifest_digest: str,
    limits: WorkerLimits,
) -> ValidatorResult:
    if not raw.endswith(b"\n") or raw.count(b"\n") != 1:
        raise WorkerFailure(
            "worker.protocol",
            "protocol",
            "The validator worker must emit exactly one JSON line.",
        )
    try:
        text = raw[:-1].decode("utf-8", errors="strict")
        value = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as error:
        raise WorkerFailure(
            "worker.protocol",
            "protocol",
            "The validator worker emitted malformed JSON.",
        ) from error
    expected = {
        "protocolVersion",
        "worker",
        "entrypoint",
        "manifestDigest",
        "outcome",
        "diagnostics",
        "stats",
    }
    if not isinstance(value, dict) or set(value) != expected:
        raise WorkerFailure(
            "worker.protocol",
            "protocol",
            "The validator worker response does not match protocol version 1.",
        )
    if value["protocolVersion"] != PROTOCOL_VERSION or value["worker"] != {
        "name": WORKER_NAME,
        "version": WORKER_VERSION,
    }:
        raise WorkerFailure(
            "worker.protocol",
            "protocol",
            "The validator worker identity or protocol version is unsupported.",
        )
    if value["entrypoint"] != entrypoint or value["manifestDigest"] != manifest_digest:
        raise WorkerFailure(
            "worker.protocol",
            "protocol",
            "The validator response does not identify the requested input.",
        )
    outcome = value["outcome"]
    if outcome not in {"valid", "invalid", "limit-exceeded"}:
        raise WorkerFailure(
            "worker.protocol",
            "protocol",
            "The validator emitted an unsupported outcome.",
        )
    diagnostics_value = value["diagnostics"]
    if (
        not isinstance(diagnostics_value, list)
        or len(diagnostics_value) > limits.max_diagnostics
    ):
        raise WorkerFailure(
            "worker.protocol",
            "protocol",
            "The validator exceeded the diagnostic contract.",
        )
    diagnostics = tuple(_parse_diagnostic(item) for item in diagnostics_value)
    diagnostic_keys = tuple(
        (
            item.source is None,
            item.source or "",
            item.line is None,
            item.line or 0,
            item.column is None,
            item.column or 0,
            item.pointer is None,
            item.pointer or "",
            item.code,
            item.severity,
            item.kind,
            item.message,
        )
        for item in diagnostics
    )
    if diagnostic_keys != tuple(sorted(set(diagnostic_keys))):
        raise WorkerFailure(
            "worker.protocol",
            "protocol",
            "The validator diagnostics are not sorted and unique.",
        )
    stats = value["stats"]
    if not isinstance(stats, dict) or set(stats) != {
        "diagnosticsObserved",
        "diagnosticsEmitted",
        "diagnosticsTruncated",
    }:
        raise WorkerFailure(
            "worker.protocol", "protocol", "The validator emitted malformed statistics."
        )
    integers: dict[str, int] = {}
    for name, item in stats.items():
        if isinstance(item, bool) or not isinstance(item, int) or item < 0:
            raise WorkerFailure(
                "worker.protocol",
                "protocol",
                "The validator emitted invalid statistics.",
            )
        integers[name] = item
    observed = integers["diagnosticsObserved"]
    emitted = integers["diagnosticsEmitted"]
    truncated = integers["diagnosticsTruncated"]
    if (
        emitted != len(diagnostics)
        or not len(diagnostics) <= observed <= MAX_OBSERVED_DIAGNOSTICS
        or truncated > observed - len(diagnostics) + 1
        or (outcome == "valid" and (observed != 0 or diagnostics or truncated != 0))
        or (outcome == "invalid" and (not diagnostics or truncated != 0))
        or (outcome == "limit-exceeded" and (observed == 0 or truncated == 0))
    ):
        raise WorkerFailure(
            "worker.protocol",
            "protocol",
            "The validator outcome and statistics disagree.",
        )
    return ValidatorResult(
        entrypoint=entrypoint,
        manifest_digest=manifest_digest,
        outcome=outcome,
        diagnostics=diagnostics,
        diagnostics_observed=integers["diagnosticsObserved"],
        diagnostics_truncated=integers["diagnosticsTruncated"],
    )


def validate_openapi(
    closure: InputClosure,
    entrypoint: str | None = None,
    *,
    limits: WorkerLimits | None = None,
) -> ValidatorResult:
    """Validate one entrypoint through the supervised, closure-only worker."""

    effective_limits = limits or WorkerLimits()
    if entrypoint is None:
        if len(closure.manifest.entrypoints) != 1:
            raise ValueError("entrypoint is required for a multi-entrypoint closure")
        entrypoint = closure.manifest.entrypoints[0]
    if entrypoint not in closure.manifest.entrypoints:
        raise ValueError("entrypoint must be declared by the input manifest")

    request = _build_request(closure, entrypoint, effective_limits)
    command = [sys.executable, "-I", "-m", "proof_validator_worker"]
    return_code, stdout, stderr = _invoke_worker(request, effective_limits, command)
    if return_code != 0:
        dependency_failure = (
            b"No module named" in stderr or b"ModuleNotFoundError" in stderr
        )
        raise WorkerFailure(
            "worker.dependency" if dependency_failure else "worker.process",
            "dependency" if dependency_failure else "process",
            (
                "The validator worker dependency is unavailable."
                if dependency_failure
                else "The validator worker exited without a valid result."
            ),
        )
    return _parse_response(
        stdout,
        entrypoint=entrypoint,
        manifest_digest=closure.manifest.digest,
        limits=effective_limits,
    )
