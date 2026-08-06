from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from proof_core import (
    WorkerFailure,
    WorkerLimits,
    build_input_closure,
    validate_openapi,
)
from proof_core.validator_client import _invoke_worker, _parse_response


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8", newline="\n")


def _valid_document() -> str:
    return """openapi: 3.1.0
info:
  title: Pets
  version: 1.0.0
paths: {}
"""


def test_supervisor_runs_real_worker_from_immutable_closure(tmp_path: Path) -> None:
    source = tmp_path / "root.yaml"
    _write(source, _valid_document())
    closure = build_input_closure(tmp_path, "root.yaml")
    source.unlink()

    result = validate_openapi(closure)

    assert result.outcome == "valid"
    assert result.manifest_digest == closure.manifest.digest
    assert result.to_dict()["stats"]["diagnosticsEmitted"] == 0


def test_supervisor_returns_invalid_document_not_worker_failure(tmp_path: Path) -> None:
    _write(
        tmp_path / "root.yaml",
        """openapi: 3.1.0
info:
  title: Pets
paths: {}
""",
    )
    closure = build_input_closure(tmp_path, "root.yaml")

    result = validate_openapi(closure)

    assert result.outcome == "invalid"
    assert result.diagnostics
    assert result.diagnostics[0].code == "oas.schema"


def test_supervisor_requires_entrypoint_for_multi_entrypoint_closure(
    tmp_path: Path,
) -> None:
    _write(tmp_path / "a.yaml", _valid_document())
    _write(tmp_path / "b.yaml", _valid_document())
    closure = build_input_closure(tmp_path, ["a.yaml", "b.yaml"])

    with pytest.raises(ValueError, match="entrypoint is required"):
        validate_openapi(closure)

    assert validate_openapi(closure, "b.yaml").entrypoint == "b.yaml"


def test_invocation_enforces_wall_time() -> None:
    limits = WorkerLimits(timeout_seconds=0.05)
    command = [sys.executable, "-I", "-c", "import time; time.sleep(5)"]

    with pytest.raises(WorkerFailure) as failure:
        _invoke_worker(b"{}", limits, command)

    assert failure.value.code == "worker.timeout"
    assert failure.value.kind == "timeout"


def test_invocation_enforces_stdout_limit() -> None:
    limits = WorkerLimits(max_stdout_bytes=128)
    command = [
        sys.executable,
        "-I",
        "-c",
        "import sys; sys.stdout.buffer.write(b'x' * 4096)",
    ]

    with pytest.raises(WorkerFailure) as failure:
        _invoke_worker(b"{}", limits, command)

    assert failure.value.code == "worker.output-limit"


def test_invocation_enforces_combined_output_limit() -> None:
    limits = WorkerLimits(
        max_stdout_bytes=128,
        max_stderr_bytes=128,
        max_output_bytes=192,
    )
    command = [
        sys.executable,
        "-I",
        "-c",
        (
            "import sys; "
            "sys.stdout.buffer.write(b'x' * 128); sys.stdout.buffer.flush(); "
            "sys.stderr.buffer.write(b'y' * 128); sys.stderr.buffer.flush()"
        ),
    ]

    with pytest.raises(WorkerFailure) as failure:
        _invoke_worker(b"{}", limits, command)

    assert failure.value.code == "worker.output-limit"


def test_invocation_preserves_nonzero_exit_for_supervisor_mapping() -> None:
    command = [sys.executable, "-I", "-c", "raise SystemExit(7)"]

    return_code, stdout, stderr = _invoke_worker(b"{}", WorkerLimits(), command)

    assert return_code == 7
    assert stdout == b""
    assert stderr == b""


@pytest.mark.parametrize(
    "payload",
    [
        b"not-json\n",
        b"{}\n{}\n",
        b'{"outcome":"valid"}\n',
    ],
)
def test_malformed_worker_output_is_protocol_failure(payload: bytes) -> None:
    with pytest.raises(WorkerFailure) as failure:
        _parse_response(
            payload,
            entrypoint="root.yaml",
            manifest_digest="0" * 64,
            limits=WorkerLimits(),
        )

    assert failure.value.code == "worker.protocol"


def test_internal_error_response_cannot_be_valid_result() -> None:
    payload = {
        "protocolVersion": 1,
        "worker": {"name": "openapi-spec-validator", "version": "0.9.0"},
        "entrypoint": "root.yaml",
        "manifestDigest": "0" * 64,
        "outcome": "internal-error",
        "diagnostics": [],
        "stats": {
            "diagnosticsObserved": 0,
            "diagnosticsEmitted": 0,
            "diagnosticsTruncated": 0,
        },
    }

    with pytest.raises(WorkerFailure, match="unsupported outcome"):
        _parse_response(
            json.dumps(payload, separators=(",", ":")).encode() + b"\n",
            entrypoint="root.yaml",
            manifest_digest="0" * 64,
            limits=WorkerLimits(),
        )


def test_response_accepts_raw_observations_above_deduplicated_emissions() -> None:
    payload = {
        "protocolVersion": 1,
        "worker": {"name": "openapi-spec-validator", "version": "0.9.0"},
        "entrypoint": "root.yaml",
        "manifestDigest": "0" * 64,
        "outcome": "invalid",
        "diagnostics": [
            {
                "source": "root.yaml",
                "line": 1,
                "column": 1,
                "pointer": "/paths",
                "code": "oas.schema",
                "severity": "error",
                "kind": "schema",
                "message": "duplicate",
            }
        ],
        "stats": {
            "diagnosticsObserved": 3,
            "diagnosticsEmitted": 1,
            "diagnosticsTruncated": 0,
        },
    }

    result = _parse_response(
        json.dumps(payload, separators=(",", ":")).encode() + b"\n",
        entrypoint="root.yaml",
        manifest_digest="0" * 64,
        limits=WorkerLimits(),
    )

    assert result.diagnostics_observed == 3
    assert len(result.diagnostics) == 1
    assert result.diagnostics_truncated == 0


@pytest.mark.parametrize(
    "keyword,value",
    [
        ("max_diagnostics", -1),
        ("max_diagnostics", 101),
        ("max_diagnostics", True),
        ("timeout_seconds", 0),
        ("timeout_seconds", 5.01),
        ("max_stdout_bytes", 0),
        ("max_stdout_bytes", 1024 * 1024 + 1),
        ("max_stderr_bytes", False),
        ("max_output_bytes", 1024 * 1024 + 1),
    ],
)
def test_worker_limits_reject_invalid_values(keyword: str, value: object) -> None:
    with pytest.raises(ValueError):
        WorkerLimits(**{keyword: value})
