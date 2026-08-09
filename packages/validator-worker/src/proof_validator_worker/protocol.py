"""Strict request and response models for the validator process boundary."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any

PROTOCOL_VERSION = 1
WORKER_NAME = "openapi-spec-validator"
WORKER_VERSION = "0.9.0"
MAX_REQUEST_BYTES = 32 * 1024 * 1024
MAX_RESOURCES = 100
MAX_TOTAL_RESOURCE_BYTES = 20 * 1024 * 1024
MAX_RESOURCE_BYTES = MAX_TOTAL_RESOURCE_BYTES
MAX_DIAGNOSTICS = 100
DEFAULT_MAX_DIAGNOSTICS = 100
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


class ProtocolError(ValueError):
    """The worker request is malformed or violates a protocol boundary."""


@dataclass(frozen=True, slots=True)
class Resource:
    path: str
    content: bytes
    digest: str


@dataclass(frozen=True, slots=True)
class ValidationRequest:
    entrypoint: str
    manifest_digest: str
    resources: tuple[Resource, ...]
    max_diagnostics: int


@dataclass(frozen=True, slots=True)
class Diagnostic:
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
class ValidationResponse:
    entrypoint: str
    manifest_digest: str
    outcome: str
    diagnostics: tuple[Diagnostic, ...]
    diagnostics_observed: int
    diagnostics_truncated: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "protocolVersion": PROTOCOL_VERSION,
            "worker": {"name": WORKER_NAME, "version": WORKER_VERSION},
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


class _DuplicateKeyError(ValueError):
    pass


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise _DuplicateKeyError(key)
        value[key] = item
    return value


def _reject_constant(token: str) -> None:
    raise ValueError(token)


def _require_exact_keys(
    value: dict[str, Any], *, required: set[str], optional: set[str] | None = None
) -> None:
    optional = optional or set()
    if set(value) != required | (set(value) & optional):
        missing = sorted(required - set(value))
        unknown = sorted(set(value) - required - optional)
        if missing:
            raise ProtocolError(f"missing request field: {missing[0]}")
        raise ProtocolError(f"unknown request field: {unknown[0]}")


def _require_int(value: Any, name: str, *, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ProtocolError(f"{name} must be an integer")
    if value < minimum or value > maximum:
        raise ProtocolError(f"{name} is outside the supported range")
    return value


def _require_digest(value: Any, name: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise ProtocolError(f"{name} must be a prefixed lowercase SHA-256 digest")
    return value


def _require_path(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise ProtocolError(f"{name} must be a portable repository-relative path")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or value != path.as_posix()
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise ProtocolError(f"{name} must be a portable repository-relative path")
    if path.suffix.lower() not in {".json", ".yaml", ".yml"}:
        raise ProtocolError(f"{name} uses an unsupported document format")
    return value


def parse_request(raw: bytes) -> ValidationRequest:
    """Parse and fully validate one bounded worker request."""

    if not raw or len(raw) > MAX_REQUEST_BYTES:
        raise ProtocolError("request bytes are outside the supported range")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise ProtocolError("request must be valid UTF-8") from error
    try:
        value = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (_DuplicateKeyError, ValueError, json.JSONDecodeError) as error:
        raise ProtocolError("request must be strict JSON with unique keys") from error
    if not isinstance(value, dict):
        raise ProtocolError("request must be a JSON object")
    _require_exact_keys(
        value,
        required={
            "protocolVersion",
            "operation",
            "entrypoint",
            "manifest",
            "resources",
            "limits",
        },
    )
    if value["protocolVersion"] != PROTOCOL_VERSION:
        raise ProtocolError("unsupported protocol version")
    if value["operation"] != "validate":
        raise ProtocolError("unsupported worker operation")

    entrypoint = _require_path(value["entrypoint"], "entrypoint")
    manifest = value["manifest"]
    if not isinstance(manifest, dict):
        raise ProtocolError("manifest must be an object")
    _require_exact_keys(
        manifest,
        required={"schemaVersion", "entrypoints", "files", "totalBytes", "digest"},
    )
    if manifest["schemaVersion"] != "1.0.0":
        raise ProtocolError("unsupported input manifest version")
    manifest_digest = _require_digest(manifest["digest"], "manifest.digest")
    content_manifest = {key: manifest[key] for key in manifest if key != "digest"}
    canonical = json.dumps(
        content_manifest,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    if f"sha256:{hashlib.sha256(canonical).hexdigest()}" != manifest_digest:
        raise ProtocolError("manifest digest does not match its content")

    entrypoints = manifest["entrypoints"]
    if not isinstance(entrypoints, list) or not entrypoints:
        raise ProtocolError("manifest.entrypoints must be a non-empty list")
    normalized_entrypoints = tuple(
        _require_path(item, "manifest.entrypoints item") for item in entrypoints
    )
    if list(normalized_entrypoints) != sorted(set(normalized_entrypoints)):
        raise ProtocolError("manifest.entrypoints must be sorted and unique")
    if entrypoint not in normalized_entrypoints:
        raise ProtocolError("entrypoint is not declared by the manifest")

    files = manifest["files"]
    resources = value["resources"]
    if not isinstance(files, list) or not isinstance(resources, list):
        raise ProtocolError("manifest files and resources must be lists")
    if len(files) != len(resources) or not 1 <= len(resources) <= MAX_RESOURCES:
        raise ProtocolError("resources must exactly match the bounded manifest files")

    parsed: list[Resource] = []
    total_bytes = 0
    for index, (file_item, resource_item) in enumerate(
        zip(files, resources, strict=True)
    ):
        if not isinstance(file_item, dict) or not isinstance(resource_item, dict):
            raise ProtocolError("manifest files and resources must contain objects")
        _require_exact_keys(file_item, required={"path", "size", "digest"})
        _require_exact_keys(resource_item, required={"path", "content", "digest"})
        path = _require_path(file_item["path"], f"manifest.files[{index}].path")
        if resource_item["path"] != path:
            raise ProtocolError("resource order or path does not match the manifest")
        digest = _require_digest(file_item["digest"], "manifest file digest")
        if resource_item["digest"] != digest:
            raise ProtocolError("resource digest does not match the manifest")
        encoded = resource_item["content"]
        if not isinstance(encoded, str):
            raise ProtocolError("resource content must be base64 text")
        try:
            content = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError) as error:
            raise ProtocolError("resource content must be canonical base64") from error
        if base64.b64encode(content).decode("ascii") != encoded:
            raise ProtocolError("resource content must be canonical base64")
        size = _require_int(
            file_item["size"],
            "manifest file size",
            minimum=0,
            maximum=MAX_RESOURCE_BYTES,
        )
        content_digest = f"sha256:{hashlib.sha256(content).hexdigest()}"
        if len(content) != size or content_digest != digest:
            raise ProtocolError("resource bytes do not match the manifest identity")
        total_bytes += len(content)
        if total_bytes > MAX_TOTAL_RESOURCE_BYTES:
            raise ProtocolError("aggregate resource bytes exceed the protocol limit")
        parsed.append(Resource(path=path, content=content, digest=digest))

    if manifest["totalBytes"] != total_bytes:
        raise ProtocolError("manifest totalBytes does not match the resources")
    resource_paths = tuple(item.path for item in parsed)
    if resource_paths != tuple(sorted(set(resource_paths))):
        raise ProtocolError("resources must be sorted and unique by path")
    if entrypoint not in resource_paths:
        raise ProtocolError("entrypoint is absent from the supplied resources")

    limits = value["limits"]
    if not isinstance(limits, dict):
        raise ProtocolError("limits must be an object")
    _require_exact_keys(limits, required={"maxDiagnostics"})
    max_diagnostics = _require_int(
        limits["maxDiagnostics"],
        "limits.maxDiagnostics",
        minimum=0,
        maximum=MAX_DIAGNOSTICS,
    )
    return ValidationRequest(
        entrypoint=entrypoint,
        manifest_digest=manifest_digest,
        resources=tuple(parsed),
        max_diagnostics=max_diagnostics,
    )


def compact_json(value: Any) -> bytes:
    """Serialize a protocol value deterministically."""

    return (
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )
