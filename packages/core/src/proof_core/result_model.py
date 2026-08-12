"""Immutable Python producers for normalized result-schema v1 values."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from types import MappingProxyType
from typing import Any, Literal
from urllib.parse import urlsplit

from proof_core.canonical_json import (
    CanonicalJsonError,
    canonical_json_bytes,
    content_digest,
)

RESULT_SCHEMA_VERSION = "1.0.0"

type JsonValue = (
    None | bool | int | float | str | tuple[JsonValue, ...] | Mapping[str, JsonValue]
)
type FailOn = Literal["error", "high", "medium", "low", "none"]
type GateOutcome = Literal["pass", "advisory", "blocked", "not-evaluated"]
type RunStatus = Literal["completed", "input-error", "internal-error"]

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_CODE = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
_RULE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_EXTENSION = re.compile(r"^x-[a-z0-9][a-z0-9._-]*$")
_EVALUATION_TIME = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_JSON_POINTER = re.compile(r"^(?:|(?:/(?:[^~/]|~[01])*)+)$")
_WINDOWS_DRIVE = re.compile(r"^[A-Za-z]:")

_FAIL_ON_VALUES = frozenset({"error", "high", "medium", "low", "none"})
_GATE_OUTCOMES = frozenset({"pass", "advisory", "blocked", "not-evaluated"})
_RUN_STATUSES = frozenset({"completed", "input-error", "internal-error"})
_SEVERITIES = ("error", "high", "medium", "low", "info")
_SEVERITY_RANK = {severity: rank for rank, severity in enumerate(_SEVERITIES)}
_FINDING_SOURCES = frozenset(
    {"openapi-validator", "agent-rule", "configuration", "core"}
)
_RISK_CATEGORIES = frozenset(
    {
        "destructive",
        "financial_action",
        "external_side_effect",
        "permission_change",
        "sensitive_data",
    }
)
_EVIDENCE_KINDS = frozenset(
    {"method", "path", "keyword", "extension", "schema", "value", "text"}
)
_HTTP_METHODS = frozenset(
    {"get", "put", "post", "delete", "options", "head", "patch", "trace"}
)
_TERMINAL_KINDS = frozenset(
    {
        "input",
        "configuration",
        "timeout",
        "dependency",
        "protocol",
        "sandbox",
        "internal",
    }
)
_INPUT_ERROR_KINDS = frozenset({"input", "configuration"})
_INTERNAL_ERROR_KINDS = _TERMINAL_KINDS - _INPUT_ERROR_KINDS
_FINDING_FIELDS = frozenset(
    {
        "ruleId",
        "source",
        "severity",
        "message",
        "fingerprint",
        "location",
        "operation",
        "riskCategories",
        "evidence",
        "remediation",
    }
)
_REQUIRED_FINDING_FIELDS = frozenset(
    {
        "ruleId",
        "source",
        "severity",
        "message",
        "fingerprint",
        "location",
        "evidence",
        "remediation",
    }
)


def _require_non_empty_string(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    return value


def _require_digest(value: Any, name: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise ValueError(f"{name} must be a lowercase SHA-256 digest")
    return value


def _require_nonnegative(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{name} must be a non-negative integer")
    return value


def _is_extension(name: Any) -> bool:
    return isinstance(name, str) and _EXTENSION.fullmatch(name) is not None


def _freeze_json(value: Any, *, name: str) -> JsonValue:
    if value is None or isinstance(value, (bool, int, float, str)):
        frozen: JsonValue = value
    elif isinstance(value, Mapping):
        frozen_items: dict[str, JsonValue] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError(f"{name} object keys must be strings")
            frozen_items[key] = _freeze_json(item, name=name)
        frozen = MappingProxyType(dict(sorted(frozen_items.items())))
    elif isinstance(value, (list, tuple)):
        frozen = tuple(_freeze_json(item, name=name) for item in value)
    else:
        raise ValueError(f"{name} must contain only JSON-compatible values")
    try:
        canonical_json_bytes(_thaw_json(frozen))
    except CanonicalJsonError as error:
        raise ValueError(f"{name} must be RFC 8785 canonicalizable") from error
    return frozen


def _thaw_json(value: JsonValue) -> Any:
    if isinstance(value, Mapping):
        return {key: _thaw_json(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw_json(item) for item in value]
    return value


def _freeze_extensions(
    value: Mapping[str, Any], *, name: str
) -> Mapping[str, JsonValue]:
    if not isinstance(value, Mapping) or any(not _is_extension(key) for key in value):
        raise ValueError(f"{name} must contain only namespaced x- fields")
    return MappingProxyType(
        {
            key: _freeze_json(item, name=f"{name}.{key}")
            for key, item in sorted(value.items())
        }
    )


def _validate_location(value: Any, *, name: str) -> Mapping[str, JsonValue]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{name} must be an object")
    allowed = {"path", "pointer", "line", "column"}
    unknown = set(value) - allowed - {key for key in value if _is_extension(key)}
    if unknown or "path" not in value or "pointer" not in value:
        raise ValueError(f"{name} does not match the result location contract")
    path = value["path"]
    if (
        not isinstance(path, str)
        or not path
        or path.startswith("/")
        or _WINDOWS_DRIVE.match(path)
        or "\\" in path
        or any(part == ".." for part in path.split("/"))
    ):
        raise ValueError(f"{name}.path must be a repository-relative POSIX path")
    pointer = value["pointer"]
    if not isinstance(pointer, str) or _JSON_POINTER.fullmatch(pointer) is None:
        raise ValueError(f"{name}.pointer must be an RFC 6901 JSON Pointer")
    for coordinate in ("line", "column"):
        if coordinate in value and (
            isinstance(value[coordinate], bool)
            or not isinstance(value[coordinate], int)
            or value[coordinate] < 1
        ):
            raise ValueError(f"{name}.{coordinate} must be a positive integer")
    return _freeze_json(value, name=name)  # type: ignore[return-value]


@dataclass(frozen=True, slots=True)
class ArtifactIdentity:
    name: str
    version: str
    digest: str

    def __post_init__(self) -> None:
        _require_non_empty_string(self.name, "artifact name")
        _require_non_empty_string(self.version, "artifact version")
        _require_digest(self.digest, "artifact digest")

    def to_dict(self) -> dict[str, str]:
        return {"name": self.name, "version": self.version, "digest": self.digest}


@dataclass(frozen=True, slots=True)
class ContentIdentity:
    digest: str

    def __post_init__(self) -> None:
        _require_digest(self.digest, "content digest")

    def to_dict(self) -> dict[str, str]:
        return {"digest": self.digest}


@dataclass(frozen=True, slots=True)
class AnalysisArtifacts:
    core: ArtifactIdentity
    validator: ArtifactIdentity
    runtime: ArtifactIdentity

    def __post_init__(self) -> None:
        for name in ("core", "validator", "runtime"):
            if not isinstance(getattr(self, name), ArtifactIdentity):
                raise TypeError(f"{name} must be an ArtifactIdentity")

    def to_dict(self) -> dict[str, dict[str, str]]:
        return {
            "core": self.core.to_dict(),
            "validator": self.validator.to_dict(),
            "runtime": self.runtime.to_dict(),
        }


@dataclass(frozen=True, slots=True)
class RunProvenance:
    core: ArtifactIdentity
    validator: ArtifactIdentity
    rule_pack: ArtifactIdentity
    runtime: ArtifactIdentity
    configuration: ContentIdentity
    input: ContentIdentity
    extensions: Mapping[str, Any] = field(default_factory=dict, repr=False)

    def __post_init__(self) -> None:
        for name in ("core", "validator", "rule_pack", "runtime"):
            if not isinstance(getattr(self, name), ArtifactIdentity):
                raise TypeError(f"{name} must be an ArtifactIdentity")
        for name in ("configuration", "input"):
            if not isinstance(getattr(self, name), ContentIdentity):
                raise TypeError(f"{name} must be a ContentIdentity")
        object.__setattr__(
            self,
            "extensions",
            _freeze_extensions(self.extensions, name="provenance extensions"),
        )

    def to_dict(self) -> dict[str, Any]:
        value: dict[str, Any] = {
            "core": self.core.to_dict(),
            "validator": self.validator.to_dict(),
            "rulePack": self.rule_pack.to_dict(),
            "runtime": self.runtime.to_dict(),
            "configuration": self.configuration.to_dict(),
            "input": self.input.to_dict(),
        }
        value.update({key: _thaw_json(item) for key, item in self.extensions.items()})
        return value


@dataclass(frozen=True, slots=True)
class GateResult:
    outcome: GateOutcome
    fail_on: FailOn
    causing_finding_fingerprints: tuple[str, ...] = ()
    extensions: Mapping[str, Any] = field(default_factory=dict, repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.outcome, str) or self.outcome not in _GATE_OUTCOMES:
            raise ValueError("gate outcome is not supported")
        if not isinstance(self.fail_on, str) or self.fail_on not in _FAIL_ON_VALUES:
            raise ValueError("gate failOn is not supported")
        causes = tuple(self.causing_finding_fingerprints)
        for cause in causes:
            _require_digest(cause, "gate cause")
        if causes != tuple(sorted(set(causes))):
            raise ValueError("gate causes must be sorted and unique")
        if self.outcome in {"advisory", "blocked"} and not causes:
            raise ValueError("advisory and blocked gates require a cause")
        if self.outcome in {"pass", "not-evaluated"} and causes:
            raise ValueError("pass and not-evaluated gates cannot have causes")
        if self.outcome == "blocked" and self.fail_on == "none":
            raise ValueError("blocked gates cannot use failOn none")
        object.__setattr__(self, "causing_finding_fingerprints", causes)
        object.__setattr__(
            self,
            "extensions",
            _freeze_extensions(self.extensions, name="gate extensions"),
        )

    def to_dict(self) -> dict[str, Any]:
        value: dict[str, Any] = {
            "outcome": self.outcome,
            "failOn": self.fail_on,
            "causingFindingFingerprints": list(self.causing_finding_fingerprints),
        }
        value.update({key: _thaw_json(item) for key, item in self.extensions.items()})
        return value


@dataclass(frozen=True, slots=True)
class RunSummary:
    finding_total: int
    error_total: int
    findings_by_severity: Mapping[str, int]
    scanned_files: int
    scanned_operations: int
    excluded_operations: int
    risky_operations: int
    truncated_findings: int
    extensions: Mapping[str, Any] = field(default_factory=dict, repr=False)

    def __post_init__(self) -> None:
        for name in (
            "finding_total",
            "error_total",
            "scanned_files",
            "scanned_operations",
            "excluded_operations",
            "risky_operations",
            "truncated_findings",
        ):
            _require_nonnegative(getattr(self, name), name)
        if not isinstance(self.findings_by_severity, Mapping) or set(
            self.findings_by_severity
        ) != set(_SEVERITIES):
            raise ValueError("findingsBySeverity must define every result severity")
        severity_counts = {
            severity: _require_nonnegative(
                self.findings_by_severity[severity], f"findingsBySeverity.{severity}"
            )
            for severity in _SEVERITIES
        }
        if sum(severity_counts.values()) != self.finding_total:
            raise ValueError("severity counts must equal findingTotal")
        if self.risky_operations > self.scanned_operations:
            raise ValueError("riskyOperations cannot exceed scannedOperations")
        object.__setattr__(
            self, "findings_by_severity", MappingProxyType(severity_counts)
        )
        object.__setattr__(
            self,
            "extensions",
            _freeze_extensions(self.extensions, name="summary extensions"),
        )

    def to_dict(self) -> dict[str, Any]:
        value: dict[str, Any] = {
            "findingTotal": self.finding_total,
            "errorTotal": self.error_total,
            "findingsBySeverity": dict(self.findings_by_severity),
            "scannedFiles": self.scanned_files,
            "scannedOperations": self.scanned_operations,
            "excludedOperations": self.excluded_operations,
            "riskyOperations": self.risky_operations,
            "truncatedFindings": self.truncated_findings,
        }
        value.update({key: _thaw_json(item) for key, item in self.extensions.items()})
        return value


@dataclass(frozen=True, slots=True)
class TerminalError:
    code: str
    kind: str
    message: str
    retryable: bool
    location: Mapping[str, Any] | None = field(default=None, repr=False)
    extensions: Mapping[str, Any] = field(default_factory=dict, repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.code, str) or _CODE.fullmatch(self.code) is None:
            raise ValueError("terminal error code is invalid")
        if not isinstance(self.kind, str) or self.kind not in _TERMINAL_KINDS:
            raise ValueError("terminal error kind is not supported")
        _require_non_empty_string(self.message, "terminal error message")
        if not isinstance(self.retryable, bool):
            raise ValueError("terminal error retryable must be boolean")
        if self.location is not None:
            object.__setattr__(
                self,
                "location",
                _validate_location(self.location, name="terminal error location"),
            )
        object.__setattr__(
            self,
            "extensions",
            _freeze_extensions(self.extensions, name="terminal error extensions"),
        )

    def to_dict(self) -> dict[str, Any]:
        value: dict[str, Any] = {
            "code": self.code,
            "kind": self.kind,
            "message": self.message,
            "retryable": self.retryable,
        }
        if self.location is not None:
            value["location"] = _thaw_json(self.location)
        value.update({key: _thaw_json(item) for key, item in self.extensions.items()})
        return value


def _validate_finding(value: Any) -> Mapping[str, JsonValue]:
    if not isinstance(value, Mapping):
        raise ValueError("each finding must be an object")
    unknown = (
        set(value) - _FINDING_FIELDS - {key for key in value if _is_extension(key)}
    )
    if unknown or not _REQUIRED_FINDING_FIELDS.issubset(value):
        raise ValueError("finding does not match the normalized finding shape")
    rule_id = value["ruleId"]
    if not isinstance(rule_id, str) or _RULE_ID.fullmatch(rule_id) is None:
        raise ValueError("finding ruleId is invalid")
    if not isinstance(value["source"], str) or value["source"] not in _FINDING_SOURCES:
        raise ValueError("finding source is not supported")
    if (
        not isinstance(value["severity"], str)
        or value["severity"] not in _SEVERITY_RANK
    ):
        raise ValueError("finding severity is not supported")
    _require_non_empty_string(value["message"], "finding message")
    _require_digest(value["fingerprint"], "finding fingerprint")
    _validate_location(value["location"], name="finding location")
    operation = value.get("operation")
    if operation is not None:
        if not isinstance(operation, Mapping):
            raise ValueError("finding operation must be an object")
        operation_unknown = (
            set(operation)
            - {"method", "path", "operationId"}
            - {key for key in operation if _is_extension(key)}
        )
        if operation_unknown or not {"method", "path"}.issubset(operation):
            raise ValueError("finding operation does not match the result contract")
        if (
            not isinstance(operation["method"], str)
            or operation["method"] not in _HTTP_METHODS
        ):
            raise ValueError("finding operation method is not supported")
        operation_path = operation["path"]
        if not isinstance(operation_path, str) or not operation_path.startswith("/"):
            raise ValueError("finding operation path must start with /")
        if "operationId" in operation:
            _require_non_empty_string(
                operation["operationId"], "finding operation operationId"
            )
    evidence = value["evidence"]
    if not isinstance(evidence, (list, tuple)) or not evidence:
        raise ValueError("finding evidence must be a non-empty array")
    if not all(isinstance(item, Mapping) for item in evidence):
        raise ValueError("finding evidence items must be objects")
    evidence_projections: list[dict[str, str]] = []
    for index, item in enumerate(evidence):
        evidence_unknown = (
            set(item)
            - {
                "kind",
                "description",
                "pointer",
                "value",
            }
            - {key for key in item if _is_extension(key)}
        )
        if evidence_unknown or not {"kind", "description"}.issubset(item):
            raise ValueError("finding evidence does not match the result contract")
        if not isinstance(item["kind"], str) or item["kind"] not in _EVIDENCE_KINDS:
            raise ValueError("finding evidence kind is not supported")
        _require_non_empty_string(
            item["description"], f"finding evidence[{index}] description"
        )
        if "pointer" in item and (
            not isinstance(item["pointer"], str)
            or _JSON_POINTER.fullmatch(item["pointer"]) is None
        ):
            raise ValueError("finding evidence pointer must be an RFC 6901 pointer")
        if "value" in item and not isinstance(item["value"], str):
            raise ValueError("finding evidence value must be a string")
        projection = {
            "kind": item["kind"],
            "value": item.get("value", item["description"]),
        }
        if "pointer" in item:
            projection["pointer"] = item["pointer"]
        evidence_projections.append(projection)
    if evidence_projections != sorted(evidence_projections, key=canonical_json_bytes):
        raise ValueError("finding evidence must use canonical projection ordering")
    remediation = value["remediation"]
    if not isinstance(remediation, Mapping):
        raise ValueError("finding remediation must be an object")
    remediation_unknown = (
        set(remediation)
        - {
            "recommendation",
            "documentationUrl",
        }
        - {key for key in remediation if _is_extension(key)}
    )
    if remediation_unknown:
        raise ValueError("finding remediation does not match the result contract")
    _require_non_empty_string(
        remediation.get("recommendation"), "finding remediation recommendation"
    )
    documentation_url = remediation.get("documentationUrl")
    if documentation_url is not None:
        if not isinstance(documentation_url, str):
            raise ValueError("finding remediation documentationUrl must be an URI")
        try:
            parsed_url = urlsplit(documentation_url)
            if (
                not parsed_url.scheme
                or re.fullmatch(r"[A-Za-z][A-Za-z0-9+.-]*", parsed_url.scheme) is None
                or (parsed_url.scheme in {"http", "https"} and not parsed_url.netloc)
            ):
                raise ValueError
            _ = parsed_url.hostname
        except ValueError as error:
            raise ValueError(
                "finding remediation documentationUrl must be an URI"
            ) from error
    risk_categories = value.get("riskCategories")
    if risk_categories is not None:
        if (
            not isinstance(risk_categories, (list, tuple))
            or any(
                not isinstance(category, str) or category not in _RISK_CATEGORIES
                for category in risk_categories
            )
            or tuple(risk_categories) != tuple(sorted(set(risk_categories)))
        ):
            raise ValueError("finding riskCategories must be sorted and unique")
    if value["fingerprint"] != _finding_fingerprint(value):
        raise ValueError("finding fingerprint does not match its identity projection")
    return _freeze_json(value, name="finding")  # type: ignore[return-value]


def _finding_sort_key(finding: Mapping[str, JsonValue]) -> tuple[Any, ...]:
    location = finding["location"]
    assert isinstance(location, Mapping)
    return (
        _SEVERITY_RANK[finding["severity"]],
        finding["source"],
        finding["ruleId"],
        location["path"],
        location["pointer"],
        finding["fingerprint"],
    )


def _finding_fingerprint(value: Mapping[str, Any]) -> str:
    location = value["location"]
    projection: dict[str, Any] = {
        "fingerprintVersion": 1,
        "source": value["source"],
        "ruleId": value["ruleId"],
        "location": {
            "path": location["path"],
            "pointer": location["pointer"],
        },
        "evidence": [],
    }
    operation = value.get("operation")
    if operation is not None:
        projection["operation"] = {
            "method": operation["method"],
            "path": operation["path"],
        }
    risks = value.get("riskCategories")
    if risks:
        projection["riskCategories"] = list(risks)
    evidence_projection = []
    for evidence in value["evidence"]:
        item = {
            "kind": evidence["kind"],
            "value": evidence.get("value", evidence["description"]),
        }
        if "pointer" in evidence:
            item["pointer"] = evidence["pointer"]
        evidence_projection.append(item)
    projection["evidence"] = sorted(evidence_projection, key=canonical_json_bytes)
    return content_digest(projection)


def _error_sort_key(error: TerminalError) -> tuple[Any, ...]:
    location = error.location or {}
    return (
        error.kind,
        error.code,
        location.get("path", ""),
        location.get("pointer", ""),
        error.message,
        canonical_json_bytes(error.to_dict()),
    )


@dataclass(frozen=True, slots=True)
class NormalizedRun:
    evaluation_time: str
    status: RunStatus
    findings: tuple[Mapping[str, Any], ...]
    errors: tuple[TerminalError, ...]
    summary: RunSummary
    gate: GateResult
    provenance: RunProvenance
    extensions: Mapping[str, Any] = field(default_factory=dict, repr=False)
    schema_version: str = RESULT_SCHEMA_VERSION
    result_digest: str = field(init=False)

    def __post_init__(self) -> None:
        if self.schema_version != RESULT_SCHEMA_VERSION:
            raise ValueError("run schemaVersion is not supported")
        if (
            not isinstance(self.evaluation_time, str)
            or _EVALUATION_TIME.fullmatch(self.evaluation_time) is None
        ):
            raise ValueError("evaluationTime must be canonical UTC to whole seconds")
        try:
            datetime.strptime(self.evaluation_time, "%Y-%m-%dT%H:%M:%SZ")
        except ValueError as error:
            raise ValueError("evaluationTime is not a valid UTC date-time") from error
        if not isinstance(self.status, str) or self.status not in _RUN_STATUSES:
            raise ValueError("run status is not supported")
        if not isinstance(self.summary, RunSummary):
            raise TypeError("summary must be a RunSummary")
        if not isinstance(self.gate, GateResult):
            raise TypeError("gate must be a GateResult")
        if not isinstance(self.provenance, RunProvenance):
            raise TypeError("provenance must be a RunProvenance")

        findings = tuple(_validate_finding(item) for item in self.findings)
        if findings != tuple(sorted(findings, key=_finding_sort_key)):
            raise ValueError("findings must use canonical result ordering")
        fingerprints = tuple(item["fingerprint"] for item in findings)
        if len(fingerprints) != len(set(fingerprints)):
            raise ValueError("finding fingerprints must be unique")
        errors = tuple(self.errors)
        if not all(isinstance(error, TerminalError) for error in errors):
            raise TypeError("errors must contain TerminalError values")
        if errors != tuple(sorted(errors, key=_error_sort_key)):
            raise ValueError("terminal errors must use canonical result ordering")
        object.__setattr__(self, "findings", findings)
        object.__setattr__(self, "errors", errors)
        object.__setattr__(
            self,
            "extensions",
            _freeze_extensions(self.extensions, name="run extensions"),
        )

        severity_counts = {severity: 0 for severity in _SEVERITIES}
        for finding in findings:
            severity_counts[finding["severity"]] += 1
        if (
            self.summary.finding_total != len(findings)
            or self.summary.error_total != len(errors)
            or dict(self.summary.findings_by_severity) != severity_counts
        ):
            raise ValueError("run summary does not match findings and errors")

        if self.status == "completed":
            if errors or self.gate.outcome == "not-evaluated":
                raise ValueError("completed runs cannot contain terminal errors")
            self._validate_completed_gate(findings)
        elif self.status == "input-error":
            if (
                findings
                or not errors
                or any(error.kind not in _INPUT_ERROR_KINDS for error in errors)
                or self.gate.outcome != "not-evaluated"
            ):
                raise ValueError("input-error run state is inconsistent")
        elif (
            findings
            or not errors
            or any(error.kind not in _INTERNAL_ERROR_KINDS for error in errors)
            or self.gate.outcome != "not-evaluated"
        ):
            raise ValueError("internal-error run state is inconsistent")

        digest_input = self._to_dict(include_result_digest=False)
        object.__setattr__(self, "result_digest", content_digest(digest_input))

    def _validate_completed_gate(
        self, findings: tuple[Mapping[str, JsonValue], ...]
    ) -> None:
        if not findings:
            expected_outcome: GateOutcome = "pass"
            expected_causes: tuple[str, ...] = ()
        elif self.gate.fail_on == "none":
            expected_outcome = "advisory"
            expected_causes = tuple(sorted(item["fingerprint"] for item in findings))
        else:
            threshold = _SEVERITY_RANK[self.gate.fail_on]
            blocking_causes = tuple(
                sorted(
                    item["fingerprint"]
                    for item in findings
                    if _SEVERITY_RANK[item["severity"]] <= threshold
                )
            )
            if blocking_causes:
                expected_outcome = "blocked"
                expected_causes = blocking_causes
            else:
                expected_outcome = "advisory"
                expected_causes = tuple(
                    sorted(item["fingerprint"] for item in findings)
                )
        if (
            self.gate.outcome != expected_outcome
            or self.gate.causing_finding_fingerprints != expected_causes
        ):
            raise ValueError("completed run gate does not match its findings")

    def _to_dict(self, *, include_result_digest: bool) -> dict[str, Any]:
        value: dict[str, Any] = {
            "schemaVersion": self.schema_version,
            "evaluationTime": self.evaluation_time,
            "status": self.status,
            "findings": [_thaw_json(item) for item in self.findings],
            "errors": [error.to_dict() for error in self.errors],
            "summary": self.summary.to_dict(),
            "gate": self.gate.to_dict(),
            "provenance": self.provenance.to_dict(),
        }
        if include_result_digest:
            value["resultDigest"] = self.result_digest
        value.update({key: _thaw_json(item) for key, item in self.extensions.items()})
        return value

    def to_dict(self) -> dict[str, Any]:
        """Return a detached JSON-compatible normalized run."""

        return self._to_dict(include_result_digest=True)

    def canonical_bytes(self) -> bytes:
        """Return RFC 8785 bytes of the complete run, including its digest."""

        return canonical_json_bytes(self.to_dict())
