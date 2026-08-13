"""Canonical result-v1 assembly shared by CLI and hosted execution surfaces."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any, Literal

from proof_rulepack import (
    AGENT_CONTRACT_IDENTITY,
    Finding,
    RuleEvaluation,
    evaluate_agent_contract,
)

from proof_core.canonical_json import canonical_json_bytes, content_digest
from proof_core.configuration import ConfigurationError, EffectiveScanConfiguration
from proof_core.input_closure import InputClosure, InputClosureError, InputManifest
from proof_core.operation_normalization import (
    NormalizationIssue,
    NormalizedOperation,
    OperationSet,
    normalize_operations,
)
from proof_core.result_model import (
    AnalysisArtifacts,
    ArtifactIdentity,
    ContentIdentity,
    GateResult,
    NormalizedRun,
    RunProvenance,
    RunSummary,
    TerminalError,
)
from proof_core.validator_client import (
    VALIDATOR_SEMANTIC_DIGEST,
    WORKER_NAME,
    WORKER_VERSION,
    ValidatorDiagnostic,
    ValidatorResult,
    WorkerFailure,
    WorkerLimits,
    validate_openapi,
)

type FailOn = Literal["error", "high", "medium", "low", "none"]

_SEVERITY_RANK = {"error": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_FAIL_ON_RANK = {"error": 0, "high": 1, "medium": 2, "low": 3}
_WORKER_KIND = {
    "timeout": "timeout",
    "dependency": "dependency",
    "protocol": "protocol",
    "sandbox": "sandbox",
    "limit": "internal",
    "process": "internal",
    "termination": "internal",
}
_RETRYABLE_WORKER_CODES = frozenset(
    {"worker.dependency", "worker.process", "worker.termination", "worker.timeout"}
)
_VALIDATOR_MESSAGES = {
    "oas.schema": "The OpenAPI document violates a schema constraint.",
}
_INPUT_ERROR_MESSAGES = {
    "document-bytes-limit": "Input document exceeds the byte limit.",
    "file-count-limit": "Input closure exceeds the file-count limit.",
    "invalid-document": "Input document is not valid strict JSON or YAML.",
    "invalid-entrypoint": "Input entrypoint is not repository-relative.",
    "invalid-reference": "Input contains an invalid local reference.",
    "invalid-repository-root": "Repository root cannot be inspected safely.",
    "invalid-utf8": "Input document must be strict UTF-8.",
    "missing-entrypoint": "At least one input entrypoint is required.",
    "missing-file": "Input file does not exist.",
    "multiple-yaml-documents": "Input must contain exactly one YAML document.",
    "non-json-value": "Input must contain only JSON-compatible values.",
    "path-case-mismatch": "Input path casing does not match the repository entry.",
    "path-escape": "Input path escapes the repository root.",
    "path-link": "Input path cannot contain repository links.",
    "reference-depth-limit": "Input closure exceeds the reference-depth limit.",
    "repository-root-link": "Repository root cannot be a link.",
    "unreadable-file": "Input file cannot be inspected safely.",
    "unsupported-format": "Input file uses an unsupported document format.",
    "unsupported-reference": "Only repository-local references are supported.",
    "utf8-bom": "Input must use UTF-8 without a byte-order mark.",
}
_CONFIGURATION_MESSAGES = {
    "configuration.invalid-document": "Configuration is not valid strict JSON or YAML.",
    "configuration.invalid-syntax": "Configuration syntax is invalid.",
    "configuration.missing-file": "Configuration file does not exist.",
    "configuration.non-canonical": "Configuration cannot be canonicalized safely.",
    "configuration.rulepack-digest-mismatch": "Rule-pack identity does not match.",
    "configuration.unknown-field": "Configuration contains an unknown standard field.",
    "configuration.unsupported-rulepack": (
        "Configuration selects an unsupported rule pack."
    ),
    "configuration.unsupported-version": "Configuration schema version is unsupported.",
}
_WORKER_MESSAGES = {
    "worker.dependency": "Validator dependency is unavailable.",
    "worker.output-limit": "Validator worker exceeded its output limit.",
    "worker.process": "Validator worker exited unexpectedly.",
    "worker.protocol": "Validator worker response violated the protocol.",
    "worker.request-limit": "Validator request exceeds the protocol byte limit.",
    "worker.termination": "Validator worker could not terminate cleanly.",
    "worker.timeout": "Validator worker exceeded its wall-time limit.",
}
CORE_SEMANTIC_DIGEST = content_digest(
    {
        "name": "proof-core",
        "version": "0.1.0",
        "resultSchemaVersion": "1.0.0",
        "operationViewSchemaVersion": "1.0.0",
        "classifierVersion": 1,
    }
)
RUNTIME_SEMANTIC_DIGEST = content_digest(
    {
        "name": "cpython",
        "version": "3.14",
        "dependencyContract": "uv.lock",
    }
)


class RunAssemblyError(ValueError):
    """A producer invariant failed and no completed result may be emitted."""


@dataclass(frozen=True, slots=True)
class EntrypointAnalysis:
    """The three deterministic analysis layers for one declared entrypoint."""

    validator: ValidatorResult
    operations: OperationSet
    rules: RuleEvaluation


def analysis_artifacts_v1() -> AnalysisArtifacts:
    """Return the exact platform-neutral analysis identities for result v1."""

    return AnalysisArtifacts(
        core=ArtifactIdentity("proof-core", "0.1.0", CORE_SEMANTIC_DIGEST),
        validator=ArtifactIdentity(
            WORKER_NAME, WORKER_VERSION, VALIDATOR_SEMANTIC_DIGEST
        ),
        runtime=ArtifactIdentity("cpython", "3.14", RUNTIME_SEMANTIC_DIGEST),
    )


def assemble_input_closure_run(
    *,
    evaluation_time: str,
    configuration: EffectiveScanConfiguration,
    closure: InputClosure,
    limits: WorkerLimits | None = None,
) -> NormalizedRun:
    """Derive every analysis layer from immutable bytes and assemble result v1."""

    analyses: list[EntrypointAnalysis] = []
    artifacts = analysis_artifacts_v1()
    for entrypoint in closure.manifest.entrypoints:
        try:
            validator = validate_openapi(closure, entrypoint, limits=limits)
        except WorkerFailure as error:
            return assemble_worker_error_run(
                evaluation_time=evaluation_time,
                error=error,
                configuration=configuration,
                input_manifest=closure.manifest,
                artifacts=artifacts,
            )
        operations = normalize_operations(closure, entrypoint)
        analyses.append(
            EntrypointAnalysis(
                validator=validator,
                operations=operations,
                rules=evaluate_agent_contract(operations),
            )
        )
    return assemble_analysis_run(
        evaluation_time=evaluation_time,
        configuration=configuration,
        input_manifest=closure.manifest,
        analyses=analyses,
        artifacts=artifacts,
    )


def finding_fingerprint(finding: Mapping[str, Any]) -> str:
    """Recompute the result-v1 identity projection for any normalized finding."""

    try:
        location = finding["location"]
        operation = finding.get("operation")
        evidence = finding["evidence"]
        projection: dict[str, Any] = {
            "fingerprintVersion": 1,
            "source": finding["source"],
            "ruleId": finding["ruleId"],
            "location": {
                "path": location["path"],
                "pointer": location["pointer"],
            },
            "evidence": sorted(
                (_evidence_identity(item) for item in evidence),
                key=canonical_json_bytes,
            ),
        }
        if operation is not None:
            projection["operation"] = {
                "method": operation["method"],
                "path": operation["path"],
            }
        risks = sorted(set(finding.get("riskCategories", ())))
        if risks:
            projection["riskCategories"] = risks
    except (KeyError, TypeError) as error:
        raise RunAssemblyError(
            "finding is missing an identity-bearing field"
        ) from error
    return content_digest(projection)


def normalize_rule_findings(evaluation: RuleEvaluation) -> tuple[dict[str, Any], ...]:
    """Normalize and independently authenticate built-in rule findings."""

    normalized: list[dict[str, Any]] = []
    for supplied in evaluation.findings:
        if not isinstance(supplied, Finding):
            raise RunAssemblyError("rule evaluation returned an unsupported finding")
        value = supplied.to_dict()
        value["evidence"] = _sorted_unique_evidence(value["evidence"])
        if "riskCategories" in value:
            value["riskCategories"] = sorted(set(value["riskCategories"]))
        actual = finding_fingerprint(value)
        if supplied.fingerprint != actual:
            raise RunAssemblyError(
                "rule finding fingerprint does not match its payload"
            )
        value["fingerprint"] = actual
        normalized.append(value)
    return _deduplicate_findings(normalized)


def normalize_validator_findings(
    result: ValidatorResult,
) -> tuple[dict[str, Any], ...]:
    """Project bounded validator diagnostics into normalized result findings."""

    _validate_validator_result(result)
    if result.outcome == "limit-exceeded":
        raise RunAssemblyError("incomplete validator output cannot become findings")
    normalized = [
        _validator_finding(result.entrypoint, diagnostic)
        for diagnostic in result.diagnostics
    ]
    return _deduplicate_findings(normalized)


def normalize_core_findings(operation_set: OperationSet) -> tuple[dict[str, Any], ...]:
    """Project normalization issues so indeterminate operations cannot pass silently."""

    normalized: list[dict[str, Any]] = [
        _core_finding(issue, operation=None) for issue in operation_set.issues
    ]
    for operation in operation_set.operations:
        normalized.extend(
            _core_finding(issue, operation=operation) for issue in operation.issues
        )
    return _deduplicate_findings(normalized)


def evaluate_gate(findings: Iterable[Mapping[str, Any]], fail_on: FailOn) -> GateResult:
    """Apply the documented threshold truth table to canonical findings."""

    ordered = tuple(findings)
    if not ordered:
        return GateResult("pass", fail_on, ())
    if fail_on == "none":
        return GateResult(
            "advisory",
            fail_on,
            tuple(sorted({str(item["fingerprint"]) for item in ordered})),
        )
    threshold = _FAIL_ON_RANK[fail_on]
    blocking = tuple(
        sorted(
            {
                str(item["fingerprint"])
                for item in ordered
                if _SEVERITY_RANK[str(item["severity"])] <= threshold
            }
        )
    )
    if blocking:
        return GateResult("blocked", fail_on, blocking)
    return GateResult(
        "advisory",
        fail_on,
        tuple(sorted({str(item["fingerprint"]) for item in ordered})),
    )


def input_attempt_identity(
    state: Literal["not-attempted", "failed"],
    *,
    selectors: Iterable[str] = (),
    available_files: Iterable[tuple[str, str]] = (),
) -> ContentIdentity:
    """Identify a bounded input attempt without host paths, messages, or raw bytes."""

    selector_values = tuple(selectors)
    available_file_values = tuple(available_files)
    if state == "not-attempted" and (selector_values or available_file_values):
        raise RunAssemblyError(
            "a not-attempted input identity cannot contain resources"
        )
    for path in selector_values:
        _validate_attempt_path(path)
    for path, digest in available_file_values:
        _validate_attempt_path(path)
        ContentIdentity(digest)
    files = [
        {"path": path, "digest": digest}
        for path, digest in sorted(set(available_file_values))
    ]
    projection = {
        "identityVersion": 1,
        "kind": "input-attempt",
        "state": state,
        "selectors": sorted(set(selector_values)),
        "availableFiles": files,
    }
    return ContentIdentity(content_digest(projection))


def assemble_analysis_run(
    *,
    evaluation_time: str,
    configuration: EffectiveScanConfiguration,
    input_manifest: InputManifest,
    analyses: Iterable[EntrypointAnalysis],
    artifacts: AnalysisArtifacts,
) -> NormalizedRun:
    """Assemble a complete run, or fail closed on incomplete validator output."""

    materialized = tuple(analyses)
    input_failures = tuple(
        item
        for item in materialized
        if any(
            diagnostic.kind in {"input", "parse", "reference"}
            for diagnostic in item.validator.diagnostics
        )
    )
    if input_failures:
        return assemble_validator_input_error_run(
            evaluation_time=evaluation_time,
            results=tuple(item.validator for item in input_failures),
            configuration=configuration,
            input_manifest=input_manifest,
            artifacts=artifacts,
        )
    limited = tuple(
        item for item in materialized if item.validator.outcome == "limit-exceeded"
    )
    if limited:
        return assemble_validator_limit_run(
            evaluation_time=evaluation_time,
            results=tuple(item.validator for item in limited),
            configuration=configuration,
            input_manifest=input_manifest,
            artifacts=artifacts,
        )
    return assemble_completed_run(
        evaluation_time=evaluation_time,
        configuration=configuration,
        input_manifest=input_manifest,
        analyses=materialized,
        artifacts=artifacts,
    )


def assemble_validator_input_error_run(
    *,
    evaluation_time: str,
    results: Iterable[ValidatorResult],
    configuration: EffectiveScanConfiguration,
    input_manifest: InputManifest,
    artifacts: AnalysisArtifacts,
) -> NormalizedRun:
    """Normalize a validator input diagnostic without claiming completed analysis."""

    _validate_input_manifest(input_manifest)
    materialized = tuple(results)
    errors: list[TerminalError] = []
    for result in materialized:
        _validate_validator_result(result)
        input_diagnostics = tuple(
            diagnostic
            for diagnostic in result.diagnostics
            if diagnostic.kind in {"input", "parse", "reference"}
        )
        if (
            result.outcome != "invalid"
            or not input_diagnostics
            or len(input_diagnostics) != len(result.diagnostics)
            or result.entrypoint not in input_manifest.entrypoints
            or result.manifest_digest != input_manifest.digest
        ):
            raise RunAssemblyError(
                "validator input-error result does not match the supported contract"
            )
        for diagnostic in input_diagnostics:
            location: dict[str, Any] = {
                "path": diagnostic.source or result.entrypoint,
                "pointer": diagnostic.pointer or "",
            }
            if diagnostic.line is not None and diagnostic.column is not None:
                location.update({"line": diagnostic.line, "column": diagnostic.column})
            errors.append(
                TerminalError(
                    diagnostic.code,
                    "input",
                    _validator_message(diagnostic),
                    False,
                    location=location,
                )
            )
    if not errors:
        raise RunAssemblyError("validator input-error requires a diagnostic")
    return _assemble_terminal_errors_run(
        evaluation_time=evaluation_time,
        status="input-error",
        errors=tuple(sorted(errors, key=_terminal_error_sort_key)),
        fail_on=configuration.fail_on,
        provenance=_provenance(configuration, input_manifest.digest, artifacts),
        scanned_files=len(input_manifest.files),
    )


def assemble_validator_limit_run(
    *,
    evaluation_time: str,
    results: Iterable[ValidatorResult],
    configuration: EffectiveScanConfiguration,
    input_manifest: InputManifest,
    artifacts: AnalysisArtifacts,
) -> NormalizedRun:
    """Fail closed when the validator cannot emit a complete diagnostic set."""

    _validate_input_manifest(input_manifest)
    materialized = tuple(results)
    for result in materialized:
        _validate_validator_result(result)
        if result.outcome != "limit-exceeded":
            raise RunAssemblyError(
                "validator limit factory requires incomplete results"
            )
        if (
            result.entrypoint not in input_manifest.entrypoints
            or result.manifest_digest != input_manifest.digest
        ):
            raise RunAssemblyError(
                "validator limit input identity does not match provenance"
            )
    if not materialized:
        raise RunAssemblyError("validator limit factory requires a result")
    return _assemble_terminal_run(
        evaluation_time=evaluation_time,
        status="input-error",
        error=TerminalError(
            "validator.observation-limit",
            "input",
            "Validator diagnostics exceeded the bounded observation limit.",
            False,
        ),
        fail_on=configuration.fail_on,
        provenance=_provenance(configuration, input_manifest.digest, artifacts),
        scanned_files=len(input_manifest.files),
        truncated_findings=sum(item.diagnostics_truncated for item in materialized),
    )


def assemble_completed_run(
    *,
    evaluation_time: str,
    configuration: EffectiveScanConfiguration,
    input_manifest: InputManifest,
    analyses: Iterable[EntrypointAnalysis],
    artifacts: AnalysisArtifacts,
) -> NormalizedRun:
    """Assemble and schema-check one aggregate completed normalized run."""

    _validate_input_manifest(input_manifest)
    materialized = tuple(analyses)
    by_entrypoint = _validate_analysis_join(configuration, input_manifest, materialized)
    finding_values: list[dict[str, Any]] = []
    operation_identities: dict[tuple[str, str, str], tuple[bytes, bool, bool]] = {}
    for entrypoint in input_manifest.entrypoints:
        analysis = by_entrypoint[entrypoint]
        finding_values.extend(normalize_validator_findings(analysis.validator))
        finding_values.extend(normalize_core_findings(analysis.operations))
        if analysis.rules != evaluate_agent_contract(analysis.operations):
            raise RunAssemblyError(
                "rule evaluation payload does not match normalized operations"
            )
        finding_values.extend(normalize_rule_findings(analysis.rules))
        if analysis.operations.state == "ready":
            expected_evaluated = sum(
                item.state == "ready" for item in analysis.operations.operations
            )
            expected_indeterminate = (
                len(analysis.operations.operations) - expected_evaluated
            )
        else:
            expected_evaluated = 0
            expected_indeterminate = len(analysis.operations.operations)
            if not normalize_core_findings(analysis.operations):
                raise RunAssemblyError(
                    "an indeterminate operation set must contain a normalized issue"
                )
        if (
            analysis.rules.evaluated_operations != expected_evaluated
            or analysis.rules.indeterminate_operations != expected_indeterminate
        ):
            raise RunAssemblyError(
                "rule evaluation counts do not match normalized operations"
            )
        _record_operation_identities(analysis.operations, operation_identities)

    findings = _deduplicate_findings(finding_values)
    scanned_operations = sum(item[1] for item in operation_identities.values())
    excluded_operations = len(operation_identities) - scanned_operations
    risky_operations = sum(
        item[1] and item[2] for item in operation_identities.values()
    )
    summary = _summary(
        findings=findings,
        errors=(),
        scanned_files=len(input_manifest.files),
        scanned_operations=scanned_operations,
        excluded_operations=excluded_operations,
        risky_operations=risky_operations,
        truncated_findings=0,
    )
    run = NormalizedRun(
        evaluation_time=evaluation_time,
        status="completed",
        findings=findings,
        errors=(),
        summary=summary,
        gate=evaluate_gate(findings, configuration.fail_on),
        provenance=_provenance(configuration, input_manifest.digest, artifacts),
    )
    return _validate_run(run)


def assemble_configuration_error_run(
    *,
    evaluation_time: str,
    error: ConfigurationError,
) -> NormalizedRun:
    """Build a schema-valid input-error before an effective configuration exists."""

    artifacts = analysis_artifacts_v1()
    identity = _artifact_identity(AGENT_CONTRACT_IDENTITY)
    terminal = _terminal_from_mapping(error.to_terminal_error())
    provenance = RunProvenance(
        artifacts.core,
        artifacts.validator,
        identity,
        artifacts.runtime,
        ContentIdentity(error.provenance_dict()["digest"]),
        input_attempt_identity("not-attempted"),
    )
    return _assemble_terminal_run(
        evaluation_time=evaluation_time,
        status="input-error",
        error=terminal,
        fail_on="high",
        provenance=provenance,
    )


def assemble_input_error_run(
    *,
    evaluation_time: str,
    error: InputClosureError,
    configuration: EffectiveScanConfiguration,
) -> NormalizedRun:
    """Build a deterministic input-error for a failed immutable input attempt."""

    artifacts = analysis_artifacts_v1()
    location = None
    if error.path is not None:
        location = {"path": error.path, "pointer": ""}
    terminal = TerminalError(
        f"input.{error.code}",
        "input",
        _INPUT_ERROR_MESSAGES.get(error.code, "Input could not be prepared safely."),
        False,
        location=location,
    )
    provenance = RunProvenance(
        artifacts.core,
        artifacts.validator,
        _artifact_identity(configuration.rule_pack),
        artifacts.runtime,
        ContentIdentity(configuration.digest),
        input_attempt_identity("failed", selectors=configuration.specifications),
    )
    return _assemble_terminal_run(
        evaluation_time=evaluation_time,
        status="input-error",
        error=terminal,
        fail_on=configuration.fail_on,
        provenance=provenance,
    )


def assemble_worker_error_run(
    *,
    evaluation_time: str,
    error: WorkerFailure,
    configuration: EffectiveScanConfiguration,
    input_manifest: InputManifest,
    artifacts: AnalysisArtifacts,
) -> NormalizedRun:
    """Build an internal-error without trusting worker failure kind strings."""

    _validate_input_manifest(input_manifest)
    kind = _WORKER_KIND.get(error.kind, "internal")
    terminal = TerminalError(
        error.code,
        kind,
        _WORKER_MESSAGES.get(error.code, "Validator worker failed safely."),
        error.code in _RETRYABLE_WORKER_CODES,
    )
    return _assemble_terminal_run(
        evaluation_time=evaluation_time,
        status="internal-error",
        error=terminal,
        fail_on=configuration.fail_on,
        provenance=_provenance(configuration, input_manifest.digest, artifacts),
        scanned_files=len(input_manifest.files),
    )


def _validator_finding(
    entrypoint: str, diagnostic: ValidatorDiagnostic
) -> dict[str, Any]:
    safe_message = _validator_message(diagnostic)
    location: dict[str, Any] = {
        "path": diagnostic.source or entrypoint,
        "pointer": diagnostic.pointer or "",
    }
    if diagnostic.line is not None and diagnostic.column is not None:
        location.update({"line": diagnostic.line, "column": diagnostic.column})
    result: dict[str, Any] = {
        "ruleId": diagnostic.code,
        "source": "openapi-validator",
        "severity": diagnostic.severity,
        "message": safe_message,
        "location": location,
        "evidence": [
            {
                "kind": "schema",
                "description": safe_message,
                "pointer": diagnostic.pointer or "",
            }
        ],
        "remediation": {
            "recommendation": (
                "Correct the OpenAPI document so it satisfies this "
                "validator constraint."
            )
        },
    }
    result["fingerprint"] = finding_fingerprint(result)
    return result


def _core_finding(
    issue: NormalizationIssue, operation: NormalizedOperation | None
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "ruleId": issue.code,
        "source": "core",
        "severity": "error",
        "message": issue.message,
        "location": {"path": issue.source, "pointer": issue.pointer},
        "evidence": [
            {"kind": "schema", "description": issue.message, "pointer": issue.pointer}
        ],
        "remediation": {
            "recommendation": (
                "Correct the OpenAPI construct identified by this "
                "normalization diagnostic."
            )
        },
    }
    if operation is not None:
        identity = {"method": operation.method, "path": operation.path}
        if operation.operation_id is not None:
            identity["operationId"] = operation.operation_id
        result["operation"] = identity
        if operation.risk_categories:
            result["riskCategories"] = list(operation.risk_categories)
    result["fingerprint"] = finding_fingerprint(result)
    return result


def _validate_analysis_join(
    configuration: EffectiveScanConfiguration,
    input_manifest: InputManifest,
    analyses: tuple[EntrypointAnalysis, ...],
) -> dict[str, EntrypointAnalysis]:
    if tuple(sorted(input_manifest.entrypoints)) != input_manifest.entrypoints:
        raise RunAssemblyError("input manifest entrypoints must be canonical")
    by_entrypoint: dict[str, EntrypointAnalysis] = {}
    for analysis in analyses:
        entrypoint = analysis.validator.entrypoint
        if entrypoint in by_entrypoint:
            raise RunAssemblyError("an entrypoint analysis was supplied more than once")
        _validate_validator_result(analysis.validator)
        if analysis.validator.outcome not in {"valid", "invalid"}:
            raise RunAssemblyError("validator output is incomplete")
        if any(
            diagnostic.kind in {"input", "parse", "reference"}
            for diagnostic in analysis.validator.diagnostics
        ):
            raise RunAssemblyError(
                "validator input diagnostics require an input-error run"
            )
        if analysis.operations.entrypoint != entrypoint:
            raise RunAssemblyError("validator and operation entrypoints differ")
        if (
            analysis.validator.manifest_digest != input_manifest.digest
            or analysis.operations.manifest_digest != input_manifest.digest
        ):
            raise RunAssemblyError("analysis input identity does not match provenance")
        if analysis.rules.rulepack != configuration.rule_pack:
            raise RunAssemblyError(
                "rule evaluation identity does not match configuration"
            )
        by_entrypoint[entrypoint] = analysis
    if tuple(sorted(by_entrypoint)) != input_manifest.entrypoints:
        raise RunAssemblyError("analyses must exactly cover manifest entrypoints")
    return by_entrypoint


def _validate_input_manifest(input_manifest: InputManifest) -> None:
    entrypoints = tuple(input_manifest.entrypoints)
    files = tuple(input_manifest.files)
    file_paths = tuple(item.path for item in files)
    if not entrypoints or entrypoints != tuple(sorted(set(entrypoints))):
        raise RunAssemblyError("input manifest entrypoints must be sorted and unique")
    if not files or file_paths != tuple(sorted(set(file_paths))):
        raise RunAssemblyError("input manifest files must be sorted and unique")
    if not set(entrypoints).issubset(file_paths):
        raise RunAssemblyError(
            "input manifest entrypoints must identify manifest files"
        )
    if any(
        isinstance(item.size, bool) or not isinstance(item.size, int) or item.size < 0
        for item in files
    ):
        raise RunAssemblyError("input manifest file sizes are invalid")
    if sum(item.size for item in files) != input_manifest.total_bytes:
        raise RunAssemblyError("input manifest byte count is inconsistent")
    try:
        for item in files:
            _validate_attempt_path(item.path)
            ContentIdentity(item.digest)
        actual_digest = content_digest(input_manifest.content_dict())
    except (TypeError, ValueError) as error:
        raise RunAssemblyError("input manifest content is invalid") from error
    if actual_digest != input_manifest.digest:
        raise RunAssemblyError("input manifest digest does not match its content")


def _validate_validator_result(result: ValidatorResult) -> None:
    if result.outcome not in {"valid", "invalid", "limit-exceeded"}:
        raise RunAssemblyError("validator result has an unsupported outcome")
    if (
        isinstance(result.diagnostics_observed, bool)
        or not isinstance(result.diagnostics_observed, int)
        or result.diagnostics_observed < 0
        or isinstance(result.diagnostics_truncated, bool)
        or not isinstance(result.diagnostics_truncated, int)
        or result.diagnostics_truncated < 0
        or len(result.diagnostics) > result.diagnostics_observed
        or result.diagnostics_truncated
        > result.diagnostics_observed - len(result.diagnostics) + 1
        or (
            result.outcome == "valid"
            and (
                result.diagnostics
                or result.diagnostics_observed != 0
                or result.diagnostics_truncated != 0
            )
        )
        or (
            result.outcome == "invalid"
            and (not result.diagnostics or result.diagnostics_truncated != 0)
        )
        or (
            result.outcome == "limit-exceeded"
            and (result.diagnostics_observed == 0 or result.diagnostics_truncated == 0)
        )
    ):
        raise RunAssemblyError("validator outcome and statistics disagree")


def _record_operation_identities(
    operation_set: OperationSet,
    observed: dict[tuple[str, str, str], tuple[bytes, bool, bool]],
) -> None:
    for operation in operation_set.operations:
        key = (operation_set.entrypoint, operation.path, operation.method)
        payload = canonical_json_bytes(operation.to_dict())
        scanned = operation_set.state == "ready" and operation.state == "ready"
        identity = (payload, scanned, bool(operation.risk_categories))
        previous = observed.setdefault(key, identity)
        if previous != identity:
            raise RunAssemblyError("operation identity maps to different payloads")


def _provenance(
    configuration: EffectiveScanConfiguration,
    input_digest: str,
    artifacts: AnalysisArtifacts,
) -> RunProvenance:
    _validate_artifacts(artifacts)
    return RunProvenance(
        artifacts.core,
        artifacts.validator,
        _artifact_identity(configuration.rule_pack),
        artifacts.runtime,
        ContentIdentity(configuration.digest),
        ContentIdentity(input_digest),
    )


def _artifact_identity(value: Any) -> ArtifactIdentity:
    return ArtifactIdentity(value.name, value.version, value.digest)


def _summary(
    *,
    findings: tuple[dict[str, Any], ...],
    errors: tuple[TerminalError, ...],
    scanned_files: int,
    scanned_operations: int,
    excluded_operations: int,
    risky_operations: int,
    truncated_findings: int,
) -> RunSummary:
    by_severity = {name: 0 for name in _SEVERITY_RANK}
    for finding in findings:
        try:
            by_severity[str(finding["severity"])] += 1
        except KeyError as error:
            raise RunAssemblyError("finding has an unsupported severity") from error
    return RunSummary(
        len(findings),
        len(errors),
        by_severity,
        scanned_files,
        scanned_operations,
        excluded_operations,
        risky_operations,
        truncated_findings,
    )


def _assemble_terminal_run(
    *,
    evaluation_time: str,
    status: Literal["input-error", "internal-error"],
    error: TerminalError,
    fail_on: FailOn,
    provenance: RunProvenance,
    scanned_files: int = 0,
    truncated_findings: int = 0,
) -> NormalizedRun:
    return _assemble_terminal_errors_run(
        evaluation_time=evaluation_time,
        status=status,
        errors=(error,),
        fail_on=fail_on,
        provenance=provenance,
        scanned_files=scanned_files,
        truncated_findings=truncated_findings,
    )


def _assemble_terminal_errors_run(
    *,
    evaluation_time: str,
    status: Literal["input-error", "internal-error"],
    errors: tuple[TerminalError, ...],
    fail_on: FailOn,
    provenance: RunProvenance,
    scanned_files: int = 0,
    truncated_findings: int = 0,
) -> NormalizedRun:
    if not errors:
        raise RunAssemblyError("terminal runs require at least one error")
    run = NormalizedRun(
        evaluation_time=evaluation_time,
        status=status,
        findings=(),
        errors=errors,
        summary=_summary(
            findings=(),
            errors=errors,
            scanned_files=scanned_files,
            scanned_operations=0,
            excluded_operations=0,
            risky_operations=0,
            truncated_findings=truncated_findings,
        ),
        gate=GateResult("not-evaluated", fail_on, ()),
        provenance=provenance,
    )
    return _validate_run(run)


def _validate_run(run: NormalizedRun) -> NormalizedRun:
    try:
        from proof_core.result_schema import validate_normalized_run

        validate_normalized_run(run.to_dict())
    except ImportError:
        raise
    except Exception as error:
        raise RunAssemblyError("assembled run violates result schema v1") from error
    return run


def _terminal_from_mapping(value: Mapping[str, Any]) -> TerminalError:
    code = str(value["code"])
    return TerminalError(
        code,
        str(value["kind"]),
        _CONFIGURATION_MESSAGES.get(
            code, "Configuration could not be resolved safely."
        ),
        bool(value["retryable"]),
        location=value.get("location"),
    )


def _validate_attempt_path(path: str) -> None:
    try:
        TerminalError(
            "input.identity",
            "input",
            "Input identity path validation.",
            False,
            location={"path": path, "pointer": ""},
        )
    except (TypeError, ValueError) as error:
        raise RunAssemblyError(
            "input attempt path is not repository-relative"
        ) from error


def _validator_message(diagnostic: ValidatorDiagnostic) -> str:
    if diagnostic.kind == "schema":
        return _VALIDATOR_MESSAGES.get(
            diagnostic.code, "The OpenAPI document violates a validator constraint."
        )
    if diagnostic.kind in {"input", "parse", "reference"}:
        return {
            "input.unsupported-dialect": (
                "Only OpenAPI 3.0 and 3.1 documents are supported."
            ),
            "parse.alias-expansion-limit": (
                "Input document exceeds the YAML alias-expansion limit."
            ),
            "parse.alias-limit": "Input document exceeds the YAML alias limit.",
            "parse.cyclic-alias": "Input document contains a cyclic YAML alias.",
            "parse.duplicate-key": "Input document contains a duplicate key.",
            "parse.invalid-document": "Input document is invalid.",
            "parse.invalid-json": "Input document is not valid strict JSON.",
            "parse.invalid-utf8": "Input document must be strict UTF-8.",
            "parse.invalid-yaml": "Input document is not valid strict YAML.",
            "parse.multiple-documents": "Input must contain exactly one document.",
            "parse.nesting-limit": "Input document exceeds the nesting limit.",
            "ref.path-outside-root": "Reference escapes the repository root.",
            "ref.scheme-denied": "Only repository-local references are supported.",
            "ref.unresolved": "A local reference cannot be resolved.",
        }.get(diagnostic.code, "Input cannot be evaluated safely.")
    return "The OpenAPI document violates a validator constraint."


def _terminal_error_sort_key(error: TerminalError) -> tuple[Any, ...]:
    location = error.location or {}
    return (
        error.kind,
        error.code,
        location.get("path", ""),
        location.get("pointer", ""),
        error.message,
        canonical_json_bytes(error.to_dict()),
    )


def _validate_artifacts(artifacts: AnalysisArtifacts) -> None:
    if artifacts != analysis_artifacts_v1():
        raise RunAssemblyError("analysis artifact identity is not trusted")


def _evidence_identity(evidence: Mapping[str, Any]) -> dict[str, Any]:
    result = {
        "kind": evidence["kind"],
        "value": evidence.get("value", evidence["description"]),
    }
    if "pointer" in evidence:
        result["pointer"] = evidence["pointer"]
    return result


def _sorted_unique_evidence(
    values: Iterable[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    unique = {
        canonical_json_bytes(_evidence_identity(value)): dict(value) for value in values
    }
    return [unique[key] for key in sorted(unique)]


def _finding_sort_key(value: Mapping[str, Any]) -> tuple[Any, ...]:
    location = value["location"]
    return (
        _SEVERITY_RANK[str(value["severity"])],
        str(value["source"]),
        str(value["ruleId"]),
        str(location["path"]),
        str(location["pointer"]),
        str(value["fingerprint"]),
    )


def _deduplicate_findings(
    findings: Iterable[Mapping[str, Any]],
) -> tuple[dict[str, Any], ...]:
    by_fingerprint: dict[str, tuple[bytes, dict[str, Any]]] = {}
    for value in findings:
        materialized = dict(value)
        fingerprint = str(materialized["fingerprint"])
        payload = canonical_json_bytes(materialized)
        previous = by_fingerprint.get(fingerprint)
        if previous is not None and previous[0] != payload:
            raise RunAssemblyError("a finding fingerprint maps to different payloads")
        by_fingerprint[fingerprint] = (payload, materialized)
    return tuple(
        sorted((item[1] for item in by_fingerprint.values()), key=_finding_sort_key)
    )
