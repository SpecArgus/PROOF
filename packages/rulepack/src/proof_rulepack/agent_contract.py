"""The five deterministic Agent contract rules in rule-pack version 0.1.0."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any

import rfc8785

RULESET_NAME = "agent-contract"
RULESET_VERSION = "0.1.0"
RESULT_SCHEMA_VERSION = "1.0.0"
FINGERPRINT_VERSION = 1
CLASSIFIER_VERSION = 1
SOURCE = "agent-rule"
JSON_WHITESPACE = " \t\r\n"
CONFIRMATION_RISKS = frozenset(
    {"destructive", "external_side_effect", "financial_action", "permission_change"}
)
SECURITY_RISKS = frozenset({"permission_change", "sensitive_data"})
STATE_CHANGING_METHODS = frozenset({"delete", "patch", "post", "put"})
IGNORED_HEADER_PARAMETERS = frozenset({"accept", "authorization", "content-type"})
_ERROR_STATUS = re.compile(r"^[45][0-9]{2}$")
_SEVERITY_RANK = {"error": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

RULES: tuple[dict[str, Any], ...] = (
    {
        "id": "AGT-CTX-001",
        "name": "Tool Selection Contract Incomplete",
        "severity": "medium",
        "message": "Operation is missing tool-selection metadata: {fields}.",
        "recommendation": (
            "Add a stable operationId and a concise summary or description that "
            "distinguishes this tool."
        ),
    },
    {
        "id": "AGT-PARAM-001",
        "name": "Parameter Lacks Domain-Specific Meaning",
        "severity": "medium",
        "message": "Parameter '{name}' in '{in}' is missing a non-empty description.",
        "recommendation": (
            "Describe the parameter's domain meaning, accepted values, units, and "
            "important constraints."
        ),
    },
    {
        "id": "AGT-RESP-001",
        "name": "Missing Structured Error Response",
        "severity": "medium",
        "message": "State-changing operation has no structured JSON error response.",
        "recommendation": (
            "Declare a 4xx, 5xx, or default JSON error response with a reusable schema."
        ),
    },
    {
        "id": "AGT-POL-001",
        "name": "Dangerous API Without Confirmation Policy",
        "severity": "high",
        "message": (
            "Operation classified as {risks} has no valid confirmation policy."
        ),
        "recommendation": (
            "Declare x-agent-policy.confirmation with required, conditional, or a "
            "reasoned not-required mode."
        ),
    },
    {
        "id": "AGT-POL-002",
        "name": "Sensitive or Privileged API Without Security Metadata",
        "severity": "high",
        "message": (
            "Operation classified as {risks} is missing security metadata: "
            "{requirements}."
        ),
        "recommendation": (
            "Declare effective OpenAPI security and the required x-agent-policy "
            "classification or roles."
        ),
    },
)
_RULE_BY_ID = {item["id"]: item for item in RULES}
_SEMANTIC_MANIFEST = {
    "rulesetName": RULESET_NAME,
    "rulesetVersion": RULESET_VERSION,
    "resultSchemaVersion": RESULT_SCHEMA_VERSION,
    "fingerprintVersion": FINGERPRINT_VERSION,
    "classifierVersion": CLASSIFIER_VERSION,
    "rules": RULES,
    "confirmationRisks": sorted(CONFIRMATION_RISKS),
    "securityRisks": sorted(SECURITY_RISKS),
    "stateChangingMethods": sorted(STATE_CHANGING_METHODS),
    "ignoredHeaderParameters": sorted(IGNORED_HEADER_PARAMETERS),
    "jsonWhitespace": JSON_WHITESPACE,
    "contextRequirements": ["operationId", "summary-or-description"],
    "parameterRequirement": "non-empty-description",
    "structuredError": {
        "statuses": ["400-599", "4XX", "5XX", "default"],
        "mediaTypes": ["application/json", "*+json"],
        "requiresSchema": True,
    },
    "confirmation": {
        "required": [],
        "conditional": ["condition"],
        "not-required": ["reason"],
    },
    "security": {
        "requiresNonAnonymousRequirement": True,
        "sensitive_data": ["confidential", "restricted"],
        "permission_change": ["authorization.roles"],
    },
    "findingOrdering": [
        "severity",
        "source",
        "ruleId",
        "location.path",
        "location.pointer",
        "fingerprint",
    ],
}


@dataclass(frozen=True, slots=True)
class RulePackIdentity:
    name: str
    version: str
    digest: str

    def to_dict(self) -> dict[str, str]:
        return {"name": self.name, "version": self.version, "digest": self.digest}


AGENT_CONTRACT_IDENTITY = RulePackIdentity(
    name=RULESET_NAME,
    version=RULESET_VERSION,
    digest=f"sha256:{hashlib.sha256(rfc8785.dumps(_SEMANTIC_MANIFEST)).hexdigest()}",
)


@dataclass(frozen=True, slots=True)
class FindingLocation:
    path: str
    pointer: str

    def to_dict(self) -> dict[str, str]:
        return {"path": self.path, "pointer": self.pointer}


@dataclass(frozen=True, slots=True)
class FindingOperation:
    method: str
    path: str
    operation_id: str | None = None

    def to_dict(self) -> dict[str, str]:
        value = {"method": self.method, "path": self.path}
        if self.operation_id is not None:
            value["operationId"] = self.operation_id
        return value


@dataclass(frozen=True, slots=True)
class Evidence:
    kind: str
    description: str
    pointer: str | None = None
    value: str | None = None

    def to_dict(self) -> dict[str, str]:
        result = {"kind": self.kind, "description": self.description}
        if self.pointer is not None:
            result["pointer"] = self.pointer
        if self.value is not None:
            result["value"] = self.value
        return result

    def identity_dict(self) -> dict[str, str]:
        result = {
            "kind": self.kind,
            "value": self.value if self.value is not None else self.description,
        }
        if self.pointer is not None:
            result["pointer"] = self.pointer
        return result


@dataclass(frozen=True, slots=True)
class Remediation:
    recommendation: str

    def to_dict(self) -> dict[str, str]:
        return {"recommendation": self.recommendation}


@dataclass(frozen=True, slots=True)
class Finding:
    rule_id: str
    severity: str
    message: str
    fingerprint: str
    location: FindingLocation
    operation: FindingOperation
    evidence: tuple[Evidence, ...]
    remediation: Remediation
    risk_categories: tuple[str, ...] = ()
    source: str = SOURCE

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "ruleId": self.rule_id,
            "source": self.source,
            "severity": self.severity,
            "message": self.message,
            "fingerprint": self.fingerprint,
            "location": self.location.to_dict(),
            "operation": self.operation.to_dict(),
            "evidence": [item.to_dict() for item in self.evidence],
            "remediation": self.remediation.to_dict(),
        }
        if self.risk_categories:
            result["riskCategories"] = list(self.risk_categories)
        return result


@dataclass(frozen=True, slots=True)
class RuleEvaluation:
    rulepack: RulePackIdentity
    findings: tuple[Finding, ...]
    evaluated_operations: int
    indeterminate_operations: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "rulepack": self.rulepack.to_dict(),
            "findings": [item.to_dict() for item in self.findings],
            "evaluatedOperations": self.evaluated_operations,
            "indeterminateOperations": self.indeterminate_operations,
        }


def _non_empty(value: str | None) -> bool:
    return isinstance(value, str) and bool(value.strip(JSON_WHITESPACE))


def _operation_identity(operation: Any) -> FindingOperation:
    operation_id = (
        operation.operation_id if _non_empty(operation.operation_id) else None
    )
    return FindingOperation(operation.method, operation.path, operation_id)


def _fingerprint_projection(
    *,
    rule_id: str,
    location: FindingLocation,
    operation: FindingOperation,
    risk_categories: tuple[str, ...],
    evidence: tuple[Evidence, ...],
) -> dict[str, Any]:
    projection: dict[str, Any] = {
        "fingerprintVersion": FINGERPRINT_VERSION,
        "source": SOURCE,
        "ruleId": rule_id,
        "location": location.to_dict(),
        "operation": {"method": operation.method, "path": operation.path},
        "evidence": sorted(
            (item.identity_dict() for item in evidence), key=rfc8785.dumps
        ),
    }
    if risk_categories:
        projection["riskCategories"] = list(risk_categories)
    return projection


def _make_finding(
    *,
    rule_id: str,
    message: str,
    location: FindingLocation,
    operation: Any,
    evidence: list[Evidence],
    risk_categories: tuple[str, ...] = (),
) -> Finding:
    rule = _RULE_BY_ID[rule_id]
    unique = {rfc8785.dumps(item.identity_dict()): item for item in evidence}
    ordered_evidence = tuple(unique[key] for key in sorted(unique))
    ordered_risks = tuple(sorted(set(risk_categories)))
    operation_identity = _operation_identity(operation)
    projection = _fingerprint_projection(
        rule_id=rule_id,
        location=location,
        operation=operation_identity,
        risk_categories=ordered_risks,
        evidence=ordered_evidence,
    )
    fingerprint = f"sha256:{hashlib.sha256(rfc8785.dumps(projection)).hexdigest()}"
    return Finding(
        rule_id=rule_id,
        severity=rule["severity"],
        message=message,
        fingerprint=fingerprint,
        location=location,
        operation=operation_identity,
        evidence=ordered_evidence,
        remediation=Remediation(rule["recommendation"]),
        risk_categories=ordered_risks,
    )


def _risk_evidence(
    operation: Any, categories: frozenset[str] | None = None
) -> list[Evidence]:
    result: list[Evidence] = []
    for signal in operation.risk_signals:
        if categories is not None and signal.category not in categories:
            continue
        label = {
            "extension": "Explicit policy risk",
            "keyword": "operationId token",
            "method": "HTTP method",
            "path": "Path token",
        }[signal.kind]
        result.append(
            Evidence(
                kind=signal.kind,
                pointer=signal.pointer,
                value=signal.value,
                description=(
                    f"{label} '{signal.value}' contributes {signal.category}."
                ),
            )
        )
    return result


def _evaluate_context(operation: Any) -> list[Finding]:
    missing: list[str] = []
    if not _non_empty(operation.operation_id):
        missing.append("operationId")
    if not (_non_empty(operation.summary) or _non_empty(operation.description)):
        missing.append("summary-or-description")
    if not missing:
        return []
    evidence = [
        Evidence(
            kind="schema",
            pointer=operation.pointer,
            value=field,
            description=f"Required tool-selection metadata '{field}' is missing.",
        )
        for field in missing
    ]
    rule = _RULE_BY_ID["AGT-CTX-001"]
    return [
        _make_finding(
            rule_id="AGT-CTX-001",
            message=rule["message"].format(fields=", ".join(missing)),
            location=FindingLocation(operation.source, operation.pointer),
            operation=operation,
            evidence=evidence,
        )
    ]


def _evaluate_parameters(operation: Any) -> list[Finding]:
    findings: list[Finding] = []
    rule = _RULE_BY_ID["AGT-PARAM-001"]
    for parameter in operation.parameters:
        if (
            parameter.location.lower() == "header"
            and parameter.name.lower() in IGNORED_HEADER_PARAMETERS
        ) or _non_empty(parameter.description):
            continue
        findings.append(
            _make_finding(
                rule_id="AGT-PARAM-001",
                message=rule["message"].format(
                    name=parameter.name, **{"in": parameter.location}
                ),
                location=FindingLocation(parameter.source, parameter.pointer),
                operation=operation,
                evidence=[
                    Evidence(
                        kind="schema",
                        pointer=parameter.pointer,
                        value="description",
                        description="Parameter description is missing.",
                    )
                ],
            )
        )
    return findings


def _is_structured_error(response: Any) -> bool:
    status = response.status_code
    is_error = (
        status == "default"
        or status in {"4XX", "5XX"}
        or _ERROR_STATUS.fullmatch(status) is not None
    )
    if not is_error:
        return False
    return any(
        media_type.lower() == "application/json" or media_type.lower().endswith("+json")
        for media_type in response.schema_media_types
    )


def _evaluate_responses(operation: Any) -> list[Finding]:
    relevant_risks = CONFIRMATION_RISKS & set(operation.risk_categories)
    if operation.method not in STATE_CHANGING_METHODS and not relevant_risks:
        return []
    if any(_is_structured_error(response) for response in operation.responses):
        return []
    evidence = [
        Evidence(
            kind="method",
            pointer=operation.pointer,
            value=operation.method,
            description=(
                f"HTTP method '{operation.method}' makes the structured-error "
                "rule applicable."
            ),
        )
    ]
    evidence.extend(_risk_evidence(operation))
    rule = _RULE_BY_ID["AGT-RESP-001"]
    return [
        _make_finding(
            rule_id="AGT-RESP-001",
            message=rule["message"],
            location=FindingLocation(
                operation.source, f"{operation.pointer}/responses"
            ),
            operation=operation,
            evidence=evidence,
            risk_categories=operation.risk_categories,
        )
    ]


def _valid_confirmation(policy: Any) -> bool:
    if not policy.valid or not policy.confirmation_present:
        return False
    if policy.confirmation_mode == "required":
        return True
    if policy.confirmation_mode == "conditional":
        return _non_empty(policy.confirmation_condition)
    if policy.confirmation_mode == "not-required":
        return _non_empty(policy.confirmation_reason)
    return False


def _evaluate_confirmation(operation: Any) -> list[Finding]:
    if not (CONFIRMATION_RISKS & set(operation.risk_categories)):
        return []
    if _valid_confirmation(operation.policy):
        return []
    pointer = (
        f"{operation.policy.pointer}/confirmation"
        if operation.policy.confirmation_present
        else operation.pointer
    )
    rule = _RULE_BY_ID["AGT-POL-001"]
    return [
        _make_finding(
            rule_id="AGT-POL-001",
            message=rule["message"].format(risks=", ".join(operation.risk_categories)),
            location=FindingLocation(operation.source, pointer),
            operation=operation,
            evidence=_risk_evidence(operation),
            risk_categories=operation.risk_categories,
        )
    ]


def _security_satisfied(operation: Any) -> bool:
    return operation.security_present and any(
        requirement.schemes for requirement in operation.security
    )


def _security_location(operation: Any, missing: list[str]) -> FindingLocation:
    if "security" in missing and operation.security_present:
        return FindingLocation(operation.security_source, operation.security_pointer)
    if "dataClassification" in missing and operation.policy.data_classification_present:
        return FindingLocation(
            operation.policy.source,
            f"{operation.policy.pointer}/dataClassification",
        )
    if "authorization.roles" in missing and operation.policy.authorization_present:
        return FindingLocation(
            operation.policy.source,
            f"{operation.policy.pointer}/authorization/roles",
        )
    return FindingLocation(operation.source, operation.pointer)


def _evaluate_security(operation: Any) -> list[Finding]:
    applicable = SECURITY_RISKS & set(operation.risk_categories)
    if not applicable:
        return []
    missing: list[str] = []
    if not _security_satisfied(operation):
        missing.append("security")
    if "sensitive_data" in applicable and operation.policy.data_classification not in {
        "confidential",
        "restricted",
    }:
        missing.append("dataClassification")
    if "permission_change" in applicable and not any(
        _non_empty(role) for role in operation.policy.authorization_roles
    ):
        missing.append("authorization.roles")
    if not missing:
        return []
    rule = _RULE_BY_ID["AGT-POL-002"]
    return [
        _make_finding(
            rule_id="AGT-POL-002",
            message=rule["message"].format(
                risks=", ".join(operation.risk_categories),
                requirements=", ".join(missing),
            ),
            location=_security_location(operation, missing),
            operation=operation,
            evidence=_risk_evidence(operation, SECURITY_RISKS),
            risk_categories=operation.risk_categories,
        )
    ]


def _finding_sort_key(finding: Finding) -> tuple[Any, ...]:
    return (
        _SEVERITY_RANK[finding.severity],
        finding.source,
        finding.rule_id,
        finding.location.path,
        finding.location.pointer,
        finding.fingerprint,
    )


def evaluate_agent_contract(operation_set: Any) -> RuleEvaluation:
    """Evaluate all five built-in rules over a normalized operation set."""

    if operation_set.state != "ready":
        return RuleEvaluation(
            rulepack=AGENT_CONTRACT_IDENTITY,
            findings=(),
            evaluated_operations=0,
            indeterminate_operations=len(operation_set.operations),
        )

    findings: list[Finding] = []
    evaluated = 0
    indeterminate = 0
    for operation in operation_set.operations:
        if operation.state != "ready":
            indeterminate += 1
            continue
        evaluated += 1
        findings.extend(_evaluate_context(operation))
        findings.extend(_evaluate_parameters(operation))
        findings.extend(_evaluate_responses(operation))
        findings.extend(_evaluate_confirmation(operation))
        findings.extend(_evaluate_security(operation))
    return RuleEvaluation(
        rulepack=AGENT_CONTRACT_IDENTITY,
        findings=tuple(sorted(findings, key=_finding_sort_key)),
        evaluated_operations=evaluated,
        indeterminate_operations=indeterminate,
    )
