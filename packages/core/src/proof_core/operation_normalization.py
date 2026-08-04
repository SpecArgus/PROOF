"""Deterministic OpenAPI operation views and exact risk classification v1."""

from __future__ import annotations

import json
import posixpath
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any
from urllib.parse import unquote_to_bytes, urlsplit

import yaml

from proof_core.input_closure import InputClosure

OPERATION_VIEW_SCHEMA_VERSION = "1.0.0"
CLASSIFIER_VERSION = 1
HTTP_METHODS = frozenset(
    {"delete", "get", "head", "options", "patch", "post", "put", "trace"}
)
STATE_CHANGING_METHODS = frozenset({"delete", "patch", "post", "put"})
METHOD_CATEGORIES: Mapping[str, tuple[str, ...]] = {"delete": ("destructive",)}
STATE_CHANGING_TOKEN_CATEGORIES: Mapping[str, frozenset[str]] = {
    "destructive": frozenset(
        {
            "cancel",
            "cancels",
            "delete",
            "deletes",
            "deletion",
            "destroy",
            "destroys",
            "purge",
            "purges",
            "remove",
            "removes",
            "terminate",
            "terminates",
        }
    ),
    "external_side_effect": frozenset(
        {
            "dispatch",
            "dispatches",
            "email",
            "emails",
            "message",
            "messages",
            "notification",
            "notifications",
            "notify",
            "publish",
            "publishes",
            "send",
            "sends",
            "sms",
            "webhook",
            "webhooks",
        }
    ),
    "financial_action": frozenset(
        {
            "charge",
            "charges",
            "checkout",
            "debit",
            "debits",
            "deposit",
            "deposits",
            "invoice",
            "invoices",
            "pay",
            "payment",
            "payments",
            "payout",
            "payouts",
            "purchase",
            "purchases",
            "refund",
            "refunds",
            "transfer",
            "transfers",
            "withdraw",
            "withdrawal",
            "withdrawals",
        }
    ),
    "permission_change": frozenset(
        {
            "access",
            "grant",
            "grants",
            "invite",
            "invites",
            "permission",
            "permissions",
            "revoke",
            "revokes",
            "role",
            "roles",
        }
    ),
}
ALL_METHOD_TOKEN_CATEGORIES: Mapping[str, frozenset[str]] = {
    "sensitive_data": frozenset(
        {
            "credential",
            "credentials",
            "health",
            "medical",
            "password",
            "passwords",
            "pii",
            "profile",
            "profiles",
            "secret",
            "secrets",
            "ssn",
            "token",
            "tokens",
        }
    )
}
RISK_CATEGORIES = tuple(
    sorted(
        set(STATE_CHANGING_TOKEN_CATEGORIES)
        | set(ALL_METHOD_TOKEN_CATEGORIES)
        | {item for values in METHOD_CATEGORIES.values() for item in values}
    )
)
_INVALID_POINTER_ESCAPE = re.compile(r"~(?![01])")
_EXTENSION_KEY = re.compile(r"^x-[a-z0-9][a-z0-9._-]*$")


@dataclass(frozen=True, slots=True)
class NormalizationIssue:
    code: str
    source: str
    pointer: str
    message: str

    def to_dict(self) -> dict[str, str]:
        return {
            "code": self.code,
            "source": self.source,
            "pointer": self.pointer,
            "message": self.message,
        }


@dataclass(frozen=True, slots=True)
class NormalizedParameter:
    source: str
    pointer: str
    name: str
    location: str
    required: bool
    description: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "pointer": self.pointer,
            "name": self.name,
            "in": self.location,
            "required": self.required,
            "description": self.description,
        }


@dataclass(frozen=True, slots=True)
class NormalizedResponse:
    source: str
    pointer: str
    status_code: str
    description: str | None
    media_types: tuple[str, ...]
    schema_media_types: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "pointer": self.pointer,
            "statusCode": self.status_code,
            "description": self.description,
            "mediaTypes": list(self.media_types),
            "schemaMediaTypes": list(self.schema_media_types),
        }


@dataclass(frozen=True, slots=True)
class SecuritySchemeRequirement:
    name: str
    scopes: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "scopes": list(self.scopes)}


@dataclass(frozen=True, slots=True)
class SecurityRequirement:
    schemes: tuple[SecuritySchemeRequirement, ...]

    def to_dict(self) -> dict[str, Any]:
        return {"schemes": [item.to_dict() for item in self.schemes]}


@dataclass(frozen=True, slots=True)
class AgentPolicy:
    present: bool
    valid: bool
    source: str
    pointer: str
    explicit_risks: tuple[str, ...]
    confirmation_present: bool
    confirmation_mode: str | None
    confirmation_condition: str | None
    confirmation_reason: str | None
    authorization_present: bool
    authorization_roles: tuple[str, ...]
    data_classification_present: bool
    data_classification: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "present": self.present,
            "valid": self.valid,
            "source": self.source,
            "pointer": self.pointer,
            "risks": list(self.explicit_risks),
            "confirmation": {
                "present": self.confirmation_present,
                "mode": self.confirmation_mode,
                "condition": self.confirmation_condition,
                "reason": self.confirmation_reason,
            },
            "authorizationPresent": self.authorization_present,
            "authorizationRoles": list(self.authorization_roles),
            "dataClassificationPresent": self.data_classification_present,
            "dataClassification": self.data_classification,
        }


@dataclass(frozen=True, slots=True)
class RiskSignal:
    category: str
    kind: str
    pointer: str
    value: str
    source: str

    def to_dict(self) -> dict[str, str]:
        return {
            "category": self.category,
            "kind": self.kind,
            "source": self.source,
            "pointer": self.pointer,
            "value": self.value,
        }


@dataclass(frozen=True, slots=True)
class NormalizedOperation:
    source: str
    pointer: str
    path_source: str
    path_pointer: str
    path: str
    method: str
    operation_id: str | None
    summary: str | None
    description: str | None
    parameters: tuple[NormalizedParameter, ...]
    responses: tuple[NormalizedResponse, ...]
    security_present: bool
    security_source: str | None
    security_pointer: str | None
    security: tuple[SecurityRequirement, ...]
    policy: AgentPolicy
    risk_categories: tuple[str, ...]
    risk_signals: tuple[RiskSignal, ...]
    state: str
    issues: tuple[NormalizationIssue, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "pointer": self.pointer,
            "pathSource": self.path_source,
            "pathPointer": self.path_pointer,
            "path": self.path,
            "method": self.method,
            "operationId": self.operation_id,
            "summary": self.summary,
            "description": self.description,
            "parameters": [item.to_dict() for item in self.parameters],
            "responses": [item.to_dict() for item in self.responses],
            "securityPresent": self.security_present,
            "securitySource": self.security_source,
            "securityPointer": self.security_pointer,
            "security": [item.to_dict() for item in self.security],
            "policy": self.policy.to_dict(),
            "riskCategories": list(self.risk_categories),
            "riskSignals": [item.to_dict() for item in self.risk_signals],
            "state": self.state,
            "issues": [item.to_dict() for item in self.issues],
        }


@dataclass(frozen=True, slots=True)
class OperationSet:
    entrypoint: str
    manifest_digest: str
    dialect: str | None
    state: str
    operations: tuple[NormalizedOperation, ...]
    issues: tuple[NormalizationIssue, ...]
    schema_version: str = OPERATION_VIEW_SCHEMA_VERSION
    classifier_version: int = CLASSIFIER_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "schemaVersion": self.schema_version,
            "classifierVersion": self.classifier_version,
            "entrypoint": self.entrypoint,
            "manifestDigest": self.manifest_digest,
            "dialect": self.dialect,
            "state": self.state,
            "operations": [item.to_dict() for item in self.operations],
            "issues": [item.to_dict() for item in self.issues],
        }


@dataclass(frozen=True, slots=True)
class _Resolved:
    value: Any
    source: str
    pointer: str


class _ResolutionError(ValueError):
    def __init__(self, code: str, source: str, pointer: str, message: str) -> None:
        super().__init__(message)
        self.issue = NormalizationIssue(code, source, pointer, message)


def _escape_pointer(value: object) -> str:
    return str(value).replace("~", "~0").replace("/", "~1")


def _append_pointer(pointer: str, value: object) -> str:
    return f"{pointer}/{_escape_pointer(value)}"


def _parse_resource(path: str, content: bytes) -> Any:
    text = content.decode("utf-8", errors="strict")
    if path.lower().endswith(".json"):
        return json.loads(text)
    return yaml.safe_load(text)


class _DocumentStore:
    def __init__(self, closure: InputClosure) -> None:
        self.documents = {
            resource.path: _parse_resource(resource.path, resource.content)
            for resource in closure.resources
        }

    def resolve_mapping(
        self,
        value: Any,
        source: str,
        pointer: str,
        stack: tuple[tuple[str, str], ...] = (),
    ) -> _Resolved:
        if not isinstance(value, Mapping):
            raise _ResolutionError(
                "normalize.expected-object",
                source,
                pointer,
                "The value must be an object before it can be normalized.",
            )
        reference = value.get("$ref")
        if not isinstance(reference, str):
            return _Resolved(value, source, pointer)
        resolved = self.resolve_reference(reference, source, pointer)
        identity = (resolved.source, resolved.pointer)
        if identity in stack:
            raise _ResolutionError(
                "normalize.reference-cycle",
                source,
                _append_pointer(pointer, "$ref"),
                "The referenced object cycle cannot be normalized.",
            )
        target = self.resolve_mapping(
            resolved.value,
            resolved.source,
            resolved.pointer,
            stack + (identity,),
        )
        siblings = {key: item for key, item in value.items() if key != "$ref"}
        if not siblings:
            return target
        merged = dict(target.value)
        merged.update(siblings)
        return _Resolved(merged, target.source, target.pointer)

    def resolve_reference(self, reference: str, source: str, pointer: str) -> _Resolved:
        try:
            parsed = urlsplit(reference)
        except ValueError as error:
            raise _ResolutionError(
                "normalize.invalid-reference",
                source,
                _append_pointer(pointer, "$ref"),
                "The reference URI cannot be normalized.",
            ) from error
        if parsed.scheme or parsed.netloc or parsed.query:
            raise _ResolutionError(
                "normalize.external-reference",
                source,
                _append_pointer(pointer, "$ref"),
                "Only resources in the immutable input closure can be normalized.",
            )
        if parsed.path:
            try:
                decoded_path = unquote_to_bytes(parsed.path).decode("utf-8")
            except UnicodeDecodeError as error:
                raise _ResolutionError(
                    "normalize.invalid-reference",
                    source,
                    _append_pointer(pointer, "$ref"),
                    "The reference path is not valid UTF-8.",
                ) from error
            target_source = posixpath.normpath(
                posixpath.join(posixpath.dirname(source), decoded_path)
            )
        else:
            target_source = source
        if target_source not in self.documents:
            raise _ResolutionError(
                "normalize.missing-resource",
                source,
                _append_pointer(pointer, "$ref"),
                "The referenced resource is absent from the immutable input closure.",
            )
        try:
            fragment = unquote_to_bytes(parsed.fragment).decode("utf-8")
        except UnicodeDecodeError as error:
            raise _ResolutionError(
                "normalize.invalid-pointer",
                source,
                _append_pointer(pointer, "$ref"),
                "The reference fragment is not valid UTF-8.",
            ) from error
        target_pointer = fragment
        if target_pointer and not target_pointer.startswith("/"):
            raise _ResolutionError(
                "normalize.invalid-pointer",
                source,
                _append_pointer(pointer, "$ref"),
                "Only JSON Pointer reference fragments can be normalized.",
            )
        value = self.documents[target_source]
        if target_pointer:
            value = self._lookup_pointer(value, target_pointer, source, pointer)
        return _Resolved(value, target_source, target_pointer)

    def _lookup_pointer(
        self, value: Any, target: str, source: str, reference_pointer: str
    ) -> Any:
        for encoded in target[1:].split("/"):
            if _INVALID_POINTER_ESCAPE.search(encoded):
                raise _ResolutionError(
                    "normalize.invalid-pointer",
                    source,
                    _append_pointer(reference_pointer, "$ref"),
                    "The reference contains an invalid JSON Pointer escape.",
                )
            segment = encoded.replace("~1", "/").replace("~0", "~")
            if isinstance(value, Mapping) and segment in value:
                value = value[segment]
            elif isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
                if not segment.isdecimal() or int(segment) >= len(value):
                    raise _ResolutionError(
                        "normalize.missing-pointer",
                        source,
                        _append_pointer(reference_pointer, "$ref"),
                        "The referenced JSON Pointer does not exist.",
                    )
                value = value[int(segment)]
            else:
                raise _ResolutionError(
                    "normalize.missing-pointer",
                    source,
                    _append_pointer(reference_pointer, "$ref"),
                    "The referenced JSON Pointer does not exist.",
                )
        return value


def tokenize_risk_text(value: str) -> tuple[str, ...]:
    """Tokenize path or operationId text exactly as classifier v1 specifies."""

    tokens: list[str] = []
    current: list[str] = []
    previous: str | None = None
    for character in value:
        is_ascii_alphanumeric = character.isascii() and character.isalnum()
        boundary = not is_ascii_alphanumeric
        if not boundary and previous is not None:
            boundary = (
                previous.isascii() and previous.islower() and character.isupper()
            ) or (previous.isascii() and previous.isalpha() and character.isdigit())
        if boundary:
            if current:
                tokens.append("".join(current))
                current.clear()
            previous = None if not is_ascii_alphanumeric else character
            if not is_ascii_alphanumeric:
                continue
        current.append(character.lower())
        previous = character
    if current:
        tokens.append("".join(current))
    return tuple(tokens)


def _string_or_none(
    value: Any,
    *,
    source: str,
    pointer: str,
    field: str,
    issues: list[NormalizationIssue],
    issue_code: str = "normalize.invalid-field",
) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    issues.append(
        NormalizationIssue(
            issue_code,
            source,
            _append_pointer(pointer, field),
            f"{field} must be a string when present.",
        )
    )
    return None


def _normalize_parameters(
    store: _DocumentStore,
    path_item: Mapping[str, Any],
    path_source: str,
    path_pointer: str,
    operation: Mapping[str, Any],
    operation_source: str,
    operation_pointer: str,
) -> tuple[tuple[NormalizedParameter, ...], list[NormalizationIssue]]:
    issues: list[NormalizationIssue] = []
    effective: dict[tuple[str, str], NormalizedParameter] = {}
    groups = (
        (path_item.get("parameters", []), path_source, path_pointer),
        (operation.get("parameters", []), operation_source, operation_pointer),
    )
    for raw_parameters, source, parent_pointer in groups:
        parameters_pointer = _append_pointer(parent_pointer, "parameters")
        if not isinstance(raw_parameters, Sequence) or isinstance(
            raw_parameters, (str, bytes)
        ):
            issues.append(
                NormalizationIssue(
                    "normalize.invalid-parameters",
                    source,
                    parameters_pointer,
                    "Parameters must be an array.",
                )
            )
            continue
        for index, raw_parameter in enumerate(raw_parameters):
            item_pointer = _append_pointer(parameters_pointer, index)
            try:
                resolved = store.resolve_mapping(raw_parameter, source, item_pointer)
            except _ResolutionError as error:
                issues.append(error.issue)
                continue
            name = resolved.value.get("name")
            location = resolved.value.get("in")
            if not isinstance(name, str) or not isinstance(location, str):
                issues.append(
                    NormalizationIssue(
                        "normalize.invalid-parameter",
                        resolved.source,
                        resolved.pointer,
                        "A parameter requires string name and in fields.",
                    )
                )
                continue
            description = resolved.value.get("description")
            if description is not None and not isinstance(description, str):
                issues.append(
                    NormalizationIssue(
                        "normalize.invalid-parameter",
                        resolved.source,
                        _append_pointer(resolved.pointer, "description"),
                        "A parameter description must be a string.",
                    )
                )
                description = None
            required = resolved.value.get("required", False)
            if not isinstance(required, bool):
                issues.append(
                    NormalizationIssue(
                        "normalize.invalid-parameter",
                        resolved.source,
                        _append_pointer(resolved.pointer, "required"),
                        "A parameter required field must be boolean.",
                    )
                )
                required = False
            effective[(location, name)] = NormalizedParameter(
                source=resolved.source,
                pointer=resolved.pointer,
                name=name,
                location=location,
                required=required,
                description=description,
            )
    return tuple(effective[key] for key in sorted(effective)), issues


def _normalize_responses(
    store: _DocumentStore,
    operation: Mapping[str, Any],
    source: str,
    pointer: str,
) -> tuple[tuple[NormalizedResponse, ...], list[NormalizationIssue]]:
    issues: list[NormalizationIssue] = []
    responses_pointer = _append_pointer(pointer, "responses")
    if "responses" not in operation:
        return (), [
            NormalizationIssue(
                "normalize.missing-responses",
                source,
                responses_pointer,
                "An OpenAPI operation requires a responses object.",
            )
        ]
    raw_responses = operation["responses"]
    if not isinstance(raw_responses, Mapping):
        return (), [
            NormalizationIssue(
                "normalize.invalid-responses",
                source,
                responses_pointer,
                "Responses must be an object.",
            )
        ]
    responses: list[NormalizedResponse] = []
    for raw_status in sorted(raw_responses, key=str):
        status = str(raw_status)
        item_pointer = _append_pointer(responses_pointer, raw_status)
        try:
            resolved = store.resolve_mapping(
                raw_responses[raw_status], source, item_pointer
            )
        except _ResolutionError as error:
            issues.append(error.issue)
            continue
        description = resolved.value.get("description")
        if description is not None and not isinstance(description, str):
            issues.append(
                NormalizationIssue(
                    "normalize.invalid-response",
                    resolved.source,
                    _append_pointer(resolved.pointer, "description"),
                    "A response description must be a string.",
                )
            )
            description = None
        content = resolved.value.get("content", {})
        media_types: tuple[str, ...] = ()
        schema_media_types: tuple[str, ...] = ()
        if isinstance(content, Mapping):
            media_types = tuple(sorted(str(item) for item in content))
            schema_media_types = tuple(
                media_type
                for media_type in media_types
                if isinstance(content.get(media_type), Mapping)
                and "schema" in content[media_type]
            )
        else:
            issues.append(
                NormalizationIssue(
                    "normalize.invalid-response-content",
                    resolved.source,
                    _append_pointer(resolved.pointer, "content"),
                    "Response content must be an object.",
                )
            )
        responses.append(
            NormalizedResponse(
                source=resolved.source,
                pointer=resolved.pointer,
                status_code=status,
                description=description,
                media_types=media_types,
                schema_media_types=schema_media_types,
            )
        )
    return tuple(responses), issues


def _normalize_security(
    raw: Any,
    source: str,
    pointer: str,
) -> tuple[tuple[SecurityRequirement, ...], list[NormalizationIssue]]:
    if not isinstance(raw, Sequence) or isinstance(raw, (str, bytes)):
        return (), [
            NormalizationIssue(
                "normalize.invalid-security",
                source,
                pointer,
                "Security requirements must be an array.",
            )
        ]
    requirements: list[SecurityRequirement] = []
    issues: list[NormalizationIssue] = []
    for index, requirement in enumerate(raw):
        requirement_pointer = _append_pointer(pointer, index)
        if not isinstance(requirement, Mapping):
            issues.append(
                NormalizationIssue(
                    "normalize.invalid-security",
                    source,
                    requirement_pointer,
                    "A security requirement must be an object.",
                )
            )
            continue
        schemes: list[SecuritySchemeRequirement] = []
        for raw_name in sorted(requirement, key=str):
            name = str(raw_name)
            raw_scopes = requirement[raw_name]
            if (
                not isinstance(raw_scopes, Sequence)
                or isinstance(raw_scopes, (str, bytes))
                or not all(isinstance(item, str) for item in raw_scopes)
            ):
                issues.append(
                    NormalizationIssue(
                        "normalize.invalid-security",
                        source,
                        _append_pointer(requirement_pointer, raw_name),
                        "Security scopes must be an array of strings.",
                    )
                )
                continue
            schemes.append(
                SecuritySchemeRequirement(
                    name=name, scopes=tuple(sorted(set(raw_scopes)))
                )
            )
        requirements.append(SecurityRequirement(schemes=tuple(schemes)))
    return tuple(requirements), issues


def _normalize_policy(
    operation: Mapping[str, Any], source: str, pointer: str
) -> tuple[AgentPolicy, tuple[RiskSignal, ...], list[NormalizationIssue]]:
    policy_pointer = _append_pointer(pointer, "x-agent-policy")
    if "x-agent-policy" not in operation:
        return (
            AgentPolicy(
                False,
                True,
                source,
                policy_pointer,
                (),
                False,
                None,
                None,
                None,
                False,
                (),
                False,
                None,
            ),
            (),
            [],
        )
    raw_policy = operation["x-agent-policy"]
    if not isinstance(raw_policy, Mapping):
        return (
            AgentPolicy(
                True,
                False,
                source,
                policy_pointer,
                (),
                False,
                None,
                None,
                None,
                False,
                (),
                False,
                None,
            ),
            (),
            [
                NormalizationIssue(
                    "normalize.invalid-agent-policy",
                    source,
                    policy_pointer,
                    "x-agent-policy must be an object.",
                )
            ],
        )

    issues: list[NormalizationIssue] = []
    allowed_policy_fields = {
        "risks",
        "confirmation",
        "authorization",
        "dataClassification",
    }
    for field in raw_policy:
        if field not in allowed_policy_fields and not (
            isinstance(field, str) and _EXTENSION_KEY.fullmatch(field)
        ):
            issues.append(
                NormalizationIssue(
                    "normalize.invalid-agent-policy",
                    source,
                    _append_pointer(policy_pointer, field),
                    "The policy contains an unsupported field.",
                )
            )
    explicit: list[str] = []
    signals: list[RiskSignal] = []
    risks_present = "risks" in raw_policy
    raw_risks = raw_policy.get("risks", [])
    risks_pointer = _append_pointer(policy_pointer, "risks")
    if not isinstance(raw_risks, Sequence) or isinstance(raw_risks, (str, bytes)):
        issues.append(
            NormalizationIssue(
                "normalize.invalid-agent-policy",
                source,
                risks_pointer,
                "Policy risks must be an array.",
            )
        )
    else:
        if risks_present and not raw_risks:
            issues.append(
                NormalizationIssue(
                    "normalize.invalid-agent-policy",
                    source,
                    risks_pointer,
                    "Policy risks must contain at least one category.",
                )
            )
        seen_risks: set[str] = set()
        for index, risk in enumerate(raw_risks):
            item_pointer = _append_pointer(risks_pointer, index)
            if risk not in RISK_CATEGORIES:
                issues.append(
                    NormalizationIssue(
                        "normalize.invalid-agent-policy",
                        source,
                        item_pointer,
                        "Policy risks must use the classifier v1 vocabulary.",
                    )
                )
                continue
            if risk in seen_risks:
                issues.append(
                    NormalizationIssue(
                        "normalize.invalid-agent-policy",
                        source,
                        item_pointer,
                        "Policy risks must be unique.",
                    )
                )
            seen_risks.add(risk)
            explicit.append(risk)
            signals.append(RiskSignal(risk, "extension", item_pointer, risk, source))

    confirmation_mode: str | None = None
    confirmation_condition: str | None = None
    confirmation_reason: str | None = None
    raw_confirmation = raw_policy.get("confirmation")
    confirmation_present = "confirmation" in raw_policy
    if raw_confirmation is not None:
        confirmation_pointer = _append_pointer(policy_pointer, "confirmation")
        if not isinstance(raw_confirmation, Mapping):
            issues.append(
                NormalizationIssue(
                    "normalize.invalid-agent-policy",
                    source,
                    confirmation_pointer,
                    "Policy confirmation must be an object.",
                )
            )
        else:
            allowed_confirmation_fields = {"mode", "condition", "reason"}
            for field in raw_confirmation:
                if field not in allowed_confirmation_fields and not (
                    isinstance(field, str) and _EXTENSION_KEY.fullmatch(field)
                ):
                    issues.append(
                        NormalizationIssue(
                            "normalize.invalid-agent-policy",
                            source,
                            _append_pointer(confirmation_pointer, field),
                            "Policy confirmation contains an unsupported field.",
                        )
                    )
            confirmation_mode = _string_or_none(
                raw_confirmation.get("mode"),
                source=source,
                pointer=confirmation_pointer,
                field="mode",
                issues=issues,
                issue_code="normalize.invalid-agent-policy",
            )
            if confirmation_mode not in {"required", "conditional", "not-required"}:
                issues.append(
                    NormalizationIssue(
                        "normalize.invalid-agent-policy",
                        source,
                        _append_pointer(confirmation_pointer, "mode"),
                        "Policy confirmation requires a supported mode.",
                    )
                )
            confirmation_condition = _string_or_none(
                raw_confirmation.get("condition"),
                source=source,
                pointer=confirmation_pointer,
                field="condition",
                issues=issues,
                issue_code="normalize.invalid-agent-policy",
            )
            if confirmation_condition is not None and not confirmation_condition.strip(
                " \t\r\n"
            ):
                issues.append(
                    NormalizationIssue(
                        "normalize.invalid-agent-policy",
                        source,
                        _append_pointer(confirmation_pointer, "condition"),
                        "Policy confirmation condition must be non-empty.",
                    )
                )
            confirmation_reason = _string_or_none(
                raw_confirmation.get("reason"),
                source=source,
                pointer=confirmation_pointer,
                field="reason",
                issues=issues,
                issue_code="normalize.invalid-agent-policy",
            )
            if confirmation_reason is not None and not confirmation_reason.strip(
                " \t\r\n"
            ):
                issues.append(
                    NormalizationIssue(
                        "normalize.invalid-agent-policy",
                        source,
                        _append_pointer(confirmation_pointer, "reason"),
                        "Policy confirmation reason must be non-empty.",
                    )
                )
            if confirmation_mode == "conditional" and not (
                confirmation_condition
                and confirmation_condition.strip(" \t\r\n")
            ):
                issues.append(
                    NormalizationIssue(
                        "normalize.invalid-agent-policy",
                        source,
                        _append_pointer(confirmation_pointer, "condition"),
                        "Conditional confirmation requires a non-empty condition.",
                    )
                )
            if confirmation_mode == "not-required" and not (
                confirmation_reason and confirmation_reason.strip(" \t\r\n")
            ):
                issues.append(
                    NormalizationIssue(
                        "normalize.invalid-agent-policy",
                        source,
                        _append_pointer(confirmation_pointer, "reason"),
                        "Not-required confirmation requires a non-empty reason.",
                    )
                )

    authorization_roles: tuple[str, ...] = ()
    raw_authorization = raw_policy.get("authorization")
    authorization_present = "authorization" in raw_policy
    if raw_authorization is not None:
        authorization_pointer = _append_pointer(policy_pointer, "authorization")
        if not isinstance(raw_authorization, Mapping):
            issues.append(
                NormalizationIssue(
                    "normalize.invalid-agent-policy",
                    source,
                    authorization_pointer,
                    "Policy authorization must be an object.",
                )
            )
        else:
            allowed_authorization_fields = {"roles"}
            for field in raw_authorization:
                if field not in allowed_authorization_fields and not (
                    isinstance(field, str) and _EXTENSION_KEY.fullmatch(field)
                ):
                    issues.append(
                        NormalizationIssue(
                            "normalize.invalid-agent-policy",
                            source,
                            _append_pointer(authorization_pointer, field),
                            "Policy authorization contains an unsupported field.",
                        )
                    )
            raw_roles = raw_authorization.get("roles", [])
            if (
                not isinstance(raw_roles, Sequence)
                or isinstance(raw_roles, (str, bytes))
                or not all(isinstance(item, str) for item in raw_roles)
            ):
                issues.append(
                    NormalizationIssue(
                        "normalize.invalid-agent-policy",
                        source,
                        _append_pointer(authorization_pointer, "roles"),
                        "Policy authorization roles must be an array of strings.",
                    )
                )
            else:
                authorization_roles = tuple(sorted(set(raw_roles)))
                if (
                    not raw_roles
                    or len(authorization_roles) != len(raw_roles)
                    or any(not item.strip(" \t\r\n") for item in raw_roles)
                ):
                    issues.append(
                        NormalizationIssue(
                            "normalize.invalid-agent-policy",
                            source,
                            _append_pointer(authorization_pointer, "roles"),
                            (
                                "Policy authorization roles must be unique "
                                "non-empty strings."
                            ),
                        )
                    )

    data_classification_present = "dataClassification" in raw_policy
    data_classification = _string_or_none(
        raw_policy.get("dataClassification"),
        source=source,
        pointer=policy_pointer,
        field="dataClassification",
        issues=issues,
        issue_code="normalize.invalid-agent-policy",
    )
    if data_classification is not None and data_classification not in {
        "public",
        "internal",
        "confidential",
        "restricted",
    }:
        issues.append(
            NormalizationIssue(
                "normalize.invalid-agent-policy",
                source,
                _append_pointer(policy_pointer, "dataClassification"),
                "Policy dataClassification is outside the v1 vocabulary.",
            )
        )
    policy = AgentPolicy(
        True,
        not issues,
        source,
        policy_pointer,
        tuple(sorted(set(explicit))),
        confirmation_present,
        confirmation_mode,
        confirmation_condition,
        confirmation_reason,
        authorization_present,
        authorization_roles,
        data_classification_present,
        data_classification,
    )
    return policy, tuple(signals), issues


def _classify_risks(
    *,
    path: str,
    method: str,
    operation_id: str | None,
    path_source: str,
    path_pointer: str,
    operation_source: str,
    operation_pointer: str,
    explicit_signals: tuple[RiskSignal, ...],
) -> tuple[tuple[str, ...], tuple[RiskSignal, ...]]:
    signals = list(explicit_signals)
    for category in METHOD_CATEGORIES.get(method, ()):
        signals.append(
            RiskSignal(category, "method", operation_pointer, method, operation_source)
        )

    token_sources = (
        (tokenize_risk_text(path), "path", path_pointer, path_source),
        (
            tokenize_risk_text(operation_id) if operation_id else (),
            "keyword",
            _append_pointer(operation_pointer, "operationId"),
            operation_source,
        ),
    )
    categories = dict(ALL_METHOD_TOKEN_CATEGORIES)
    if method in STATE_CHANGING_METHODS:
        categories.update(STATE_CHANGING_TOKEN_CATEGORIES)
    for tokens, kind, pointer, source in token_sources:
        for token in tokens:
            for category, vocabulary in categories.items():
                if token in vocabulary:
                    signals.append(RiskSignal(category, kind, pointer, token, source))

    unique = {
        (item.kind, item.pointer, item.value, item.category, item.source): item
        for item in signals
    }
    ordered = tuple(unique[key] for key in sorted(unique))
    risk_categories = tuple(sorted({item.category for item in ordered}))
    return risk_categories, ordered


def _normalize_operation(
    *,
    store: _DocumentStore,
    root: Mapping[str, Any],
    entrypoint: str,
    path: str,
    path_pointer: str,
    path_item: _Resolved,
    method: str,
    operation_value: Any,
) -> NormalizedOperation:
    operation_pointer = _append_pointer(path_item.pointer, method)
    issues: list[NormalizationIssue] = []
    if not isinstance(operation_value, Mapping):
        issues.append(
            NormalizationIssue(
                "normalize.invalid-operation",
                path_item.source,
                operation_pointer,
                "An OpenAPI operation must be an object.",
            )
        )
        operation: Mapping[str, Any] = {}
    else:
        operation = operation_value

    operation_id = _string_or_none(
        operation.get("operationId"),
        source=path_item.source,
        pointer=operation_pointer,
        field="operationId",
        issues=issues,
    )
    summary = _string_or_none(
        operation.get("summary"),
        source=path_item.source,
        pointer=operation_pointer,
        field="summary",
        issues=issues,
    )
    description = _string_or_none(
        operation.get("description"),
        source=path_item.source,
        pointer=operation_pointer,
        field="description",
        issues=issues,
    )
    parameters, parameter_issues = _normalize_parameters(
        store,
        path_item.value,
        path_item.source,
        path_item.pointer,
        operation,
        path_item.source,
        operation_pointer,
    )
    issues.extend(parameter_issues)
    responses, response_issues = _normalize_responses(
        store, operation, path_item.source, operation_pointer
    )
    issues.extend(response_issues)

    if "security" in operation:
        security_present = True
        security_source = path_item.source
        security_pointer = _append_pointer(operation_pointer, "security")
        raw_security = operation["security"]
    elif "security" in root:
        security_present = True
        security_source = entrypoint
        security_pointer = "/security"
        raw_security = root["security"]
    else:
        security_present = False
        security_source = None
        security_pointer = None
        raw_security = []
    if security_present:
        assert security_source is not None and security_pointer is not None
        security, security_issues = _normalize_security(
            raw_security, security_source, security_pointer
        )
        issues.extend(security_issues)
    else:
        security = ()

    policy, explicit_signals, policy_issues = _normalize_policy(
        operation, path_item.source, operation_pointer
    )
    issues.extend(policy_issues)
    risk_categories, risk_signals = _classify_risks(
        path=path,
        method=method,
        operation_id=operation_id,
        path_source=entrypoint,
        path_pointer=path_pointer,
        operation_source=path_item.source,
        operation_pointer=operation_pointer,
        explicit_signals=explicit_signals,
    )
    ordered_issues = tuple(
        sorted(
            issues,
            key=lambda item: (item.source, item.pointer, item.code, item.message),
        )
    )
    return NormalizedOperation(
        source=path_item.source,
        pointer=operation_pointer,
        path_source=entrypoint,
        path_pointer=path_pointer,
        path=path,
        method=method,
        operation_id=operation_id,
        summary=summary,
        description=description,
        parameters=parameters,
        responses=responses,
        security_present=security_present,
        security_source=security_source,
        security_pointer=security_pointer,
        security=security,
        policy=policy,
        risk_categories=risk_categories,
        risk_signals=risk_signals,
        state=(
            "ready"
            if all(
                item.code == "normalize.invalid-agent-policy"
                for item in ordered_issues
            )
            else "indeterminate"
        ),
        issues=ordered_issues,
    )


def normalize_operations(
    closure: InputClosure, entrypoint: str | None = None
) -> OperationSet:
    """Create canonical operation views from one immutable input closure."""

    if entrypoint is None:
        if len(closure.manifest.entrypoints) != 1:
            raise ValueError("entrypoint is required for a multi-entrypoint closure")
        entrypoint = closure.manifest.entrypoints[0]
    if entrypoint not in closure.manifest.entrypoints:
        raise ValueError("entrypoint must be declared by the input manifest")

    store = _DocumentStore(closure)
    root = store.documents[entrypoint]
    issues: list[NormalizationIssue] = []
    if not isinstance(root, Mapping):
        issues.append(
            NormalizationIssue(
                "normalize.invalid-document",
                entrypoint,
                "",
                "An OpenAPI document must be an object.",
            )
        )
        root = {}
    version = root.get("openapi")
    dialect: str | None
    if isinstance(version, str) and version.startswith("3.0."):
        dialect = "3.0"
    elif isinstance(version, str) and version.startswith("3.1."):
        dialect = "3.1"
    else:
        dialect = None
        issues.append(
            NormalizationIssue(
                "normalize.unsupported-dialect",
                entrypoint,
                "/openapi",
                "Only OpenAPI 3.0 and 3.1 operations can be normalized.",
            )
        )

    raw_paths = root.get("paths", {})
    operations: list[NormalizedOperation] = []
    if not isinstance(raw_paths, Mapping):
        issues.append(
            NormalizationIssue(
                "normalize.invalid-paths",
                entrypoint,
                "/paths",
                "OpenAPI paths must be an object.",
            )
        )
    else:
        for raw_path in sorted(raw_paths, key=str):
            path = str(raw_path)
            if not path.startswith("/"):
                continue
            path_pointer = _append_pointer("/paths", raw_path)
            try:
                path_item = store.resolve_mapping(
                    raw_paths[raw_path], entrypoint, path_pointer
                )
            except _ResolutionError as error:
                issues.append(error.issue)
                continue
            for method in sorted(
                key for key in path_item.value if str(key).lower() in HTTP_METHODS
            ):
                normalized_method = str(method).lower()
                operations.append(
                    _normalize_operation(
                        store=store,
                        root=root,
                        entrypoint=entrypoint,
                        path=path,
                        path_pointer=path_pointer,
                        path_item=path_item,
                        method=normalized_method,
                        operation_value=path_item.value[method],
                    )
                )

    ordered_operations = tuple(
        sorted(
            operations,
            key=lambda item: (item.path, item.method, item.source, item.pointer),
        )
    )
    ordered_issues = tuple(
        sorted(
            issues,
            key=lambda item: (item.source, item.pointer, item.code, item.message),
        )
    )
    return OperationSet(
        entrypoint=entrypoint,
        manifest_digest=closure.manifest.digest,
        dialect=dialect,
        state=(
            "ready"
            if not ordered_issues
            and all(item.state == "ready" for item in ordered_operations)
            else "indeterminate"
        ),
        operations=ordered_operations,
        issues=ordered_issues,
    )
