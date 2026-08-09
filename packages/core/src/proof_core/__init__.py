"""Deterministic analysis primitives shared by PROOF execution surfaces."""

from proof_core.input_closure import (
    InputClosure,
    InputClosureError,
    InputFile,
    InputLimits,
    InputManifest,
    InputResource,
    build_input_closure,
    build_input_manifest,
)
from proof_core.operation_normalization import (
    CLASSIFIER_VERSION,
    OPERATION_VIEW_SCHEMA_VERSION,
    AgentPolicy,
    NormalizationIssue,
    NormalizedOperation,
    NormalizedParameter,
    NormalizedResponse,
    OperationSet,
    RiskSignal,
    SecurityRequirement,
    SecuritySchemeRequirement,
    normalize_operations,
    tokenize_risk_text,
)
from proof_core.validator_client import (
    ValidatorDiagnostic,
    ValidatorResult,
    WorkerFailure,
    WorkerLimits,
    validate_openapi,
)

__all__ = [
    "InputClosure",
    "InputClosureError",
    "InputFile",
    "InputLimits",
    "InputManifest",
    "InputResource",
    "build_input_closure",
    "build_input_manifest",
    "ValidatorDiagnostic",
    "ValidatorResult",
    "WorkerFailure",
    "WorkerLimits",
    "validate_openapi",
    "CLASSIFIER_VERSION",
    "OPERATION_VIEW_SCHEMA_VERSION",
    "AgentPolicy",
    "NormalizationIssue",
    "NormalizedOperation",
    "NormalizedParameter",
    "NormalizedResponse",
    "OperationSet",
    "RiskSignal",
    "SecurityRequirement",
    "SecuritySchemeRequirement",
    "normalize_operations",
    "tokenize_risk_text",
]

__version__ = "0.1.0"
