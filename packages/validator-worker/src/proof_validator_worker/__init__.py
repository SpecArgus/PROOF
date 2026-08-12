"""Versioned, closure-only OpenAPI validator worker."""

from proof_validator_worker.protocol import (
    Diagnostic,
    ProtocolError,
    ValidationRequest,
    ValidationResponse,
    parse_request,
)
from proof_validator_worker.validation import validate_request

__all__ = [
    "Diagnostic",
    "ProtocolError",
    "ValidationRequest",
    "ValidationResponse",
    "parse_request",
    "validate_request",
]

__version__ = "0.1.0"
