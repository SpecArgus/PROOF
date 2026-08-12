"""RFC 8785 canonical JSON and content identity helpers."""

from __future__ import annotations

import hashlib
from typing import Any

import rfc8785


class CanonicalJsonError(ValueError):
    """A value cannot be represented by the shared canonical JSON contract."""


def canonical_json_bytes(value: Any) -> bytes:
    """Return RFC 8785 bytes or a stable public error."""

    try:
        return rfc8785.dumps(value)
    except (TypeError, ValueError) as error:
        raise CanonicalJsonError(
            "value cannot be represented as canonical JSON"
        ) from error


def content_digest(value: Any) -> str:
    """Return the lowercase SHA-256 identity of an RFC 8785 value."""

    return f"sha256:{hashlib.sha256(canonical_json_bytes(value)).hexdigest()}"
