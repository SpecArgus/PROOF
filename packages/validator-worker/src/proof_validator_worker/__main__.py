"""Standard-input/standard-output entry point for the validator worker."""

from __future__ import annotations

import sys

from proof_validator_worker.protocol import (
    MAX_REQUEST_BYTES,
    PROTOCOL_VERSION,
    WORKER_NAME,
    WORKER_VERSION,
    ProtocolError,
    compact_json,
    parse_request,
)
from proof_validator_worker.validation import validate_request


def _failure(code: str, message: str) -> dict[str, object]:
    return {
        "protocolVersion": PROTOCOL_VERSION,
        "worker": {"name": WORKER_NAME, "version": WORKER_VERSION},
        "outcome": "internal-error",
        "error": {"code": code, "kind": "protocol", "message": message},
    }


def main() -> int:
    raw = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
    try:
        request = parse_request(raw)
        response = validate_request(request)
    except ProtocolError:
        sys.stdout.buffer.write(
            compact_json(
                _failure("worker.invalid-request", "The worker request is invalid.")
            )
        )
        return 2
    except Exception:
        sys.stdout.buffer.write(
            compact_json(
                _failure(
                    "worker.internal",
                    "The validator worker failed before producing a result.",
                )
            )
        )
        return 2

    sys.stdout.buffer.write(compact_json(response.to_dict()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
