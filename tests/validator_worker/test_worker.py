from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest
from proof_core import WorkerLimits, build_input_closure
from proof_core.validator_client import _build_request
from proof_validator_worker import (
    ProtocolError,
    ValidationRequest,
    parse_request,
    validate_request,
)
from proof_validator_worker.protocol import Resource
from proof_validator_worker.validation import ClosedMemoryHandlers, NoSuchResource


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8", newline="\n")


def _valid_document(version: str = "3.1.0") -> str:
    return f"""openapi: {version}
info:
  title: Pets
  version: 1.0.0
paths: {{}}
"""


def _request(root: Path, entrypoint: str = "root.yaml", *, maximum: int = 100):
    closure = build_input_closure(root, entrypoint)
    raw = _build_request(
        closure,
        entrypoint,
        WorkerLimits(max_diagnostics=maximum),
    )
    return closure, raw, parse_request(raw)


@pytest.mark.parametrize("version", ["3.0.4", "3.1.2"])
def test_validates_supported_openapi_versions(tmp_path: Path, version: str) -> None:
    _write(tmp_path / "root.yaml", _valid_document(version))
    _closure, _raw, request = _request(tmp_path)

    result = validate_request(request)

    assert result.outcome == "valid"
    assert result.diagnostics == ()
    assert result.diagnostics_observed == 0


def test_reports_diagnostic_in_defining_reference_file(tmp_path: Path) -> None:
    _write(
        tmp_path / "root.yaml",
        """openapi: 3.1.0
info:
  title: Pets
  version: 1.0.0
paths:
  /pets:
    get:
      responses:
        '200':
          description: ok
          content:
            application/json:
              schema:
                $ref: components.yaml#/components/schemas/Pet
""",
    )
    _write(
        tmp_path / "components.yaml",
        """components:
  schemas:
    Pet:
      type: impossible
""",
    )
    _closure, _raw, request = _request(tmp_path)

    result = validate_request(request)

    assert result.outcome == "invalid"
    assert any(item.source == "components.yaml" for item in result.diagnostics)
    assert all(item.line and item.column for item in result.diagnostics)


def test_validation_uses_bytes_after_repository_file_is_removed(tmp_path: Path) -> None:
    source = tmp_path / "root.yaml"
    _write(source, _valid_document())
    _closure, _raw, request = _request(tmp_path)
    source.unlink()

    assert validate_request(request).outcome == "valid"


def test_diagnostics_are_deterministic_and_bounded(tmp_path: Path) -> None:
    operations = "\n".join(
        f"  /p{index:02d}:\n    get:\n      responses: []"
        for index in range(8)
    )
    _write(
        tmp_path / "root.yaml",
        f"""openapi: 3.1.0
info:
  title: Flood
  version: 1.0.0
paths:
{operations}
""",
    )
    _closure, _raw, request = _request(tmp_path, maximum=3)

    results = [validate_request(request) for _ in range(3)]
    serializations = [
        json.dumps(item.to_dict(), sort_keys=True, separators=(",", ":"))
        for item in results
    ]

    assert len(set(serializations)) == 1
    assert results[0].outcome == "limit-exceeded"
    assert len(results[0].diagnostics) == 3
    assert results[0].diagnostics_truncated == 5


def test_known_post_schema_exception_keeps_structural_finding(tmp_path: Path) -> None:
    _write(
        tmp_path / "root.yaml",
        """openapi: 3.1.0
info:
  title: Exception regression
  version: 1.0.0
paths:
  /pets:
    get:
      responses: []
""",
    )
    _closure, _raw, request = _request(tmp_path)

    result = validate_request(request)

    assert result.outcome == "invalid"
    assert any(
        item.pointer == "/paths/~1pets/get/responses"
        for item in result.diagnostics
    )


def test_request_rejects_resource_identity_tampering(tmp_path: Path) -> None:
    _write(tmp_path / "root.yaml", _valid_document())
    _closure, raw, _request_value = _request(tmp_path)
    value = json.loads(raw)
    value["resources"][0]["content"] = "e30="

    with pytest.raises(ProtocolError, match="resource bytes"):
        parse_request(json.dumps(value).encode())


def test_request_rejects_duplicate_json_keys() -> None:
    with pytest.raises(ProtocolError, match="strict JSON"):
        parse_request(b'{"protocolVersion":1,"protocolVersion":1}')


def test_closed_handlers_claim_every_scheme_without_fallback() -> None:
    handlers = ClosedMemoryHandlers({})
    for scheme in ("", "file", "http", "https", "unknown"):
        assert scheme in handlers
        with pytest.raises(NoSuchResource):
            handlers[scheme](f"{scheme}://not-allowed.invalid/schema")


def test_remote_reference_is_denied_before_validator_resolution() -> None:
    content = b"""openapi: 3.1.0
info:
  title: Remote
  version: 1.0.0
paths:
  /pets:
    get:
      responses:
        '200':
          description: ok
          content:
            application/json:
              schema:
                $ref: https://example.invalid/schema.json
"""
    request = ValidationRequest(
        entrypoint="root.yaml",
        manifest_digest="sha256:" + "0" * 64,
        resources=(
            Resource(
                path="root.yaml",
                content=content,
                digest=f"sha256:{hashlib.sha256(content).hexdigest()}",
            ),
        ),
        max_diagnostics=100,
    )

    result = validate_request(request)

    assert result.outcome == "invalid"
    assert result.diagnostics[0].code == "ref.scheme-denied"


def test_process_contract_failure_is_one_json_line_and_nonzero() -> None:
    completed = subprocess.run(
        [sys.executable, "-I", "-m", "proof_validator_worker"],
        input=b"{}",
        capture_output=True,
        check=False,
        timeout=15,
    )

    assert completed.returncode == 2
    assert len(completed.stdout.splitlines()) == 1
    assert json.loads(completed.stdout)["outcome"] == "internal-error"


def test_alias_expansion_is_bounded_before_validation() -> None:
    aliases = ["  a0: &a0 [x, x]"]
    aliases.extend(
        f"  a{index}: &a{index} [*a{index - 1}, *a{index - 1}]"
        for index in range(1, 18)
    )
    aliases.append("  root: *a17")
    content = (
        "openapi: 3.1.0\n"
        "info:\n"
        "  title: Alias bound\n"
        "  version: 1.0.0\n"
        "paths: {}\n"
        "x-bomb:\n"
        + "\n".join(aliases)
        + "\n"
    ).encode()
    request = ValidationRequest(
        entrypoint="root.yaml",
        manifest_digest="sha256:" + "0" * 64,
        resources=(
            Resource(
                path="root.yaml",
                content=content,
                digest=f"sha256:{hashlib.sha256(content).hexdigest()}",
            ),
        ),
        max_diagnostics=100,
    )

    result = validate_request(request)

    assert result.outcome == "invalid"
    assert result.diagnostics[0].code == "parse.alias-expansion-limit"
