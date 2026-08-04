from __future__ import annotations

import json
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from proof_core import build_input_closure, normalize_operations, tokenize_risk_text
from proof_core import operation_normalization as normalization

FIXTURE_ROOT = Path("rulepacks/agent-contract/v1/fixtures")
CLASSIFIER_PATH = Path("rulepacks/agent-contract/v1/risk-classification.json")
OPERATION_SCHEMA_PATH = Path(
    "packages/contracts/src/proof_contracts/schemas/operation/v1/"
    "operation-set.schema.json"
)


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8", newline="\n")


def _normalize_fixture(relative: str):
    fixture = FIXTURE_ROOT / relative
    closure = build_input_closure(fixture.parent, fixture.name)
    return normalize_operations(closure)


def _operation(result, pointer: str):
    return next(item for item in result.operations if item.pointer == pointer)


def test_classifier_constants_match_machine_readable_rulepack() -> None:
    vocabulary = json.loads(CLASSIFIER_PATH.read_text(encoding="utf-8"))

    assert vocabulary["classifierVersion"] == normalization.CLASSIFIER_VERSION
    assert (
        set(vocabulary["stateChangingMethods"]) == normalization.STATE_CHANGING_METHODS
    )
    assert {
        key: tuple(value) for key, value in vocabulary["methodCategories"].items()
    } == normalization.METHOD_CATEGORIES
    assert {
        key: frozenset(value)
        for key, value in vocabulary["stateChangingTokenCategories"].items()
    } == normalization.STATE_CHANGING_TOKEN_CATEGORIES
    assert {
        key: frozenset(value)
        for key, value in vocabulary["allMethodTokenCategories"].items()
    } == normalization.ALL_METHOD_TOKEN_CATEGORIES


def test_fixture_views_validate_against_language_neutral_contract() -> None:
    schema = json.loads(OPERATION_SCHEMA_PATH.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)

    for fixture in sorted(FIXTURE_ROOT.glob("oas*/*.json")):
        result = _normalize_fixture(fixture.relative_to(FIXTURE_ROOT).as_posix())
        validator.validate(result.to_dict())


def test_all_twenty_issue_10_cases_have_expected_classifier_output() -> None:
    manifest = json.loads((FIXTURE_ROOT / "manifest.json").read_text(encoding="utf-8"))
    expected = {
        "ctx-positive-oas30": (),
        "ctx-negative-oas30": (),
        "ctx-boundary-oas31": (),
        "ctx-false-positive-oas31": (),
        "param-positive-oas30": (),
        "param-negative-oas30": (),
        "param-boundary-oas31": (),
        "param-false-positive-oas31": (),
        "resp-positive-oas30": ("external_side_effect",),
        "resp-negative-oas30": (),
        "resp-boundary-oas31": ("destructive",),
        "resp-false-positive-oas31": ("sensitive_data",),
        "pol1-positive-oas30": ("destructive",),
        "pol1-negative-oas30": ("financial_action",),
        "pol1-boundary-oas31": ("destructive",),
        "pol1-false-positive-oas31": (),
        "pol2-positive-oas30": ("sensitive_data",),
        "pol2-negative-oas30": ("permission_change",),
        "pol2-boundary-oas31": ("sensitive_data",),
        "pol2-false-positive-oas31": (),
    }
    results = {
        fixture: _normalize_fixture(fixture)
        for fixture in sorted({item["fixture"] for item in manifest["cases"]})
    }

    assert len(manifest["cases"]) == 20
    for case in manifest["cases"]:
        result = results[case["fixture"]]
        assert result.state == "ready", case["caseId"]
        operation = _operation(result, case["operationPointer"])
        assert operation.state == "ready", case["caseId"]
        assert operation.risk_categories == expected[case["caseId"]]
        assert result.dialect == ("3.0" if case["dialect"] == "3.0.x" else "3.1")


def test_fixture_risk_evidence_preserves_every_classifier_signal() -> None:
    delete = _operation(
        _normalize_fixture("oas30/agt-pol-001.json"),
        "/paths/~1users~1{userId}/delete",
    )
    assert [(item.kind, item.value, item.category) for item in delete.risk_signals] == [
        ("extension", "destructive", "destructive"),
        ("keyword", "delete", "destructive"),
        ("method", "delete", "destructive"),
    ]

    refund = _operation(
        _normalize_fixture("oas30/agt-pol-001.json"),
        "/paths/~1payments~1{paymentId}~1refund/post",
    )
    assert [(item.kind, item.value) for item in refund.risk_signals] == [
        ("keyword", "payment"),
        ("keyword", "refund"),
        ("path", "payment"),
        ("path", "payments"),
        ("path", "refund"),
    ]

    credential = _operation(
        _normalize_fixture("oas31/agt-pol-002.json"),
        "/paths/~1credentials~1{credentialId}/get",
    )
    assert [(item.kind, item.value) for item in credential.risk_signals] == [
        ("path", "credential"),
        ("path", "credentials"),
    ]


@pytest.mark.parametrize(
    "value,expected",
    [
        ("refundPayment", ("refund", "payment")),
        ("sendSMS2FA.profile-é", ("send", "sms", "2fa", "profile")),
        ("deleteable", ("deleteable",)),
        ("/users/{userId}/roles", ("users", "user", "id", "roles")),
    ],
)
def test_classifier_v1_ascii_tokenization(
    value: str, expected: tuple[str, ...]
) -> None:
    assert tokenize_risk_text(value) == expected


def test_explicit_risks_add_without_suppressing_inference(tmp_path: Path) -> None:
    _write(
        tmp_path / "root.yaml",
        """openapi: 3.1.0
info: {title: Test, version: 1.0.0}
paths:
  /deleteable:
    post:
      operationId: process
      description: delete transfer password words are ignored
      x-agent-policy:
        risks: [sensitive_data]
      responses:
        '200': {description: ok}
  /items/{id}:
    delete:
      operationId: removeItem
      x-agent-policy:
        risks: [sensitive_data, destructive]
      responses:
        '204': {description: removed}
""",
    )

    result = normalize_operations(build_input_closure(tmp_path, "root.yaml"))
    first, second = result.operations

    assert first.path == "/deleteable"
    assert first.risk_categories == ("sensitive_data",)
    assert second.risk_categories == ("destructive", "sensitive_data")
    assert [(item.kind, item.value) for item in second.risk_signals] == [
        ("extension", "sensitive_data"),
        ("extension", "destructive"),
        ("keyword", "remove"),
        ("method", "delete"),
    ]


def test_effective_parameters_override_path_item_by_name_and_location(
    tmp_path: Path,
) -> None:
    _write(
        tmp_path / "root.yaml",
        """openapi: 3.0.3
info: {title: Test, version: 1.0.0}
paths:
  /items/{id}:
    parameters:
      - name: id
        in: path
        required: true
        description: path description
        schema: {type: string}
    get:
      operationId: getItem
      parameters:
        - name: id
          in: path
          required: true
          description: operation override
          schema: {type: string}
        - {name: q, in: query, description: query description, schema: {type: string}}
      responses:
        '200': {description: ok}
""",
    )

    operation = normalize_operations(
        build_input_closure(tmp_path, "root.yaml")
    ).operations[0]

    assert [(item.location, item.name) for item in operation.parameters] == [
        ("path", "id"),
        ("query", "q"),
    ]
    assert operation.parameters[0].description == "operation override"
    assert operation.parameters[0].pointer.endswith("/get/parameters/0")


def test_responses_and_effective_security_are_normalized(tmp_path: Path) -> None:
    _write(
        tmp_path / "root.yaml",
        """openapi: 3.1.0
info: {title: Test, version: 1.0.0}
security:
  - oauth: [write, read, write]
paths:
  /inherited:
    get:
      operationId: getInherited
      responses:
        default:
          description: error
          content:
            application/problem+json: {schema: {type: object}}
            text/plain: {schema: {type: string}}
            application/json: {schema: {type: object}}
  /public:
    get:
      operationId: getPublic
      security: []
      responses:
        '204': {description: none}
""",
    )

    inherited, public = normalize_operations(
        build_input_closure(tmp_path, "root.yaml")
    ).operations

    assert inherited.security_present is True
    assert inherited.security_pointer == "/security"
    assert inherited.security[0].schemes[0].scopes == ("read", "write")
    assert inherited.responses[0].media_types == (
        "application/json",
        "application/problem+json",
        "text/plain",
    )
    assert (
        inherited.responses[0].schema_media_types == inherited.responses[0].media_types
    )
    assert public.security_present is True
    assert public.security_pointer.endswith("/get/security")
    assert public.security == ()


def test_local_refs_preserve_defining_file_locations(tmp_path: Path) -> None:
    _write(
        tmp_path / "root.yaml",
        """openapi: 3.1.0
info: {title: Test, version: 1.0.0}
paths:
  /items/{id}:
    $ref: items.yaml#/pathItem
""",
    )
    _write(
        tmp_path / "items.yaml",
        """pathItem:
  get:
    operationId: getItem
    parameters:
      - $ref: parts.yaml#/parameter
    responses:
      '200':
        $ref: parts.yaml#/response
""",
    )
    _write(
        tmp_path / "parts.yaml",
        """parameter:
  name: id
  in: path
  required: true
  description: Item identifier
  schema: {type: string}
response:
  description: found
  content:
    application/json: {schema: {type: object}}
""",
    )

    operation = normalize_operations(
        build_input_closure(tmp_path, "root.yaml")
    ).operations[0]

    assert operation.source == "items.yaml"
    assert operation.pointer == "/pathItem/get"
    assert operation.path_source == "root.yaml"
    assert operation.path_pointer == "/paths/~1items~1{id}"
    assert operation.parameters[0].source == "parts.yaml"
    assert operation.parameters[0].pointer == "/parameter"
    assert operation.responses[0].source == "parts.yaml"
    assert operation.responses[0].pointer == "/response"


def test_invalid_operation_and_policy_are_visibly_indeterminate(tmp_path: Path) -> None:
    _write(
        tmp_path / "root.yaml",
        """openapi: 3.1.0
info: {title: Test, version: 1.0.0}
paths:
  /broken:
    get: []
  /missing:
    post:
      operationId: missingResponses
  /policy:
    delete:
      operationId: deletePolicy
      x-agent-policy:
        risks: not-an-array
      responses:
        '204': {description: deleted}
""",
    )

    result = normalize_operations(
        build_input_closure(tmp_path, "root.yaml")
    )
    broken, missing, policy = result.operations

    assert result.state == "indeterminate"
    assert broken.state == "indeterminate"
    assert any(item.code == "normalize.invalid-operation" for item in broken.issues)
    assert missing.state == "indeterminate"
    assert any(item.code == "normalize.missing-responses" for item in missing.issues)
    assert policy.state == "ready"
    assert policy.policy.valid is False
    assert policy.risk_categories == ("destructive",)
    assert any(item.code == "normalize.invalid-agent-policy" for item in policy.issues)


def test_policy_presence_and_conditional_metadata_are_preserved(tmp_path: Path) -> None:
    _write(
        tmp_path / "root.yaml",
        """openapi: 3.1.0
info: {title: Test, version: 1.0.0}
paths:
  /payments:
    post:
      operationId: transferPayment
      x-agent-policy:
        confirmation:
          mode: conditional
          condition: Require approval above the configured limit.
        authorization:
          roles: [operator]
        dataClassification: confidential
      responses:
        '200': {description: ok}
""",
    )

    policy = normalize_operations(
        build_input_closure(tmp_path, "root.yaml")
    ).operations[0].policy

    assert policy.present is True
    assert policy.valid is True
    assert policy.confirmation_present is True
    assert policy.confirmation_mode == "conditional"
    assert policy.confirmation_condition == (
        "Require approval above the configured limit."
    )
    assert policy.confirmation_reason is None
    assert policy.authorization_present is True
    assert policy.authorization_roles == ("operator",)
    assert policy.data_classification_present is True
    assert policy.data_classification == "confidential"


def test_operation_views_are_deterministic_immutable_and_dialect_neutral(
    tmp_path: Path,
) -> None:
    documents = {
        "a.json": {
            "openapi": "3.0.3",
            "info": {"title": "A", "version": "1"},
            "paths": {"/items": {"get": {"responses": {"200": {"description": "ok"}}}}},
        },
        "b.json": {
            "openapi": "3.1.1",
            "info": {"title": "B", "version": "1"},
            "paths": {"/items": {"get": {"responses": {"200": {"description": "ok"}}}}},
        },
    }
    results = []
    for name, document in documents.items():
        _write(tmp_path / name, json.dumps(document))
        closure = build_input_closure(tmp_path, name)
        results.append(normalize_operations(closure))

    assert set(results[0].operations[0].to_dict()) == set(
        results[1].operations[0].to_dict()
    )
    first = json.dumps(results[0].to_dict(), sort_keys=True, separators=(",", ":"))
    repeated = normalize_operations(build_input_closure(tmp_path, "a.json"))
    assert (
        json.dumps(repeated.to_dict(), sort_keys=True, separators=(",", ":")) == first
    )
    with pytest.raises(FrozenInstanceError):
        results[0].operations[0].method = "post"


def test_multi_entrypoint_requires_explicit_selection(tmp_path: Path) -> None:
    for name in ("a.yaml", "b.yaml"):
        _write(
            tmp_path / name,
            """openapi: 3.1.0
info: {title: Test, version: 1.0.0}
paths: {}
""",
        )
    closure = build_input_closure(tmp_path, ["a.yaml", "b.yaml"])

    with pytest.raises(ValueError, match="entrypoint is required"):
        normalize_operations(closure)

    assert normalize_operations(closure, "b.yaml").entrypoint == "b.yaml"
