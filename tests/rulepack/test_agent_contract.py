from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
import rfc8785
from jsonschema import Draft202012Validator
from proof_core import build_input_closure, normalize_operations
from proof_rulepack import (
    AGENT_CONTRACT_IDENTITY,
    agent_contract,
    evaluate_agent_contract,
)
from referencing import Registry, Resource

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
FIXTURE_ROOT = REPOSITORY_ROOT / "rulepacks" / "agent-contract" / "v1" / "fixtures"
CORPUS_FIXTURE_ROOT = REPOSITORY_ROOT / "corpus" / "fixtures"
RULE_ROOT = REPOSITORY_ROOT / "rulepacks" / "agent-contract" / "v1"
RESULT_SCHEMA_ROOT = (
    REPOSITORY_ROOT
    / "packages"
    / "contracts"
    / "src"
    / "proof_contracts"
    / "schemas"
    / "result"
    / "v1"
)


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8", newline="\n")


def _evaluate_fixture(relative: str):
    fixture = FIXTURE_ROOT / relative
    closure = build_input_closure(fixture.parent, fixture.name)
    operations = normalize_operations(closure)
    return operations, evaluate_agent_contract(operations)


def _finding_validator() -> Draft202012Validator:
    schemas = [
        json.loads(path.read_text(encoding="utf-8"))
        for path in sorted(RESULT_SCHEMA_ROOT.glob("*.schema.json"))
    ]
    registry = Registry()
    for schema in schemas:
        registry = registry.with_resource(schema["$id"], Resource.from_contents(schema))
    finding = next(
        schema for schema in schemas if schema["title"].endswith("finding v1")
    )
    return Draft202012Validator(finding, registry=registry)


def _projected_evidence(finding: dict) -> list[dict]:
    projected = []
    for evidence in finding["evidence"]:
        identity = {
            "kind": evidence["kind"],
            "value": evidence.get("value", evidence["description"]),
        }
        if "pointer" in evidence:
            identity["pointer"] = evidence["pointer"]
        projected.append(identity)
    return sorted(projected, key=rfc8785.dumps)


def _expected_fingerprint(finding: dict) -> str:
    projection = {
        "fingerprintVersion": 1,
        "source": finding["source"],
        "ruleId": finding["ruleId"],
        "location": finding["location"],
        "operation": {
            "method": finding["operation"]["method"],
            "path": finding["operation"]["path"],
        },
        "evidence": _projected_evidence(finding),
    }
    if finding.get("riskCategories"):
        projection["riskCategories"] = sorted(finding["riskCategories"])
    return f"sha256:{hashlib.sha256(rfc8785.dumps(projection)).hexdigest()}"


def test_rule_catalog_and_exact_identity_match_source_artifacts() -> None:
    catalog = json.loads((RULE_ROOT / "rules.json").read_text(encoding="utf-8"))
    implemented = [
        {
            "id": item["id"],
            "name": item["name"],
            "defaultSeverity": item["severity"],
        }
        for item in agent_contract.RULES
    ]
    declared = [
        {
            "id": item["id"],
            "name": item["name"],
            "defaultSeverity": item["defaultSeverity"],
        }
        for item in catalog["rules"]
    ]

    assert catalog["rulesetName"] == AGENT_CONTRACT_IDENTITY.name
    assert catalog["rulesetVersion"] == AGENT_CONTRACT_IDENTITY.version
    assert implemented == declared
    assert AGENT_CONTRACT_IDENTITY.digest == (
        "sha256:6ee271830ad74f69f77bc83bc6d783020e4e895408ea1dee4bd332139e3ff71b"
    )


def test_all_twenty_cases_match_complete_five_rule_outcomes() -> None:
    manifest = json.loads((FIXTURE_ROOT / "manifest.json").read_text(encoding="utf-8"))
    cache = {
        fixture: _evaluate_fixture(fixture)
        for fixture in sorted({item["fixture"] for item in manifest["cases"]})
    }

    assert len(manifest["cases"]) == 20
    for case in manifest["cases"]:
        operations, evaluation = cache[case["fixture"]]
        operation = next(
            item
            for item in operations.operations
            if item.pointer == case["operationPointer"]
        )
        findings = [
            item.to_dict()
            for item in evaluation.findings
            if item.operation.method == operation.method
            and item.operation.path == operation.path
        ]
        expected = case["expectedFindings"]
        assert len(findings) == len(expected), case["caseId"]
        actual_labels = []
        for finding in findings:
            actual_labels.append(
                {
                    "ruleId": finding["ruleId"],
                    "severity": finding["severity"],
                    "locationPointer": finding["location"]["pointer"],
                    "riskCategories": finding.get("riskCategories", []),
                    "evidence": [
                        {
                            key: evidence[key]
                            for key in ("kind", "pointer", "value")
                            if key in evidence
                        }
                        for evidence in finding["evidence"]
                    ],
                }
            )
        assert actual_labels == expected, case["caseId"]


def test_findings_validate_and_fingerprints_follow_result_v1() -> None:
    validator = _finding_validator()
    manifest = json.loads((FIXTURE_ROOT / "manifest.json").read_text(encoding="utf-8"))
    fixtures = sorted({item["fixture"] for item in manifest["cases"]})

    for relative in fixtures:
        _operations, evaluation = _evaluate_fixture(relative)
        for finding in evaluation.findings:
            value = finding.to_dict()
            validator.validate(value)
            assert value["fingerprint"] == _expected_fingerprint(value)


def test_rule_output_is_byte_deterministic_and_canonically_sorted() -> None:
    fixture = "oas30/agt-pol-001.json"
    serializations = []
    for _ in range(3):
        _operations, evaluation = _evaluate_fixture(fixture)
        serializations.append(rfc8785.dumps(evaluation.to_dict()))

    assert len(set(serializations)) == 1
    _operations, evaluation = _evaluate_fixture(fixture)
    severities = [finding.severity for finding in evaluation.findings]
    assert severities == sorted(
        severities, key=agent_contract._SEVERITY_RANK.__getitem__
    )


def test_every_risk_finding_exposes_classification_evidence() -> None:
    manifest = json.loads((FIXTURE_ROOT / "manifest.json").read_text(encoding="utf-8"))
    fixtures = sorted({item["fixture"] for item in manifest["cases"]})
    for relative in fixtures:
        _operations, evaluation = _evaluate_fixture(relative)
        for finding in evaluation.findings:
            if not finding.risk_categories:
                continue
            assert any(
                item.kind in {"extension", "keyword", "method", "path"}
                for item in finding.evidence
            )


def test_context_parameter_exclusions_and_structured_error_boundary(
    tmp_path: Path,
) -> None:
    _write(
        tmp_path / "root.yaml",
        """openapi: 3.1.0
info: {title: Test, version: 1.0.0}
paths:
  /process:
    post:
      operationId: " "
      summary: "\t"
      parameters:
        - {name: Accept, in: header, schema: {type: string}}
        - {name: content-type, in: header, schema: {type: string}}
        - {name: AUTHORIZATION, in: header, schema: {type: string}}
        - {name: X-Trace, in: header, schema: {type: string}}
      responses:
        4XX:
          description: problem
          content:
            application/problem+json: {schema: {type: object}}
""",
    )
    operations = normalize_operations(build_input_closure(tmp_path, "root.yaml"))
    evaluation = evaluate_agent_contract(operations)

    assert [item.rule_id for item in evaluation.findings] == [
        "AGT-CTX-001",
        "AGT-PARAM-001",
    ]
    context, parameter = evaluation.findings
    assert [item.value for item in context.evidence] == [
        "operationId",
        "summary-or-description",
    ]
    assert parameter.location.pointer.endswith("/parameters/3")


@pytest.mark.parametrize(
    "status,schema_media_types,expected",
    [
        ("400", ("application/json",), True),
        ("599", ("application/problem+json",), True),
        ("4XX", ("application/json",), True),
        ("5XX", ("application/json",), True),
        ("default", ("application/json",), True),
        ("4xx", ("application/json",), False),
        ("399", ("application/json",), False),
        ("600", ("application/json",), False),
        ("400", (), False),
        ("400", ("text/plain",), False),
    ],
)
def test_structured_error_status_and_media_boundaries(
    status: str, schema_media_types: tuple[str, ...], expected: bool
) -> None:
    response = SimpleNamespace(
        status_code=status, schema_media_types=schema_media_types
    )
    assert agent_contract._is_structured_error(response) is expected


def test_confirmation_modes_and_malformed_policy_are_determinate(
    tmp_path: Path,
) -> None:
    paths = []
    policies = {
        "required": "confirmation: {mode: required}",
        "conditional": (
            "confirmation: {mode: conditional, condition: Above the limit}"
        ),
        "missing-condition": "confirmation: {mode: conditional}",
        "not-required": ("confirmation: {mode: not-required, reason: Already expired}"),
        "malformed": "confirmation: {mode: required, unknown: value}",
    }
    for name, policy in policies.items():
        paths.append(
            f"""  /delete/{name}:
    delete:
      operationId: delete{name.title().replace("-", "")}
      summary: Delete test item
      x-agent-policy:
        {policy}
      responses:
        default:
          description: problem
          content:
            application/json: {{schema: {{type: object}}}}
"""
        )
    _write(
        tmp_path / "root.yaml",
        "openapi: 3.1.0\ninfo: {title: Test, version: 1.0.0}\npaths:\n"
        + "".join(paths),
    )

    operations = normalize_operations(build_input_closure(tmp_path, "root.yaml"))
    evaluation = evaluate_agent_contract(operations)
    policy_findings = [
        item for item in evaluation.findings if item.rule_id == "AGT-POL-001"
    ]

    assert [item.operation.path for item in policy_findings] == [
        "/delete/malformed",
        "/delete/missing-condition",
    ]
    assert all(
        item.location.pointer.endswith("/confirmation") for item in policy_findings
    )


def test_security_requirements_aggregate_and_locate_missing_metadata(
    tmp_path: Path,
) -> None:
    _write(
        tmp_path / "root.yaml",
        """openapi: 3.1.0
info: {title: Test, version: 1.0.0}
components:
  securitySchemes:
    auth: {type: http, scheme: bearer}
paths:
  /optional-profile:
    get:
      operationId: getOptionalProfile
      summary: Get optional profile
      security: [{auth: []}, {}]
      x-agent-policy: {dataClassification: restricted}
      responses: {'200': {description: ok}}
  /profile:
    get:
      operationId: getProfile
      summary: Get profile
      security: [{}]
      x-agent-policy: {dataClassification: restricted}
      responses: {'200': {description: ok}}
  /roles:
    patch:
      operationId: updateRoles
      summary: Update roles
      security: [{auth: []}]
      x-agent-policy:
        confirmation: {mode: required}
        authorization: {roles: [" "]}
      responses:
        default:
          description: problem
          content:
            application/json: {schema: {type: object}}
  /secure-profile:
    get:
      operationId: getSecureProfile
      summary: Get secure profile
      security: [{auth: []}]
      x-agent-policy: {dataClassification: confidential}
      responses: {'200': {description: ok}}
""",
    )
    operations = normalize_operations(build_input_closure(tmp_path, "root.yaml"))
    evaluation = evaluate_agent_contract(operations)
    findings = [item for item in evaluation.findings if item.rule_id == "AGT-POL-002"]

    assert [(item.operation.path, item.location.pointer) for item in findings] == [
        (
            "/optional-profile",
            "/paths/~1optional-profile/get/security",
        ),
        ("/profile", "/paths/~1profile/get/security"),
        ("/roles", "/paths/~1roles/patch/x-agent-policy/authorization/roles"),
    ]
    assert "security" in findings[0].message
    assert "security" in findings[1].message
    assert "authorization.roles" in findings[2].message


@pytest.mark.parametrize(
    ("case_id", "relative", "dialect", "operation_path"),
    [
        (
            "syn-pol2-permission-xpolicy-no-roles-30",
            "synthetic/pol2-cases.json",
            "3.0",
            "/roles",
        ),
        (
            "syn-pol2-both-risks-roles-missing-31",
            "synthetic/pol2-cases-31.json",
            "3.1",
            "/access/credentials",
        ),
    ],
)
def test_missing_policy_subfield_locates_present_policy_object(
    case_id: str,
    relative: str,
    dialect: str,
    operation_path: str,
) -> None:
    fixture = CORPUS_FIXTURE_ROOT / relative
    operations = normalize_operations(
        build_input_closure(fixture.parent, fixture.name)
    )
    manifest = json.loads(
        (REPOSITORY_ROOT / "corpus" / "manifest.json").read_text(encoding="utf-8")
    )
    case = next(item for item in manifest["cases"] if item["caseId"] == case_id)
    expected = next(
        item
        for item in case["expectedFindings"]
        if item["ruleId"] == "AGT-POL-002"
    )

    assert operations.dialect == dialect
    first = evaluate_agent_contract(operations)
    second = evaluate_agent_contract(operations)
    finding = next(
        item
        for item in first.findings
        if item.rule_id == "AGT-POL-002" and item.operation.path == operation_path
    )
    actual = finding.to_dict()
    projected = {
        "ruleId": actual["ruleId"],
        "severity": actual["severity"],
        "locationPointer": actual["location"]["pointer"],
        "riskCategories": actual["riskCategories"],
        "evidence": _projected_evidence(actual),
    }
    expected_projection = {
        key: value for key, value in expected.items() if key != "reviewers"
    }

    assert projected == expected_projection
    assert finding.fingerprint == _expected_fingerprint(actual)
    assert [item.to_dict() for item in first.findings] == [
        item.to_dict() for item in second.findings
    ]


@pytest.mark.parametrize(
    ("authorization", "expected_suffix"),
    [
        ("{}", "/x-agent-policy"),
        ("null", "/x-agent-policy"),
        ("{roles: []}", "/x-agent-policy/authorization/roles"),
        ('{roles: [" "]}', "/x-agent-policy/authorization/roles"),
    ],
)
def test_security_location_uses_only_present_authorization_roles_field(
    tmp_path: Path,
    authorization: str,
    expected_suffix: str,
) -> None:
    _write(
        tmp_path / "root.yaml",
        f"""openapi: 3.1.0
info: {{title: Review, version: 1.0.0}}
components:
  securitySchemes:
    auth: {{type: http, scheme: bearer}}
security: [{{auth: []}}]
paths:
  /roles:
    post:
      operationId: createRole
      summary: Create role
      x-agent-policy:
        confirmation: {{mode: required}}
        authorization: {authorization}
      responses:
        default:
          description: problem
          content:
            application/json: {{schema: {{type: object}}}}
""",
    )

    operations = normalize_operations(build_input_closure(tmp_path, "root.yaml"))
    first = evaluate_agent_contract(operations)
    second = evaluate_agent_contract(operations)
    finding = next(
        item for item in first.findings if item.rule_id == "AGT-POL-002"
    )
    actual = finding.to_dict()

    assert finding.location.pointer == f"/paths/~1roles/post{expected_suffix}"
    assert finding.fingerprint == _expected_fingerprint(actual)
    assert [item.to_dict() for item in first.findings] == [
        item.to_dict() for item in second.findings
    ]


@pytest.mark.parametrize(
    ("root_security", "expects_finding"),
    [
        ("[{auth: []}]", False),
        ("[{}]", True),
        ("[{auth: []}, {}]", True),
        ("[]", True),
    ],
)
def test_inherited_security_requires_every_alternative_to_authenticate(
    tmp_path: Path,
    root_security: str,
    expects_finding: bool,
) -> None:
    _write(
        tmp_path / "root.yaml",
        f"""openapi: 3.1.0
info: {{title: Test, version: 1.0.0}}
components:
  securitySchemes:
    auth: {{type: http, scheme: bearer}}
security: {root_security}
paths:
  /profile:
    get:
      operationId: getProfile
      summary: Get profile
      x-agent-policy: {{dataClassification: restricted}}
      responses: {{'200': {{description: ok}}}}
""",
    )

    operations = normalize_operations(build_input_closure(tmp_path, "root.yaml"))
    evaluation = evaluate_agent_contract(operations)
    findings = [item for item in evaluation.findings if item.rule_id == "AGT-POL-002"]

    assert bool(findings) is expects_finding
    if expects_finding:
        assert findings[0].location.pointer == "/security"
        assert "security" in findings[0].message


def test_invalid_operation_is_skipped_without_speculative_finding(
    tmp_path: Path,
) -> None:
    _write(
        tmp_path / "root.yaml",
        """openapi: 3.1.0
info: {title: Test, version: 1.0.0}
paths:
  /broken:
    get: []
""",
    )
    operations = normalize_operations(build_input_closure(tmp_path, "root.yaml"))
    evaluation = evaluate_agent_contract(operations)

    assert evaluation.findings == ()
    assert evaluation.evaluated_operations == 0
    assert evaluation.indeterminate_operations == 1


def test_indeterminate_operation_set_suppresses_ready_operation_findings(
    tmp_path: Path,
) -> None:
    _write(
        tmp_path / "root.yaml",
        """openapi: 2.0
info: {title: Unsupported, version: 1.0.0}
paths:
  /pets:
    get:
      responses:
        '200': {description: ok}
""",
    )
    operations = normalize_operations(build_input_closure(tmp_path, "root.yaml"))

    assert operations.state == "indeterminate"
    assert operations.operations[0].state == "ready"

    evaluation = evaluate_agent_contract(operations)

    assert evaluation.findings == ()
    assert evaluation.evaluated_operations == 0
    assert evaluation.indeterminate_operations == 1


def test_messages_and_remediation_do_not_claim_runtime_enforcement() -> None:
    manifest = json.loads((FIXTURE_ROOT / "manifest.json").read_text(encoding="utf-8"))
    fixtures = sorted({item["fixture"] for item in manifest["cases"]})
    forbidden = ("is enforced", "enforces authorization", "guarantees")
    for relative in fixtures:
        _operations, evaluation = _evaluate_fixture(relative)
        for finding in evaluation.findings:
            text = f"{finding.message} {finding.remediation.recommendation}".lower()
            assert not any(phrase in text for phrase in forbidden)
