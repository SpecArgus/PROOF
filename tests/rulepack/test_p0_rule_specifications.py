from __future__ import annotations

import json
import re
from collections import defaultdict
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
RULEPACK_ROOT = REPOSITORY_ROOT / "rulepacks" / "agent-contract" / "v1"
FIXTURE_ROOT = RULEPACK_ROOT / "fixtures"
CONTRACT_SCHEMA_ROOT = (
    REPOSITORY_ROOT
    / "packages"
    / "contracts"
    / "src"
    / "proof_contracts"
    / "schemas"
    / "result"
    / "v1"
)

EXPECTED_RULE_IDS = (
    "AGT-CTX-001",
    "AGT-PARAM-001",
    "AGT-RESP-001",
    "AGT-POL-001",
    "AGT-POL-002",
)
EXPECTED_CASE_TYPES = {
    "positive",
    "negative",
    "boundary",
    "false-positive",
}
EXPECTED_DIALECTS = {
    "3.0.x",
    "3.1.x",
}
HTTP_METHODS = {
    "get",
    "put",
    "post",
    "delete",
    "options",
    "head",
    "patch",
    "trace",
}


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


CATALOG = load_json(RULEPACK_ROOT / "rules.json")
MANIFEST = load_json(FIXTURE_ROOT / "manifest.json")
POLICY_SCHEMA = load_json(RULEPACK_ROOT / "schemas" / "agent-policy.schema.json")
RISK_CLASSIFICATION = load_json(RULEPACK_ROOT / "risk-classification.json")
FINDING_SCHEMA = load_json(CONTRACT_SCHEMA_ROOT / "finding.schema.json")
RUN_SCHEMA = load_json(CONTRACT_SCHEMA_ROOT / "run.schema.json")

CATALOG_BY_ID = {rule["id"]: rule for rule in CATALOG["rules"]}
ALLOWED_SEVERITIES = set(FINDING_SCHEMA["properties"]["severity"]["enum"])
ALLOWED_RISK_CATEGORIES = set(
    FINDING_SCHEMA["properties"]["riskCategories"]["items"]["enum"]
)
ALLOWED_EVIDENCE_KINDS = set(
    FINDING_SCHEMA["properties"]["evidence"]["items"]["properties"]["kind"]["enum"]
)


def decode_pointer_token(token: str) -> str:
    return token.replace("~1", "/").replace("~0", "~")


def resolve_pointer(document: object, pointer: str) -> object:
    if pointer == "":
        return document
    assert pointer.startswith("/")

    current = document
    for raw_token in pointer[1:].split("/"):
        token = decode_pointer_token(raw_token)
        if isinstance(current, list):
            current = current[int(token)]
        else:
            assert isinstance(current, dict)
            current = current[token]
    return current


def encode_pointer_token(token: str) -> str:
    return token.replace("~", "~0").replace("/", "~1")


def operation_pointers(document: dict) -> set[str]:
    pointers = set()
    for path, path_item in document["paths"].items():
        for method in HTTP_METHODS & path_item.keys():
            pointers.add(f"/paths/{encode_pointer_token(path)}/{method}")
    return pointers


def classifier_tokens(value: str) -> list[str]:
    with_camel_boundaries = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", value)
    with_digit_boundaries = re.sub(
        r"(?<=[A-Za-z])(?=[0-9])|(?<=[0-9])(?=[A-Za-z])",
        " ",
        with_camel_boundaries,
    )
    return re.findall(r"[a-z0-9]+", with_digit_boundaries.lower(), flags=re.ASCII)


def classify_operation(
    document: dict,
    operation_pointer: str,
) -> tuple[list[str], list[dict]]:
    pointer_parts = operation_pointer.split("/")
    assert pointer_parts[:2] == ["", "paths"]
    path_token = pointer_parts[2]
    method = pointer_parts[3]
    path = decode_pointer_token(path_token)
    path_pointer = f"/paths/{path_token}"
    operation = resolve_pointer(document, operation_pointer)
    assert isinstance(operation, dict)

    categories = set(RISK_CLASSIFICATION["methodCategories"].get(method, []))
    evidence_by_identity = {}

    if RISK_CLASSIFICATION["methodCategories"].get(method):
        item = {
            "kind": "method",
            "pointer": operation_pointer,
            "value": method,
        }
        evidence_by_identity[tuple(item.values())] = item

    token_categories = dict(RISK_CLASSIFICATION["allMethodTokenCategories"])
    if method in RISK_CLASSIFICATION["stateChangingMethods"]:
        token_categories.update(
            RISK_CLASSIFICATION["stateChangingTokenCategories"]
        )

    token_sources = [
        ("path", path_pointer, classifier_tokens(path)),
    ]
    if "operationId" in operation:
        token_sources.append(
            (
                "keyword",
                f"{operation_pointer}/operationId",
                classifier_tokens(operation["operationId"]),
            )
        )

    for category, vocabulary in token_categories.items():
        vocabulary_set = set(vocabulary)
        for kind, pointer, tokens in token_sources:
            for token in tokens:
                if token not in vocabulary_set:
                    continue
                categories.add(category)
                item = {
                    "kind": kind,
                    "pointer": pointer,
                    "value": token,
                }
                evidence_by_identity[tuple(item.values())] = item

    policy = operation.get("x-agent-policy", {})
    for index, category in enumerate(policy.get("risks", [])):
        categories.add(category)
        item = {
            "kind": "extension",
            "pointer": f"{operation_pointer}/x-agent-policy/risks/{index}",
            "value": category,
        }
        evidence_by_identity[tuple(item.values())] = item

    evidence = sorted(
        evidence_by_identity.values(),
        key=lambda item: (item["kind"], item["pointer"], item["value"]),
    )
    return sorted(categories), evidence


def iter_references(value: object):
    if isinstance(value, dict):
        for key, child in value.items():
            if key == "$ref":
                yield child
            yield from iter_references(child)
    elif isinstance(value, list):
        for child in value:
            yield from iter_references(child)


def test_catalog_defines_the_five_stable_rules() -> None:
    assert CATALOG["rulesetName"] == "agent-contract"
    assert CATALOG["rulesetVersion"] == "0.1.0"
    assert CATALOG["resultSchemaVersion"] == RUN_SCHEMA["properties"][
        "schemaVersion"
    ]["const"]
    assert CATALOG["supportedOpenApi"] == ["3.0.x", "3.1.x"]
    assert tuple(CATALOG_BY_ID) == EXPECTED_RULE_IDS

    expected_severities = {
        "AGT-CTX-001": "medium",
        "AGT-PARAM-001": "medium",
        "AGT-RESP-001": "medium",
        "AGT-POL-001": "high",
        "AGT-POL-002": "high",
    }
    assert {
        rule_id: rule["defaultSeverity"]
        for rule_id, rule in CATALOG_BY_ID.items()
    } == expected_severities


@pytest.mark.parametrize("rule_id", EXPECTED_RULE_IDS)
def test_each_rule_has_a_complete_normative_document(rule_id: str) -> None:
    rule = CATALOG_BY_ID[rule_id]
    document_path = RULEPACK_ROOT / rule["documentation"]
    assert document_path.is_file()

    content = document_path.read_text(encoding="utf-8")
    for heading in (
        "## Identity",
        "## Intent",
        "## Pass and finding behavior",
        "## Indeterminate behavior",
        "## Finding contract",
        "## Dialects and false positives",
    ):
        assert heading in content
    assert rule_id in content
    assert rule["defaultSeverity"] in content


def test_agent_policy_schema_is_valid_draft_2020_12() -> None:
    assert POLICY_SCHEMA["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    Draft202012Validator.check_schema(POLICY_SCHEMA)


def test_risk_vocabulary_is_sorted_and_covers_result_categories() -> None:
    category_maps = (
        RISK_CLASSIFICATION["methodCategories"],
        RISK_CLASSIFICATION["stateChangingTokenCategories"],
        RISK_CLASSIFICATION["allMethodTokenCategories"],
    )
    represented_categories = set()
    for category_map in category_maps:
        for key, values in category_map.items():
            if key in ALLOWED_RISK_CATEGORIES:
                represented_categories.add(key)
            else:
                represented_categories.update(values)
            assert values == sorted(set(values))

    assert represented_categories == ALLOWED_RISK_CATEGORIES
    assert RISK_CLASSIFICATION["stateChangingMethods"] == sorted(
        set(RISK_CLASSIFICATION["stateChangingMethods"])
    )


def test_all_fixture_agent_policies_match_the_extension_schema() -> None:
    validator = Draft202012Validator(POLICY_SCHEMA)
    policies = []
    for fixture_path in sorted(FIXTURE_ROOT.glob("oas*/*.json")):
        document = load_json(fixture_path)
        for path_item in document["paths"].values():
            for method in HTTP_METHODS & path_item.keys():
                operation = path_item[method]
                if "x-agent-policy" in operation:
                    policies.append(operation["x-agent-policy"])

    assert policies
    for policy in policies:
        assert list(validator.iter_errors(policy)) == []


@pytest.mark.parametrize(
    "invalid_policy",
    [
        {"confirmation": {"mode": "conditional"}},
        {"confirmation": {"mode": "not-required"}},
        {"authorization": {"roles": []}},
        {"risks": ["destructive", "destructive"]},
        {"unexpected": True},
    ],
)
def test_agent_policy_schema_rejects_ambiguous_or_weak_metadata(
    invalid_policy: dict,
) -> None:
    assert not Draft202012Validator(POLICY_SCHEMA).is_valid(invalid_policy)


def test_fixture_manifest_covers_every_rule_case_type_and_dialect() -> None:
    cases_by_rule = defaultdict(list)
    for case in MANIFEST["cases"]:
        cases_by_rule[case["ruleId"]].append(case)

    assert set(cases_by_rule) == set(EXPECTED_RULE_IDS)
    for rule_id, cases in cases_by_rule.items():
        assert len(cases) == 4, rule_id
        assert {case["caseType"] for case in cases} == EXPECTED_CASE_TYPES
        assert {case["dialect"] for case in cases} == EXPECTED_DIALECTS


def test_fixture_cases_are_unique_and_cover_every_fixture_operation() -> None:
    cases = MANIFEST["cases"]
    assert len(cases) == 20
    assert len({case["caseId"] for case in cases}) == len(cases)

    represented_operations = {
        (case["fixture"], case["operationPointer"]) for case in cases
    }
    fixture_operations = set()
    for fixture_path in sorted(FIXTURE_ROOT.glob("oas*/*.json")):
        fixture_name = fixture_path.relative_to(FIXTURE_ROOT).as_posix()
        document = load_json(fixture_path)
        fixture_operations.update(
            (fixture_name, pointer) for pointer in operation_pointers(document)
        )

    assert represented_operations == fixture_operations


def test_fixtures_cover_every_risk_category_and_signal_kind() -> None:
    observed_categories = set()
    observed_signal_kinds = set()
    for case in MANIFEST["cases"]:
        document = load_json(FIXTURE_ROOT / case["fixture"])
        categories, evidence = classify_operation(
            document,
            case["operationPointer"],
        )
        observed_categories.update(categories)
        observed_signal_kinds.update(item["kind"] for item in evidence)

    assert observed_categories == ALLOWED_RISK_CATEGORIES
    assert observed_signal_kinds == {
        "extension",
        "keyword",
        "method",
        "path",
    }


@pytest.mark.parametrize(
    "case",
    MANIFEST["cases"],
    ids=[case["caseId"] for case in MANIFEST["cases"]],
)
def test_fixture_case_uses_result_contract_terminology(case: dict) -> None:
    fixture_path = FIXTURE_ROOT / case["fixture"]
    assert fixture_path.is_file()
    document = load_json(fixture_path)

    assert document["openapi"].startswith(case["dialect"].removesuffix("x"))
    operation = resolve_pointer(document, case["operationPointer"])
    assert isinstance(operation, dict)

    if case["caseType"] == "positive":
        assert case["expectedFindings"]
    if case["caseType"] in {"negative", "false-positive"}:
        assert case["expectedFindings"] == []

    expected_severity = CATALOG_BY_ID[case["ruleId"]]["defaultSeverity"]
    for finding in case["expectedFindings"]:
        assert finding["ruleId"] == case["ruleId"]
        assert finding["severity"] == expected_severity
        assert finding["severity"] in ALLOWED_SEVERITIES
        assert resolve_pointer(document, finding["locationPointer"]) is not None

        risk_categories = finding["riskCategories"]
        assert risk_categories == sorted(set(risk_categories))
        assert set(risk_categories) <= ALLOWED_RISK_CATEGORIES

        evidence = finding["evidence"]
        assert evidence
        assert evidence == sorted(
            evidence,
            key=lambda item: (
                item["kind"],
                item["pointer"],
                item.get("value", ""),
            ),
        )
        for item in evidence:
            assert item["kind"] in ALLOWED_EVIDENCE_KINDS
            assert resolve_pointer(document, item["pointer"]) is not None

        if risk_categories:
            classified_categories, classification_evidence = classify_operation(
                document,
                case["operationPointer"],
            )
            assert risk_categories == classified_categories
            assert all(item in evidence for item in classification_evidence)


@pytest.mark.parametrize(
    "fixture_path",
    sorted(FIXTURE_ROOT.glob("oas*/*.json")),
    ids=lambda path: path.relative_to(FIXTURE_ROOT).as_posix(),
)
def test_fixtures_are_self_contained_and_use_supported_dialects(
    fixture_path: Path,
) -> None:
    document = load_json(fixture_path)
    assert document["openapi"].startswith(("3.0.", "3.1."))
    assert document["info"]["title"]
    assert document["info"]["version"]
    assert document["paths"]

    for reference in iter_references(document):
        assert isinstance(reference, str)
        assert reference.startswith("#/")
