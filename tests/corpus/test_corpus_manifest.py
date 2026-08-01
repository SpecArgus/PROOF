from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
CORPUS_ROOT = REPOSITORY_ROOT / "corpus"
FIXTURE_ROOT = CORPUS_ROOT / "fixtures"
RULEPACK_ROOT = REPOSITORY_ROOT / "rulepacks" / "agent-contract" / "v1"
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


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


MANIFEST = load_json(CORPUS_ROOT / "manifest.json")
MANIFEST_SCHEMA = load_json(CORPUS_ROOT / "manifest.schema.json")
COVERAGE = load_json(CORPUS_ROOT / "coverage-summary.json")
CATALOG = load_json(RULEPACK_ROOT / "rules.json")
FINDING_SCHEMA = load_json(CONTRACT_SCHEMA_ROOT / "finding.schema.json")

CATALOG_BY_ID = {rule["id"]: rule for rule in CATALOG["rules"]}
ALLOWED_RULE_IDS = frozenset(CATALOG_BY_ID)
ALL_RISK_CATEGORIES = frozenset(
    FINDING_SCHEMA["properties"]["riskCategories"]["items"]["enum"]
)
ALLOWED_EVIDENCE_KINDS = frozenset(
    FINDING_SCHEMA["properties"]["evidence"]["items"]["properties"]["kind"]["enum"]
)
ALLOWED_SEVERITIES = frozenset(FINDING_SCHEMA["properties"]["severity"]["enum"])

CASES = MANIFEST["cases"]
CASE_IDS = [case["caseId"] for case in CASES]


def decode_pointer_token(token: str) -> str:
    return token.replace("~1", "/").replace("~0", "~")


def encode_pointer_token(segment: str) -> str:
    return segment.replace("~", "~0").replace("/", "~1")


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


def load_fixture(fixture_rel: str) -> dict:
    """Load a JSON fixture. Fail clearly if a YAML fixture is referenced."""
    path = FIXTURE_ROOT / fixture_rel
    if path.suffix in (".yaml", ".yml"):
        pytest.fail(
            f"YAML fixture '{fixture_rel}' cannot be loaded: no approved YAML parser "
            "is available in the current lockfile. Convert the fixture to JSON or add "
            "an approved YAML parser dependency before introducing YAML corpus cases."
        )
    return load_json(path)


def test_manifest_validates_against_schema() -> None:
    validator = Draft202012Validator(MANIFEST_SCHEMA)
    errors = list(validator.iter_errors(MANIFEST))
    assert errors == [], [str(e) for e in errors]


def test_case_ids_are_unique() -> None:
    ids = [case["caseId"] for case in CASES]
    assert len(ids) == len(set(ids))


def test_no_yaml_cases_in_pilot() -> None:
    yaml_cases = [c for c in CASES if c.get("format") in ("yaml", "yml")]
    if yaml_cases:
        ids = ", ".join(c["caseId"] for c in yaml_cases)
        pytest.fail(
            f"YAML fixtures are not supported in this pilot ({ids}). "
            "Add an approved YAML parser dependency before introducing YAML cases. "
            "See corpus/README.md for details."
        )


@pytest.mark.parametrize("case", CASES, ids=CASE_IDS)
def test_fixture_path_and_operation_pointer_resolve(case: dict) -> None:
    expected_pointer = (
        f"/paths/{encode_pointer_token(case['apiPath'])}/{case['method']}"
    )
    assert case["operationPointer"] == expected_pointer, (
        f"operationPointer {case['operationPointer']!r} != "
        f"canonical {expected_pointer!r}"
    )
    fixture_path = FIXTURE_ROOT / case["fixture"]
    assert fixture_path.is_file(), f"Fixture not found: {case['fixture']}"
    document = load_fixture(case["fixture"])
    pointer = case["operationPointer"]
    last_slash = pointer.rfind("/")
    parent_pointer = pointer[:last_slash]
    method_token = decode_pointer_token(pointer[last_slash + 1:])
    operation = resolve_pointer(document, pointer)
    assert isinstance(operation, dict)
    assert method_token == case["method"], (
        f"pointer last token {method_token!r} != declared method {case['method']!r}"
    )
    path_item = resolve_pointer(document, parent_pointer)
    assert isinstance(path_item, dict)
    assert case["method"] in path_item
    assert path_item[case["method"]] == operation


@pytest.mark.parametrize("case", CASES, ids=CASE_IDS)
def test_format_and_dialect_consistency(case: dict) -> None:
    fixture_path = FIXTURE_ROOT / case["fixture"]
    assert fixture_path.suffix == f".{case['format']}", (
        f"File suffix {fixture_path.suffix!r} does not match format {case['format']!r}"
    )
    document = load_fixture(case["fixture"])
    openapi_version = document["openapi"]
    expected_prefix = case["dialect"].removesuffix("x")
    assert openapi_version.startswith(expected_prefix), (
        f"openapi {openapi_version!r} does not match dialect {case['dialect']!r}"
    )


def test_no_remote_refs() -> None:
    def iter_refs(value: object):
        if isinstance(value, dict):
            for k, v in value.items():
                if k == "$ref":
                    yield v
                yield from iter_refs(v)
        elif isinstance(value, list):
            for item in value:
                yield from iter_refs(item)

    seen_fixtures: set[str] = set()
    for case in CASES:
        if case["fixture"] in seen_fixtures:
            continue
        seen_fixtures.add(case["fixture"])
        document = load_fixture(case["fixture"])
        for ref in iter_refs(document):
            assert isinstance(ref, str) and ref.startswith("#/"), (
                f"Remote $ref {ref!r} found in {case['fixture']}"
            )


@pytest.mark.parametrize("case", CASES, ids=CASE_IDS)
def test_vocabulary_crosscheck(case: dict) -> None:
    assert case["ruleId"] in ALLOWED_RULE_IDS, f"Unknown ruleId: {case['ruleId']}"
    for rule_id in case["expectedNonFindings"]:
        assert rule_id in ALLOWED_RULE_IDS, (
            f"Unknown ruleId in expectedNonFindings: {rule_id}"
        )
    assert set(case["expectedRisks"]) <= ALL_RISK_CATEGORIES
    assert set(case["expectedNonRisks"]) <= ALL_RISK_CATEGORIES
    for finding in case["expectedFindings"]:
        assert finding["ruleId"] in ALLOWED_RULE_IDS
        assert finding["severity"] in ALLOWED_SEVERITIES
        catalog_default = CATALOG_BY_ID[finding["ruleId"]]["defaultSeverity"]
        assert finding["severity"] == catalog_default, (
            f"severity {finding['severity']!r} does not match catalog default "
            f"{catalog_default!r} for {finding['ruleId']}"
        )
        assert set(finding["riskCategories"]) <= ALL_RISK_CATEGORIES
        for item in finding["evidence"]:
            assert item["kind"] in ALLOWED_EVIDENCE_KINDS, (
                f"Unknown evidence kind {item['kind']!r}"
            )


@pytest.mark.parametrize("case", CASES, ids=CASE_IDS)
def test_expected_risks_exhaustive_and_disjoint(case: dict) -> None:
    risks = frozenset(case["expectedRisks"])
    non_risks = frozenset(case["expectedNonRisks"])
    assert risks.isdisjoint(non_risks), (
        f"expectedRisks and expectedNonRisks overlap: {risks & non_risks}"
    )
    assert risks | non_risks == ALL_RISK_CATEGORIES, (
        f"Union does not cover all categories. "
        f"Missing: {ALL_RISK_CATEGORIES - (risks | non_risks)}"
    )


@pytest.mark.parametrize("case", CASES, ids=CASE_IDS)
def test_finding_risk_categories_subset_of_expected_risks(case: dict) -> None:
    risks = frozenset(case["expectedRisks"])
    for finding in case["expectedFindings"]:
        finding_risks = frozenset(finding["riskCategories"])
        assert finding_risks <= risks, (
            f"Finding riskCategories {finding_risks} not a subset of "
            f"case expectedRisks {risks}"
        )


@pytest.mark.parametrize("case", CASES, ids=CASE_IDS)
def test_caselabels_consistency(case: dict) -> None:
    labels = set(case["caseLabels"])
    has_findings = bool(case["expectedFindings"])
    if "positive" in labels:
        assert has_findings, (
            f"{case['caseId']}: 'positive' label requires non-empty expectedFindings"
        )
    if labels & {"negative", "false-positive"}:
        assert not has_findings, (
            f"{case['caseId']}: 'negative'/'false-positive' label "
            "requires empty expectedFindings"
        )
    if has_findings:
        assert "positive" in labels, (
            f"{case['caseId']}: non-empty expectedFindings requires 'positive' label"
        )
    if not has_findings:
        assert "negative" in labels, (
            f"{case['caseId']}: empty expectedFindings requires 'negative' label"
        )
    assert not ("positive" in labels and "negative" in labels), (
        f"{case['caseId']}: 'positive' and 'negative' labels cannot coexist"
    )
    if "false-positive" in labels:
        assert "negative" in labels, (
            f"{case['caseId']}: 'false-positive' label requires 'negative' label"
        )


@pytest.mark.parametrize("case", CASES, ids=CASE_IDS)
def test_evidence_ordering_in_findings(case: dict) -> None:
    for finding in case["expectedFindings"]:
        evidence = finding["evidence"]
        sorted_evidence = sorted(
            evidence,
            key=lambda item: (
                item["kind"],
                item.get("pointer", ""),
                item.get("value", ""),
            ),
        )
        assert evidence == sorted_evidence, (
            f"Evidence in {case['caseId']} / {finding['ruleId']} "
            "is not sorted by (kind, pointer, value)"
        )


@pytest.mark.parametrize("case", CASES, ids=CASE_IDS)
def test_reviewer_records_structure(case: dict) -> None:
    for finding in case["expectedFindings"]:
        for reviewer in finding.get("reviewers", []):
            assert isinstance(reviewer, dict), (
                f"Reviewer record in {case['caseId']} must be an object"
            )


def test_coverage_summary_consistent_with_manifest() -> None:
    assert COVERAGE["totalCases"] == len(CASES), (
        f"coverage totalCases {COVERAGE['totalCases']} != "
        f"manifest case count {len(CASES)}"
    )
    by_rule: dict[str, int] = {}
    for case in CASES:
        by_rule[case["ruleId"]] = by_rule.get(case["ruleId"], 0) + 1
    for rule_id, total in by_rule.items():
        assert COVERAGE["byRule"][rule_id]["total"] == total, (
            f"coverage byRule[{rule_id}].total {COVERAGE['byRule'][rule_id]['total']} "
            f"!= manifest count {total}"
        )
