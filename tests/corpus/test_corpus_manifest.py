from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from urllib.parse import urlsplit

import pytest
import rfc8785
import yaml
from jsonschema import Draft202012Validator, FormatChecker
from proof_core import (
    DocumentLimits,
    InputLimits,
    OperationSet,
    ValidatorResult,
    build_input_closure,
    normalize_operations,
    read_repository_document,
    validate_openapi,
)
from proof_rulepack import RuleEvaluation, evaluate_agent_contract

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
FORMAT_CHECKER = FormatChecker()
FIXTURE_ENTRYPOINTS = tuple(sorted({case["fixture"] for case in CASES}))
EngineResult = tuple[ValidatorResult, OperationSet, RuleEvaluation]


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


_ENGINE_LIMITS = InputLimits()
_FIXTURE_DOCUMENT_LIMITS = DocumentLimits(
    max_bytes=_ENGINE_LIMITS.max_entrypoint_bytes,
    max_document_nesting=_ENGINE_LIMITS.max_document_nesting,
    max_yaml_aliases=_ENGINE_LIMITS.max_yaml_aliases,
)


def load_fixture(fixture_rel: str) -> dict:
    """Parse a JSON or YAML fixture with the engine's strict document parser.

    The explicit limits mirror the engine's ``InputLimits`` defaults so the
    corpus loader accepts exactly the documents the engine itself accepts.
    """
    return read_repository_document(
        FIXTURE_ROOT,
        fixture_rel,
        limits=_FIXTURE_DOCUMENT_LIMITS,
    ).value


def parse_fixture_text(fixture_rel: str) -> dict:
    """Parse a fixture permissively, without the engine's reference guards.

    ``test_no_remote_refs`` needs a loader that does not itself reject remote
    or absolute ``$ref`` targets, so its own assertions stay reachable as an
    independent guard.
    """
    path = FIXTURE_ROOT / fixture_rel
    text = path.read_text(encoding="utf-8")
    if path.suffix in (".yaml", ".yml"):
        return yaml.safe_load(text)
    return json.loads(text)


def manifest_validation_errors(manifest: dict) -> list:
    validator = Draft202012Validator(
        MANIFEST_SCHEMA,
        format_checker=FORMAT_CHECKER,
    )
    return list(validator.iter_errors(manifest))


@pytest.fixture(scope="session")
def corpus_engine_cache() -> dict[str, EngineResult]:
    """Run each immutable corpus fixture through the engine exactly once."""
    return build_engine_cache(FIXTURE_ROOT, FIXTURE_ENTRYPOINTS)


def build_engine_cache(
    fixture_root: Path,
    entrypoints: tuple[str, ...],
) -> dict[str, EngineResult]:
    """Evaluate manifest entrypoints; referenced resources stay inside closures."""
    cache: dict[str, EngineResult] = {}
    for fixture_rel in entrypoints:
        closure = build_input_closure(fixture_root, fixture_rel)
        validation = validate_openapi(closure)
        operation_set = normalize_operations(closure)
        evaluation = evaluate_agent_contract(operation_set)
        cache[fixture_rel] = (validation, operation_set, evaluation)
    return cache


def projected_evidence(finding: dict) -> list[dict]:
    projection = []
    for evidence in finding["evidence"]:
        item = {
            "kind": evidence["kind"],
            "value": evidence.get("value", evidence["description"]),
        }
        if "pointer" in evidence:
            item["pointer"] = evidence["pointer"]
        projection.append(item)
    return sorted(projection, key=rfc8785.dumps)


def projected_finding(finding: dict) -> dict:
    return {
        "ruleId": finding["ruleId"],
        "severity": finding["severity"],
        "locationPointer": finding["location"]["pointer"],
        "riskCategories": sorted(set(finding.get("riskCategories", []))),
        "evidence": projected_evidence(finding),
    }


def expected_finding_projection(finding: dict) -> dict:
    projection = {
        key: deepcopy(value) for key, value in finding.items() if key != "reviewers"
    }
    projection["riskCategories"] = sorted(set(projection["riskCategories"]))
    projection["evidence"] = sorted(projection["evidence"], key=rfc8785.dumps)
    return projection


def test_manifest_validates_against_schema() -> None:
    errors = manifest_validation_errors(MANIFEST)
    assert errors == [], [str(e) for e in errors]


def test_public_source_requires_provenance() -> None:
    candidate = deepcopy(MANIFEST)
    case = candidate["cases"][0]
    case["caseId"] = "pub-missing-provenance"
    case["sourceType"] = "public"
    case["provenance"] = None
    assert manifest_validation_errors(candidate), (
        "public source with null provenance must fail schema validation"
    )


def test_public_source_accepts_complete_provenance() -> None:
    candidate = deepcopy(MANIFEST)
    case = candidate["cases"][0]
    case["caseId"] = "pub-complete-provenance"
    case["sourceType"] = "public"
    case["provenance"] = {
        "sourceUrl": "https://example.com/openapi.json",
        "license": "Apache-2.0",
        "sourceRef": "0123456789abcdef",
        "modifications": "Reduced to one operation for deterministic coverage.",
    }
    assert manifest_validation_errors(candidate) == []


def test_synthetic_source_requires_null_provenance() -> None:
    candidate = deepcopy(MANIFEST)
    case = candidate["cases"][0]
    case["provenance"] = {
        "sourceUrl": "https://example.com/openapi.json",
        "license": "Apache-2.0",
        "sourceRef": "0123456789abcdef",
    }
    assert manifest_validation_errors(candidate), (
        "synthetic source with provenance metadata must fail schema validation"
    )


def test_case_ids_are_unique() -> None:
    ids = [case["caseId"] for case in CASES]
    assert len(ids) == len(set(ids))


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
    method_token = decode_pointer_token(pointer[last_slash + 1 :])
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
        document = parse_fixture_text(case["fixture"])
        for ref in iter_refs(document):
            assert isinstance(ref, str)
            target = ref.split("#", maxsplit=1)[0]
            parsed = urlsplit(target)
            assert not parsed.scheme and not parsed.netloc, (
                f"Remote $ref {ref!r} found in {case['fixture']}"
            )
            assert not target.startswith(("/", "\\")), (
                f"Absolute $ref {ref!r} found in {case['fixture']}"
            )


def test_local_ref_resources_are_not_independent_entrypoints(tmp_path: Path) -> None:
    shared = tmp_path / "shared"
    shared.mkdir()
    (shared / "problem.json").write_text(
        json.dumps(
            {
                "Problem": {
                    "type": "object",
                    "properties": {"message": {"type": "string"}},
                }
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "root.json").write_text(
        json.dumps(
            {
                "openapi": "3.1.0",
                "info": {"title": "Local ref", "version": "1.0.0"},
                "paths": {
                    "/items": {
                        "get": {
                            "responses": {
                                "400": {
                                    "description": "problem",
                                    "content": {
                                        "application/json": {
                                            "schema": {
                                                "$ref": "shared/problem.json#/Problem"
                                            }
                                        }
                                    },
                                }
                            }
                        }
                    }
                },
            }
        ),
        encoding="utf-8",
    )

    closure = build_input_closure(tmp_path, "root.json")
    cache = build_engine_cache(tmp_path, ("root.json",))

    assert {resource.path for resource in closure.resources} == {
        "root.json",
        "shared/problem.json",
    }
    assert tuple(cache) == ("root.json",)
    assert cache["root.json"][0].outcome == "valid"
    assert len(cache["root.json"][1].operations) == 1


def test_every_fixture_file_belongs_to_an_entrypoint_closure() -> None:
    fixture_files = {
        path.relative_to(FIXTURE_ROOT).as_posix()
        for path in FIXTURE_ROOT.rglob("*")
        if path.is_file()
    }
    closure_files = {
        resource.path
        for entrypoint in FIXTURE_ENTRYPOINTS
        for resource in build_input_closure(FIXTURE_ROOT, entrypoint).resources
    }

    assert fixture_files == closure_files, {
        "orphanResources": sorted(fixture_files - closure_files),
        "missingResources": sorted(closure_files - fixture_files),
    }


def test_all_corpus_fixtures_pass_closure_only_openapi_validation(
    corpus_engine_cache: dict[str, EngineResult],
) -> None:
    outcomes = {
        fixture_rel: {
            "outcome": validation.outcome,
            "diagnostics": [item.to_dict() for item in validation.diagnostics],
        }
        for fixture_rel, (validation, _, _) in corpus_engine_cache.items()
    }
    assert all(item["outcome"] == "valid" for item in outcomes.values()), outcomes


def test_manifest_and_normalized_operations_are_a_bijection(
    corpus_engine_cache: dict[str, EngineResult],
) -> None:
    manifest_operations = [
        (case["fixture"], case["operationPointer"]) for case in CASES
    ]
    normalized_operations = [
        (fixture_rel, operation.pointer)
        for fixture_rel, (_, operation_set, _) in corpus_engine_cache.items()
        for operation in operation_set.operations
    ]

    assert len(manifest_operations) == len(set(manifest_operations)), (
        "Each manifest operation must be represented exactly once"
    )
    assert len(normalized_operations) == len(set(normalized_operations)), (
        "Each normalized fixture operation must be unique"
    )
    assert set(manifest_operations) == set(normalized_operations), {
        "missingFromManifest": sorted(
            set(normalized_operations) - set(manifest_operations)
        ),
        "missingFromFixtures": sorted(
            set(manifest_operations) - set(normalized_operations)
        ),
    }


@pytest.mark.parametrize("case", CASES, ids=CASE_IDS)
def test_engine_results_match_manifest_expectations(
    case: dict,
    corpus_engine_cache: dict[str, EngineResult],
) -> None:
    _, operation_set, evaluation = corpus_engine_cache[case["fixture"]]
    operation = next(
        item
        for item in operation_set.operations
        if item.pointer == case["operationPointer"]
    )
    assert frozenset(operation.risk_categories) == frozenset(case["expectedRisks"])

    actual_findings = [
        projected_finding(finding.to_dict())
        for finding in evaluation.findings
        if finding.operation.method == operation.method
        and finding.operation.path == operation.path
    ]
    expected_findings = [
        expected_finding_projection(finding) for finding in case["expectedFindings"]
    ]
    assert sorted(actual_findings, key=rfc8785.dumps) == sorted(
        expected_findings,
        key=rfc8785.dumps,
    )


def test_expected_finding_projection_is_order_independent() -> None:
    original = next(
        finding
        for case in CASES
        for finding in case["expectedFindings"]
        if len(finding["riskCategories"]) > 1 and len(finding["evidence"]) > 1
    )
    reordered = deepcopy(original)
    reordered["riskCategories"].reverse()
    reordered["evidence"].reverse()

    assert expected_finding_projection(reordered) == expected_finding_projection(
        original
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
    by_rule = {
        rule_id: {"total": 0, "positive": 0, "negative": 0}
        for rule_id in sorted(ALLOWED_RULE_IDS)
    }
    dialects = MANIFEST_SCHEMA["$defs"]["case"]["properties"]["dialect"]["enum"]
    formats = MANIFEST_SCHEMA["$defs"]["case"]["properties"]["format"]["enum"]
    source_types = MANIFEST_SCHEMA["$defs"]["case"]["properties"]["sourceType"]["enum"]
    by_dialect = {dialect: 0 for dialect in dialects}
    by_format = {format_name: 0 for format_name in formats}
    by_source_type = {source_type: 0 for source_type in source_types}
    by_risk = {
        risk: {"total": 0, "positive": 0, "negative": 0}
        for risk in sorted(ALL_RISK_CATEGORIES)
    }

    for case in CASES:
        labels = set(case["caseLabels"])
        rule_counts = by_rule[case["ruleId"]]
        rule_counts["total"] += 1
        rule_counts["positive"] += int("positive" in labels)
        rule_counts["negative"] += int("negative" in labels)
        by_dialect[case["dialect"]] += 1
        by_format[case["format"]] += 1
        by_source_type[case["sourceType"]] += 1

        for risk in case["expectedRisks"]:
            by_risk[risk]["total"] += 1
            by_risk[risk]["positive"] += 1
        for risk in case["expectedNonRisks"]:
            by_risk[risk]["total"] += 1
            by_risk[risk]["negative"] += 1

    assert COVERAGE["byRule"] == by_rule
    assert COVERAGE["byDialect"] == by_dialect
    assert COVERAGE["byFormat"] == by_format
    assert COVERAGE["bySourceType"] == by_source_type
    assert COVERAGE["byRisk"] == by_risk
