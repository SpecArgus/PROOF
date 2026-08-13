from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest
import rfc8785
from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
CONTRACT_ROOT = REPOSITORY_ROOT / "packages" / "contracts"
SCHEMA_ROOT = (
    CONTRACT_ROOT
    / "src"
    / "proof_contracts"
    / "schemas"
    / "result"
    / "v1"
)
EXAMPLE_ROOT = CONTRACT_ROOT / "examples" / "result" / "v1"

SCHEMA_FILES = {
    path.name: path
    for path in sorted(SCHEMA_ROOT.glob("*.schema.json"), key=lambda item: item.name)
}
SCHEMAS = {
    name: json.loads(path.read_text(encoding="utf-8"))
    for name, path in SCHEMA_FILES.items()
}

REGISTRY = Registry()
for schema in SCHEMAS.values():
    REGISTRY = REGISTRY.with_resource(
        schema["$id"],
        Resource.from_contents(schema),
    )

FORMAT_CHECKER = FormatChecker()
SEVERITY_RANK = {
    "error": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}
PUBLIC_CONTRACTS = {
    "finding",
    "gate",
    "provenance",
    "run",
}


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def schema_name_for_example(path: Path) -> str:
    prefix = path.name.split("-", maxsplit=1)[0].removesuffix(".json")
    return {
        "finding": "finding.schema.json",
        "gate": "gate.schema.json",
        "provenance": "provenance.schema.json",
        "run": "run.schema.json",
    }[prefix]


def validator(schema_name: str) -> Draft202012Validator:
    return Draft202012Validator(
        SCHEMAS[schema_name],
        registry=REGISTRY,
        format_checker=FORMAT_CHECKER,
    )


def projected_evidence(finding: dict) -> list[dict]:
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


def finding_fingerprint(finding: dict) -> str:
    projection = {
        "fingerprintVersion": 1,
        "source": finding["source"],
        "ruleId": finding["ruleId"],
        "location": {
            "path": finding["location"]["path"],
            "pointer": finding["location"]["pointer"],
        },
        "evidence": projected_evidence(finding),
    }
    if "operation" in finding:
        projection["operation"] = {
            "method": finding["operation"]["method"],
            "path": finding["operation"]["path"],
        }
    if finding.get("riskCategories"):
        projection["riskCategories"] = sorted(finding["riskCategories"])
    return f"sha256:{hashlib.sha256(rfc8785.dumps(projection)).hexdigest()}"


def normalized_result_digest(run: dict) -> str:
    digest_input = copy.deepcopy(run)
    digest_input.pop("resultDigest")
    return f"sha256:{hashlib.sha256(rfc8785.dumps(digest_input)).hexdigest()}"


def finding_sort_key(finding: dict) -> tuple:
    location = finding["location"]
    return (
        SEVERITY_RANK[finding["severity"]],
        finding["source"],
        finding["ruleId"],
        location["path"],
        location["pointer"],
        finding["fingerprint"],
    )


def error_sort_key(error: dict) -> tuple:
    location = error.get("location", {})
    return (
        error["kind"],
        error["code"],
        location.get("path", ""),
        location.get("pointer", ""),
        error["message"],
    )


@pytest.mark.parametrize("schema_name", sorted(SCHEMAS))
def test_schemas_are_valid_draft_2020_12(schema_name: str) -> None:
    schema = SCHEMAS[schema_name]
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    Draft202012Validator.check_schema(schema)


def test_schema_identifiers_are_unique_and_versioned() -> None:
    identifiers = [schema["$id"] for schema in SCHEMAS.values()]
    assert len(identifiers) == len(set(identifiers))
    assert all("/schemas/result/v1/" in identifier for identifier in identifiers)


def test_each_public_contract_has_valid_and_invalid_examples() -> None:
    for example_kind in ("valid", "invalid"):
        represented_contracts = {
            path.name.split("-", maxsplit=1)[0].removesuffix(".json")
            for path in (EXAMPLE_ROOT / example_kind).glob("*.json")
        }
        assert represented_contracts == PUBLIC_CONTRACTS


@pytest.mark.parametrize(
    "example_path",
    sorted((EXAMPLE_ROOT / "valid").glob("*.json"), key=lambda item: item.name),
    ids=lambda path: path.name,
)
def test_valid_examples_match_their_contract(example_path: Path) -> None:
    instance = load_json(example_path)
    contract = validator(schema_name_for_example(example_path))
    errors = list(contract.iter_errors(instance))
    assert errors == []


@pytest.mark.parametrize(
    "example_path",
    sorted((EXAMPLE_ROOT / "invalid").glob("*.json"), key=lambda item: item.name),
    ids=lambda path: path.name,
)
def test_invalid_examples_are_rejected(example_path: Path) -> None:
    instance = load_json(example_path)
    contract = validator(schema_name_for_example(example_path))
    errors = list(contract.iter_errors(instance))
    assert errors, f"{example_path.name} unexpectedly passed validation"


def test_extensions_do_not_weaken_required_fields() -> None:
    finding = load_json(EXAMPLE_ROOT / "valid" / "finding.json")
    finding["x-example-data"] = {"stable": True}
    assert validator("finding.schema.json").is_valid(finding)

    with_unknown_standard_field = copy.deepcopy(finding)
    with_unknown_standard_field["unexpected"] = True
    assert not validator("finding.schema.json").is_valid(
        with_unknown_standard_field
    )

    without_evidence = copy.deepcopy(finding)
    without_evidence.pop("evidence")
    assert not validator("finding.schema.json").is_valid(without_evidence)


@pytest.mark.parametrize(
    "invalid_path",
    [
        "/tmp/repository/openapi.yaml",
        "../outside/openapi.yaml",
        "api/../../outside/openapi.yaml",
        "C:\\work\\repository\\openapi.yaml",
    ],
)
def test_locations_reject_host_and_escaping_paths(invalid_path: str) -> None:
    finding = load_json(EXAMPLE_ROOT / "valid" / "finding.json")
    finding["location"]["path"] = invalid_path
    assert not validator("finding.schema.json").is_valid(finding)


def test_high_threshold_allows_medium_finding_to_be_advisory() -> None:
    run = load_json(EXAMPLE_ROOT / "valid" / "run-blocked.json")
    run["findings"][0]["severity"] = "medium"
    run["summary"]["findingsBySeverity"]["high"] = 0
    run["summary"]["findingsBySeverity"]["medium"] = 1
    run["gate"]["outcome"] = "advisory"
    run["gate"]["failOn"] = "high"
    run["resultDigest"] = normalized_result_digest(run)

    assert validator("run.schema.json").is_valid(run)


def test_pass_and_advisory_gate_causes_are_constrained() -> None:
    advisory_with_cause = load_json(EXAMPLE_ROOT / "valid" / "gate.json")
    fingerprint = advisory_with_cause["causingFindingFingerprints"][0]
    pass_without_cause = {
        "outcome": "pass",
        "failOn": "high",
        "causingFindingFingerprints": [],
    }

    pass_with_cause = {
        **pass_without_cause,
        "causingFindingFingerprints": [fingerprint],
    }
    advisory_without_cause = {
        **advisory_with_cause,
        "causingFindingFingerprints": [],
    }

    assert validator("gate.schema.json").is_valid(pass_without_cause)
    assert validator("gate.schema.json").is_valid(advisory_with_cause)
    assert not validator("gate.schema.json").is_valid(pass_with_cause)
    assert not validator("gate.schema.json").is_valid(advisory_without_cause)


@pytest.mark.parametrize(
    "example_path",
    sorted(
        (EXAMPLE_ROOT / "valid").glob("run-*.json"),
        key=lambda item: item.name,
    ),
    ids=lambda path: path.name,
)
def test_run_examples_have_consistent_counts_and_canonical_order(
    example_path: Path,
) -> None:
    run = load_json(example_path)
    summary = run["summary"]

    assert summary["findingTotal"] == len(run["findings"])
    assert summary["errorTotal"] == len(run["errors"])
    assert sum(summary["findingsBySeverity"].values()) == len(run["findings"])
    assert run["findings"] == sorted(run["findings"], key=finding_sort_key)
    assert run["errors"] == sorted(run["errors"], key=error_sort_key)
    assert run["gate"]["causingFindingFingerprints"] == sorted(
        run["gate"]["causingFindingFingerprints"]
    )


@pytest.mark.parametrize(
    "example_path",
    [
        EXAMPLE_ROOT / "valid" / "finding.json",
        EXAMPLE_ROOT / "valid" / "run-blocked.json",
    ],
    ids=lambda path: path.name,
)
def test_finding_examples_use_the_specified_fingerprint(example_path: Path) -> None:
    instance = load_json(example_path)
    findings = instance["findings"] if "findings" in instance else [instance]
    for finding in findings:
        assert finding["fingerprint"] == finding_fingerprint(finding)


@pytest.mark.parametrize(
    "example_path",
    sorted(
        (EXAMPLE_ROOT / "valid").glob("run-*.json"),
        key=lambda item: item.name,
    ),
    ids=lambda path: path.name,
)
def test_run_examples_use_the_specified_result_digest(example_path: Path) -> None:
    run = load_json(example_path)
    assert run["resultDigest"] == normalized_result_digest(run)
