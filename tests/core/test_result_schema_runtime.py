from __future__ import annotations

import copy
import json
from pathlib import Path
from types import MappingProxyType

import pytest
from proof_core.result_schema import ResultSchemaError, validate_normalized_run

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
EXAMPLE_ROOT = (
    REPOSITORY_ROOT / "packages" / "contracts" / "examples" / "result" / "v1"
)


def load_json(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def embed_contract_example_in_run(example_path: Path) -> dict[str, object]:
    instance = load_json(example_path)
    contract = example_path.name.split("-", maxsplit=1)[0].removesuffix(".json")
    if contract == "run":
        return instance

    run = load_json(EXAMPLE_ROOT / "valid" / "run-pass.json")
    if contract == "finding":
        run["findings"] = [instance]
    elif contract in {"gate", "provenance"}:
        run[contract] = instance
    else:  # pragma: no cover - the example set is contract-controlled
        raise AssertionError(f"unsupported result contract example: {contract}")
    return run


@pytest.mark.parametrize(
    "example_path",
    sorted(
        (EXAMPLE_ROOT / "valid").glob("*.json"),
        key=lambda item: item.name,
    ),
    ids=lambda path: path.name,
)
def test_valid_contract_examples_pass_in_normalized_run(example_path: Path) -> None:
    validate_normalized_run(embed_contract_example_in_run(example_path))


@pytest.mark.parametrize(
    "example_path",
    sorted(
        (EXAMPLE_ROOT / "invalid").glob("*.json"),
        key=lambda item: item.name,
    ),
    ids=lambda path: path.name,
)
def test_invalid_contract_examples_fail_in_normalized_run(example_path: Path) -> None:
    with pytest.raises(ResultSchemaError) as captured:
        validate_normalized_run(embed_contract_example_in_run(example_path))

    assert captured.value.code == "result-schema.invalid-run"


def test_runtime_registry_resolves_transitive_finding_contract() -> None:
    run = load_json(EXAMPLE_ROOT / "valid" / "run-blocked.json")
    findings = run["findings"]
    assert isinstance(findings, list)
    finding = findings[0]
    assert isinstance(finding, dict)
    finding["location"]["path"] = "C:\\private\\repository\\openapi.yaml"

    with pytest.raises(ResultSchemaError) as captured:
        validate_normalized_run(run)

    error = captured.value
    assert error.pointer == "/findings/0/location/path"
    assert error.keyword == "pattern"
    assert "C:\\private" not in str(error)


def test_runtime_registry_resolves_transitive_provenance_contract() -> None:
    run = load_json(EXAMPLE_ROOT / "valid" / "run-pass.json")
    provenance = run["provenance"]
    assert isinstance(provenance, dict)
    validator = provenance["validator"]
    assert isinstance(validator, dict)
    validator.pop("digest")

    with pytest.raises(ResultSchemaError) as captured:
        validate_normalized_run(run)

    assert captured.value.pointer == "/provenance/validator"
    assert captured.value.keyword == "required"


def test_runtime_validation_enforces_date_time_format() -> None:
    run = load_json(EXAMPLE_ROOT / "valid" / "run-pass.json")
    run["evaluationTime"] = "not-a-date-time"

    with pytest.raises(ResultSchemaError) as captured:
        validate_normalized_run(run)

    assert captured.value.pointer == "/evaluationTime"
    assert captured.value.keyword == "format"


def test_runtime_validation_accepts_read_only_mapping() -> None:
    run = load_json(EXAMPLE_ROOT / "valid" / "run-pass.json")
    validate_normalized_run(MappingProxyType(run))


def test_error_does_not_expose_rejected_value_or_host_path() -> None:
    run = load_json(EXAMPLE_ROOT / "valid" / "run-pass.json")
    hostile = copy.deepcopy(run)
    hostile["evaluationTime"] = "D:\\secret\\repository\\spec.yaml"

    with pytest.raises(ResultSchemaError) as captured:
        validate_normalized_run(hostile)

    error = captured.value
    assert str(error) == "normalized run does not satisfy result schema"
    assert "secret" not in str(error)
    assert vars(error) == {
        "code": "result-schema.invalid-run",
        "pointer": "/evaluationTime",
        "keyword": "format",
    }
