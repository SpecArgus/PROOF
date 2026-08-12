from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = (
    REPOSITORY_ROOT
    / "packages"
    / "contracts"
    / "src"
    / "proof_contracts"
    / "schemas"
    / "config"
    / "v1"
    / "config.schema.json"
)
EXAMPLE_ROOT = (
    REPOSITORY_ROOT / "packages" / "contracts" / "examples" / "config" / "v1"
)


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


SCHEMA = load_json(SCHEMA_PATH)
VALIDATOR = Draft202012Validator(SCHEMA)
EXPECTED_INVALID_EXAMPLES = {
    "config-bad-extension.json",
    "config-bad-rulepack-digest.json",
    "config-device-selector.json",
    "config-empty-segment-selector.json",
    "config-empty-specifications.json",
    "config-invalid-fail-on.json",
    "config-invalid-scope.json",
    "config-invalid-selector.json",
    "config-missing-required.json",
    "config-missing-rulepack-name.json",
    "config-missing-rulepack-version.json",
    "config-unknown-field.json",
    "config-unsupported-version.json",
    "config-wrong-type.json",
}


def test_schema_is_valid_draft_2020_12() -> None:
    assert SCHEMA["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert "/schemas/config/v1/" in SCHEMA["$id"]
    Draft202012Validator.check_schema(SCHEMA)


@pytest.mark.parametrize(
    "example_path",
    sorted((EXAMPLE_ROOT / "valid").glob("*.json")),
    ids=lambda path: path.name,
)
def test_valid_examples_match_contract(example_path: Path) -> None:
    assert list(VALIDATOR.iter_errors(load_json(example_path))) == []


@pytest.mark.parametrize(
    "example_path",
    sorted((EXAMPLE_ROOT / "invalid").glob("*.json")),
    ids=lambda path: path.name,
)
def test_invalid_examples_are_rejected(example_path: Path) -> None:
    assert list(VALIDATOR.iter_errors(load_json(example_path)))


def test_schema_defaults_match_p0_policy() -> None:
    assert SCHEMA["properties"]["failOn"]["default"] == "high"
    assert SCHEMA["properties"]["scope"]["default"] == "all"
    assert SCHEMA["properties"]["scope"]["const"] == "all"


def test_invalid_examples_cover_every_field_and_default_boundary() -> None:
    assert {path.name for path in (EXAMPLE_ROOT / "invalid").glob("*.json")} == (
        EXPECTED_INVALID_EXAMPLES
    )


@pytest.mark.parametrize(
    "selector",
    [
        "CON.json",
        "api/COM1.yaml",
        "api//openapi.json",
        "api/trailing./openapi.json",
        "api/[ab].json",
        "api/OPENAPI.JSON",
        "api/.json",
        "...json",
    ],
)
def test_schema_rejects_non_portable_selector_boundaries(selector: str) -> None:
    example = load_json(EXAMPLE_ROOT / "valid" / "config-minimal.json")
    example["specifications"] = [selector]
    assert list(VALIDATOR.iter_errors(example))


def test_schema_and_runtime_selector_boundaries_stay_aligned() -> None:
    valid = load_json(EXAMPLE_ROOT / "valid" / "config-minimal.json")
    selectors = [
        "openapi.json",
        "api/**/*.yaml",
        "api/.json",
        "...json",
        "a" * 507 + ".json",
        "a" * 508 + ".json",
    ]
    for selector in selectors:
        candidate = dict(valid)
        candidate["specifications"] = [selector]
        schema_valid = not list(VALIDATOR.iter_errors(candidate))
        runtime_valid = (
            selector not in {"api/.json", "...json"} and len(selector) <= 512
        )
        assert schema_valid is runtime_valid
