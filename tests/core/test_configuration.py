from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from proof_contracts.schemas.result.v1 import __path__ as result_schema_paths
from proof_core import (
    ConfigurationError,
    ConfigurationLimits,
    EffectiveScanConfiguration,
    ScanConfigurationOverrides,
    load_scan_configuration,
    match_specifications,
    resolve_local_scan_configuration,
    resolve_scan_configuration,
)
from proof_rulepack import AGENT_CONTRACT_IDENTITY, RulePackIdentity


def source_config(**changes: object) -> dict:
    value = {
        "schemaVersion": "1.0.0",
        "specifications": ["openapi.json"],
        "rulePack": AGENT_CONTRACT_IDENTITY.to_dict(),
    }
    value.update(changes)
    return value


def write_text(root: Path, path: str, content: str) -> None:
    target = root.joinpath(*path.split("/"))
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")


def test_defaults_are_materialized_and_digest_is_stable() -> None:
    minimal = resolve_scan_configuration(source_config())
    explicit = resolve_scan_configuration(
        source_config(failOn="high", scope="all")
    )

    assert minimal.content_dict() == explicit.content_dict()
    assert minimal.digest == explicit.digest
    assert minimal.provenance_dict() == {"digest": minimal.digest}
    assert minimal.digest == (
        "sha256:e247295cd1d0f9c5925a7805e553240f875b1d28c5b1f0437545619d4c85a532"
    )
    assert minimal.canonical_bytes() == (
        b'{"failOn":"high","rulePack":{"digest":"sha256:'
        b'6ee271830ad74f69f77bc83bc6d783020e4e895408ea1dee4bd332139e3ff71b",'
        b'"name":"agent-contract","version":"0.1.0"},"schemaVersion":"1.0.0",'
        b'"scope":"all","specifications":["openapi.json"]}'
    )


def test_non_canonical_direct_input_is_a_configuration_error() -> None:
    with pytest.raises(ConfigurationError) as caught:
        resolve_scan_configuration(source_config(**{"x-example": float("nan")}))

    assert caught.value.code == "configuration.non-canonical"


def test_semantic_json_and_yaml_have_the_same_effective_identity(
    tmp_path: Path,
) -> None:
    identity = AGENT_CONTRACT_IDENTITY.to_dict()
    write_text(
        tmp_path,
        "proof.json",
        json.dumps(
            {
                "rulePack": identity,
                "specifications": ["z.yaml", "a.json"],
                "schemaVersion": "1.0.0",
                "x-example": {"b": 2, "a": 1},
            },
            indent=2,
        ),
    )
    write_text(
        tmp_path,
        "proof.yaml",
        """schemaVersion: 1.0.0
specifications:
  - a.json
  - z.yaml
rulePack:
  digest: sha256:6ee271830ad74f69f77bc83bc6d783020e4e895408ea1dee4bd332139e3ff71b
  version: 0.1.0
  name: agent-contract
x-example:
  a: 1
  b: 2
""",
    )

    json_config = load_scan_configuration(tmp_path, "proof.json")
    yaml_config = load_scan_configuration(tmp_path, "proof.yaml")

    assert json_config.canonical_bytes() == yaml_config.canonical_bytes()
    assert json_config.digest == yaml_config.digest


def test_configuration_does_not_follow_extension_ref(tmp_path: Path) -> None:
    write_text(
        tmp_path,
        "proof.json",
        json.dumps(source_config(**{"x-example": {"$ref": "missing.json"}})),
    )

    config = load_scan_configuration(tmp_path, "proof.json")

    assert config.content_dict()["x-example"] == {"$ref": "missing.json"}


@pytest.mark.parametrize(
    ("changes", "code"),
    [
        ({"schemaVersion": "2.0.0"}, "configuration.unsupported-version"),
        ({"fialOn": "high"}, "configuration.unknown-field"),
        ({"specifications": []}, "configuration.empty-specifications"),
        (
            {"rulePack": {**AGENT_CONTRACT_IDENTITY.to_dict(), "extra": True}},
            "configuration.unknown-field",
        ),
        ({"X-example": True}, "configuration.unknown-field"),
        ({"specifications": ["../openapi.json"]}, "configuration.invalid-selector"),
    ],
)
def test_invalid_fields_have_stable_sanitized_errors(
    changes: dict, code: str
) -> None:
    with pytest.raises(ConfigurationError) as caught:
        resolve_scan_configuration(source_config(**changes), path="proof.yaml")

    assert caught.value.code == code
    assert caught.value.path == "proof.yaml"
    assert "D:\\" not in str(caught.value)
    assert caught.value.to_terminal_error()["kind"] == "configuration"


def test_configuration_error_matches_result_terminal_error_contract() -> None:
    schema_root = Path(next(iter(result_schema_paths)))
    common = json.loads(
        (schema_root / "common.schema.json").read_text(encoding="utf-8")
    )
    terminal_schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$defs": common["$defs"],
        "$ref": "#/$defs/terminalError",
    }
    error = ConfigurationError(
        "configuration.invalid-field",
        "configuration contains an invalid field",
        path="proof.yaml",
        pointer="/failOn",
    )

    Draft202012Validator(terminal_schema).validate(error.to_terminal_error())


def test_rulepack_release_and_digest_fail_differently() -> None:
    unknown = RulePackIdentity(
        "unknown", AGENT_CONTRACT_IDENTITY.version, AGENT_CONTRACT_IDENTITY.digest
    )
    mismatched = RulePackIdentity(
        AGENT_CONTRACT_IDENTITY.name,
        AGENT_CONTRACT_IDENTITY.version,
        f"sha256:{'0' * 64}",
    )

    with pytest.raises(ConfigurationError, match="unsupported") as release_error:
        resolve_scan_configuration(source_config(rulePack=unknown.to_dict()))
    with pytest.raises(ConfigurationError, match="does not match") as digest_error:
        resolve_scan_configuration(source_config(rulePack=mismatched.to_dict()))

    assert release_error.value.code == "configuration.unsupported-rulepack"
    assert digest_error.value.code == "configuration.rulepack-digest-mismatch"
    assert mismatched.digest not in str(digest_error.value)


def test_explicit_overrides_replace_source_values_atomically() -> None:
    document = source_config(
        specifications=["source.json"],
        failOn="medium",
    )
    original = copy.deepcopy(document)
    overrides = ScanConfigurationOverrides(
        specifications=("override.yaml", "override.yaml"),
        rule_pack=AGENT_CONTRACT_IDENTITY,
        fail_on="none",
    )

    effective = resolve_local_scan_configuration(document, overrides=overrides)

    assert document == original
    assert effective.specifications == ("override.yaml",)
    assert effective.fail_on == "none"


@pytest.mark.parametrize(
    "overrides",
    [
        ScanConfigurationOverrides(specifications="openapi.json"),
        ScanConfigurationOverrides(rule_pack="agent-contract"),
        ScanConfigurationOverrides(fail_on="critical"),
    ],
)
def test_invalid_overrides_are_configuration_errors(
    overrides: ScanConfigurationOverrides,
) -> None:
    with pytest.raises(ConfigurationError):
        resolve_local_scan_configuration(source_config(), overrides=overrides)


def test_local_override_cannot_exceed_selector_length_contract() -> None:
    override = ScanConfigurationOverrides(specifications=("a" * 508 + ".json",))

    with pytest.raises(ConfigurationError) as caught:
        resolve_local_scan_configuration(source_config(), overrides=override)

    assert caught.value.code == "configuration.invalid-selector"


@pytest.mark.parametrize(
    "changes",
    [
        {"specifications": ()},
        {"fail_on": "critical"},
        {"schema_version": "2.0.0"},
        {"scope": "changed-only"},
        {"extensions": {"failOn": "none"}},
    ],
)
def test_effective_model_cannot_bypass_contract(changes: dict) -> None:
    arguments = {
        "specifications": ("openapi.json",),
        "rule_pack": AGENT_CONTRACT_IDENTITY,
        "fail_on": "high",
        "extensions": {},
    }
    arguments.update(changes)

    with pytest.raises(ConfigurationError):
        EffectiveScanConfiguration(**arguments)


@pytest.mark.parametrize(
    "unsafe_path",
    [
        r"C:\private\proof.yaml",
        r"\\server\share\proof.yaml",
        "/private/proof.yaml",
        "../proof.yaml",
        "",
    ],
)
def test_resolver_never_emits_unsafe_source_path(unsafe_path: str) -> None:
    with pytest.raises(ConfigurationError) as caught:
        resolve_scan_configuration(
            source_config(fialOn="high"),
            path=unsafe_path,
        )

    terminal = caught.value.to_terminal_error()
    assert "location" not in terminal
    if unsafe_path:
        assert unsafe_path not in json.dumps(terminal)


def test_failed_attempt_has_deterministic_provenance_identity() -> None:
    overrides = ScanConfigurationOverrides(fail_on="none")

    with pytest.raises(ConfigurationError) as first:
        resolve_local_scan_configuration(
            source_config(fialOn="high"),
            source_digest=f"sha256:{'1' * 64}",
            overrides=overrides,
        )
    with pytest.raises(ConfigurationError) as repeated:
        resolve_local_scan_configuration(
            source_config(fialOn="high"),
            source_digest=f"sha256:{'1' * 64}",
            overrides=overrides,
        )
    with pytest.raises(ConfigurationError) as changed:
        resolve_local_scan_configuration(
            source_config(fialOn="high"),
            source_digest=f"sha256:{'2' * 64}",
            overrides=overrides,
        )

    assert first.value.provenance_dict() == repeated.value.provenance_dict()
    assert first.value.provenance_dict() != changed.value.provenance_dict()
    assert first.value.configuration_digest.startswith("sha256:")


def test_extension_values_are_immutable_and_change_digest() -> None:
    extension = {"items": [1, {"enabled": True}]}
    first = resolve_scan_configuration(source_config(**{"x-example": extension}))
    second = resolve_scan_configuration(
        source_config(**{"x-example": {"items": [1, {"enabled": False}]}})
    )
    extension["items"].append(2)

    assert first.content_dict()["x-example"] == {
        "items": [1, {"enabled": True}]
    }
    assert first.digest != second.digest


@pytest.mark.parametrize(
    "content",
    [
        b'\xef\xbb\xbf{"schemaVersion":"1.0.0"}',
        b'{"schemaVersion":"1.0.0","schemaVersion":"1.0.0"}',
        b"schemaVersion: 1.0.0\nschemaVersion: 1.0.0\n",
        b"a: 1\n---\nb: 2\n",
        b"base: &base {a: 1}\nmerged: {<<: *base}\n",
    ],
)
def test_strict_parser_rejects_ambiguous_documents(
    tmp_path: Path, content: bytes
) -> None:
    (tmp_path / "proof.yaml").write_bytes(content)

    with pytest.raises(ConfigurationError) as caught:
        load_scan_configuration(tmp_path, "proof.yaml")

    assert caught.value.source_digest is not None
    assert str(tmp_path) not in str(caught.value)


def test_matching_is_sorted_deduplicated_and_each_selector_must_match(
    tmp_path: Path,
) -> None:
    write_text(tmp_path, "api/a.json", "{}")
    write_text(tmp_path, "api/nested/z.yaml", "{}")
    write_text(tmp_path, "api/readme.txt", "ignored")
    write_text(tmp_path, ".git/private.json", "{}")
    config = resolve_scan_configuration(
        source_config(specifications=["api/**/*.yaml", "api/*.json"])
    )

    assert match_specifications(tmp_path, config) == (
        "api/a.json",
        "api/nested/z.yaml",
    )

    missing = resolve_scan_configuration(
        source_config(specifications=["api/*.json", "missing/*.yaml"])
    )
    with pytest.raises(ConfigurationError) as caught:
        match_specifications(tmp_path, missing)
    assert caught.value.code == "configuration.no-specification-match"


def test_matching_does_not_traverse_directory_links(tmp_path: Path) -> None:
    external = tmp_path.parent / f"{tmp_path.name}-external"
    external.mkdir()
    write_text(external, "secret.json", "{}")
    linked = tmp_path / "linked"
    try:
        linked.symlink_to(external, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlinks are unavailable on this platform")
    config = resolve_scan_configuration(source_config(specifications=["**/*.json"]))

    with pytest.raises(ConfigurationError) as caught:
        match_specifications(tmp_path, config)

    assert caught.value.code == "configuration.no-specification-match"


def test_match_limit_is_enforced(tmp_path: Path) -> None:
    for index in range(3):
        write_text(tmp_path, f"api/{index}.json", "{}")
    config = resolve_scan_configuration(source_config(specifications=["api/*.json"]))

    with pytest.raises(ConfigurationError) as caught:
        match_specifications(
            tmp_path,
            config,
            limits=ConfigurationLimits(max_matches=2),
        )

    assert caught.value.code == "configuration.specification-match-limit"


def test_repository_failure_preserves_effective_configuration_identity(
    tmp_path: Path,
) -> None:
    configuration = resolve_scan_configuration(source_config())

    with pytest.raises(ConfigurationError) as caught:
        match_specifications(tmp_path / "missing", configuration)

    assert caught.value.code == "configuration.invalid-repository-root"
    assert caught.value.provenance_dict() == configuration.provenance_dict()
