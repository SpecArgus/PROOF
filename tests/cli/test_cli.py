from __future__ import annotations

import io
import json
from pathlib import Path

import pytest
from proof_cli import cli
from proof_rulepack import AGENT_CONTRACT_IDENTITY

EVALUATION_TIME = "2026-08-13T00:00:00Z"


def _config(path: Path, specifications: list[str], *, fail_on: str = "high") -> None:
    document = {
        "schemaVersion": "1.0.0",
        "specifications": specifications,
        "rulePack": AGENT_CONTRACT_IDENTITY.to_dict(),
        "failOn": fail_on,
    }
    if path.suffix == ".json":
        path.write_text(json.dumps(document), encoding="utf-8")
        return
    lines = [
        'schemaVersion: "1.0.0"',
        "specifications:",
        *(f'  - "{value}"' for value in specifications),
        "rulePack:",
        f'  name: "{AGENT_CONTRACT_IDENTITY.name}"',
        f'  version: "{AGENT_CONTRACT_IDENTITY.version}"',
        f'  digest: "{AGENT_CONTRACT_IDENTITY.digest}"',
        f'failOn: "{fail_on}"',
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _spec(path: Path, *, method: str = "get") -> None:
    operation = {
        "operationId": f"{method}Items",
        "summary": f"{method.title()} items",
        "responses": {"200": {"description": "ok"}},
    }
    if method == "delete":
        operation["responses"] = {
            "default": {
                "description": "problem",
                "content": {"application/json": {"schema": {"type": "object"}}},
            }
        }
    document = {
        "openapi": "3.1.0",
        "info": {"title": "CLI", "version": "1.0.0"},
        "paths": {"/items": {method: operation}},
    }
    if path.suffix == ".json":
        path.write_text(json.dumps(document), encoding="utf-8")
        return
    import yaml

    path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")


def _run(root: Path, *arguments: str) -> tuple[int, dict, str]:
    stdout = io.BytesIO()
    stderr = io.StringIO()
    code = cli.main(
        [
            "proof",
            "scan",
            "--repository",
            str(root),
            "--evaluation-time",
            EVALUATION_TIME,
            *arguments,
        ],
        stdout=stdout,
        stderr=stderr,
    )
    value = json.loads(stdout.getvalue()) if stdout.getvalue() else {}
    return code, value, stderr.getvalue()


@pytest.mark.parametrize(
    ("config_name", "spec_name"),
    (("proof.json", "api.json"), ("proof.yaml", "api.yaml")),
)
def test_json_and_yaml_complete_core_pass(
    tmp_path: Path, config_name: str, spec_name: str
) -> None:
    _spec(tmp_path / spec_name)
    _config(tmp_path / config_name, [spec_name], fail_on="none")

    code, result, error = _run(tmp_path, "--config", config_name)

    assert code == 0
    assert result["status"] == "completed"
    assert result["gate"]["outcome"] in {"pass", "advisory"}
    assert result["summary"]["scannedOperations"] == 1
    assert error == ""


@pytest.mark.parametrize("spec_name", ("bad.json", "bad.yaml"))
def test_blocked_finding_returns_exit_one(tmp_path: Path, spec_name: str) -> None:
    _spec(tmp_path / spec_name, method="delete")
    _config(tmp_path / "proof.json", [spec_name])

    code, result, _ = _run(tmp_path, "--config", "proof.json")

    assert code == 1
    assert result["status"] == "completed"
    assert result["gate"]["outcome"] == "blocked"


@pytest.mark.parametrize(
    ("arguments", "expected_code"),
    (
        (("--config", "missing.json"), "configuration.missing-file"),
        (
            ("--config", "proof.json", "missing-*.json"),
            "configuration.no-specification-match",
        ),
    ),
)
def test_missing_config_and_empty_glob_are_input_errors(
    tmp_path: Path, arguments: tuple[str, ...], expected_code: str
) -> None:
    if "proof.json" in arguments:
        _config(tmp_path / "proof.json", ["api.json"])

    code, result, _ = _run(tmp_path, *arguments)

    assert code == 2
    assert result["status"] == "input-error"
    assert result["errors"][0]["code"] == expected_code
    assert result["gate"]["outcome"] == "not-evaluated"


def test_invalid_specification_is_distinct_from_configuration_error(
    tmp_path: Path,
) -> None:
    (tmp_path / "invalid.json").write_text("{", encoding="utf-8")
    _config(tmp_path / "proof.json", ["invalid.json"])

    code, result, _ = _run(tmp_path, "--config", "proof.json")

    assert code == 2
    assert result["status"] == "input-error"
    assert result["errors"][0]["kind"] == "input"


def test_bad_config_empty_glob_and_missing_local_ref_have_distinct_codes(
    tmp_path: Path,
) -> None:
    (tmp_path / "bad-config.json").write_text("{", encoding="utf-8")
    bad_config = _run(tmp_path, "--config", "bad-config.json")

    _config(tmp_path / "proof.json", ["missing-*.json"])
    empty_glob = _run(tmp_path, "--config", "proof.json")

    missing_ref_document = {
        "openapi": "3.1.0",
        "info": {"title": "Missing", "version": "1.0.0"},
        "paths": {},
        "components": {"schemas": {"Missing": {"$ref": "missing.json#/Value"}}},
    }
    (tmp_path / "missing-ref.json").write_text(
        json.dumps(missing_ref_document), encoding="utf-8"
    )
    _config(tmp_path / "proof.json", ["missing-ref.json"])
    missing_ref = _run(tmp_path, "--config", "proof.json")

    assert bad_config[0] == empty_glob[0] == missing_ref[0] == 2
    assert bad_config[1]["errors"][0]["code"] == "configuration.invalid-document"
    assert empty_glob[1]["errors"][0]["code"] == (
        "configuration.no-specification-match"
    )
    assert missing_ref[1]["errors"][0]["code"] == "input.missing-file"


def test_output_path_receives_canonical_json(tmp_path: Path) -> None:
    _spec(tmp_path / "api.json")
    _config(tmp_path / "proof.json", ["api.json"], fail_on="none")
    output = tmp_path / "result.json"
    stdout = io.BytesIO()
    stderr = io.StringIO()

    code = cli.main(
        [
            "proof",
            "scan",
            "--repository",
            str(tmp_path),
            "--config",
            "proof.json",
            "--output",
            str(output),
            "--evaluation-time",
            EVALUATION_TIME,
        ],
        stdout=stdout,
        stderr=stderr,
    )

    assert code == 0
    assert stdout.getvalue() == b""
    assert json.loads(output.read_bytes())["status"] == "completed"
    assert output.read_bytes().endswith(b"\n")


def test_console_output_file_is_atomic_and_output_failure_is_sanitized(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _spec(tmp_path / "api.json", method="delete")
    _config(tmp_path / "proof.json", ["api.json"])
    output = tmp_path / "report.txt"
    output.write_bytes(b"previous report\n")

    def fail_replace(*_: object) -> None:
        raise OSError("SECRET host path")

    monkeypatch.setattr(cli.os, "replace", fail_replace)
    stdout = io.BytesIO()
    stderr = io.StringIO()
    code = cli.main(
        [
            "proof",
            "scan",
            "--repository",
            str(tmp_path),
            "--config",
            "proof.json",
            "--format",
            "console",
            "--output",
            str(output),
            "--evaluation-time",
            EVALUATION_TIME,
        ],
        stdout=stdout,
        stderr=stderr,
    )

    assert code == 3
    assert output.read_bytes() == b"previous report\n"
    assert stdout.getvalue() == b""
    assert stderr.getvalue() == "PROOF could not write the normalized result.\n"
    assert "SECRET" not in stderr.getvalue()
    assert not list(tmp_path.glob(".report.txt.*"))


def test_cli_overrides_are_atomic_and_invocation_labels_do_not_change_result(
    tmp_path: Path,
) -> None:
    _spec(tmp_path / "a.json")
    _spec(tmp_path / "b.yaml")
    _config(tmp_path / "proof.json", ["a.json"], fail_on="none")

    first = _run(
        tmp_path,
        "--config",
        "proof.json",
        "--fail-on",
        "none",
        "--git-ref",
        "sha:abc",
        "--policy-ref",
        "base:abc",
        "b.yaml",
    )
    second = _run(
        tmp_path,
        "--config",
        "proof.json",
        "--fail-on",
        "none",
        "--git-ref",
        "sha:def",
        "--policy-ref",
        "base:def",
        "b.yaml",
    )

    assert first[0] == second[0] == 0
    assert first[1] == second[1]
    assert first[1]["summary"]["scannedOperations"] == 1


def test_exact_rulepack_override_passes_and_wrong_digest_is_input_error(
    tmp_path: Path,
) -> None:
    _spec(tmp_path / "api.json")
    _config(tmp_path / "proof.json", ["api.json"], fail_on="none")
    identity = AGENT_CONTRACT_IDENTITY
    common = (
        "--config",
        "proof.json",
        "--rule-pack-name",
        identity.name,
        "--rule-pack-version",
        identity.version,
        "--rule-pack-digest",
    )

    exact = _run(tmp_path, *common, identity.digest)
    mismatch = _run(tmp_path, *common, "sha256:" + "0" * 64)

    assert exact[0] == 0
    assert mismatch[0] == 2
    assert mismatch[1]["errors"][0]["code"] == (
        "configuration.rulepack-digest-mismatch"
    )


def test_remote_reference_is_rejected_without_network_access(tmp_path: Path) -> None:
    document = {
        "openapi": "3.1.0",
        "info": {"title": "Remote", "version": "1.0.0"},
        "paths": {},
        "components": {
            "schemas": {"Remote": {"$ref": "https://127.0.0.1/canary.json"}}
        },
    }
    (tmp_path / "remote.json").write_text(json.dumps(document), encoding="utf-8")
    _config(tmp_path / "proof.json", ["remote.json"])

    code, result, _ = _run(tmp_path, "--config", "proof.json")

    assert code == 2
    assert result["status"] == "input-error"
    assert result["errors"][0]["code"] == "input.unsupported-reference"


def test_internal_failure_returns_exit_three_without_traceback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _spec(tmp_path / "api.json")
    _config(tmp_path / "proof.json", ["api.json"])

    def fail(**_: object) -> None:
        raise cli.RunAssemblyError("SECRET internal detail")

    monkeypatch.setattr(cli, "assemble_input_closure_run", fail)
    code, result, error = _run(tmp_path, "--config", "proof.json")

    assert code == 3
    assert result == {}
    assert error == "PROOF failed internally before producing a normalized result.\n"
    assert "SECRET" not in error


def test_invalid_evaluation_time_and_partial_rulepack_identity_return_two(
    tmp_path: Path,
) -> None:
    stdout = io.BytesIO()
    stderr = io.StringIO()
    invalid_time = cli.main(
        ["proof", "scan", "--evaluation-time", "2026-08-13T00:00:00+00:00"],
        stdout=stdout,
        stderr=stderr,
    )
    partial_identity = cli.main(
        ["proof", "scan", "--rule-pack-name", "agent-contract"],
        stdout=stdout,
        stderr=stderr,
    )

    assert invalid_time == partial_identity == 2
    assert b"Traceback" not in stdout.getvalue()


def test_output_cannot_overwrite_configuration_or_input(tmp_path: Path) -> None:
    _spec(tmp_path / "api.json")
    _config(tmp_path / "proof.json", ["api.json"])

    code, result, error = _run(
        tmp_path,
        "--config",
        "proof.json",
        "--output",
        str(tmp_path / "api.json"),
    )

    assert code == 3
    assert result == {}
    assert error == "PROOF failed internally before producing a normalized result.\n"

    config_code, config_result, config_error = _run(
        tmp_path,
        "--config",
        "proof.json",
        "--output",
        str(tmp_path / "proof.json"),
    )
    assert config_code == 3
    assert config_result == {}
    assert config_error == (
        "PROOF could not safely select the normalized output path.\n"
    )


def test_help_describes_static_boundary_and_default_gate(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as caught:
        cli.main(["proof", "scan", "--help"])

    output = capsys.readouterr().out
    assert caught.value.code == 0
    assert "never executes repository content" in output
    assert "Remote and file:" in output
    assert "rejected" in output
    assert "default configuration" in output
    assert "value: high" in output
