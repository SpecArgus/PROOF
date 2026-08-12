from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import proof_core
import pytest
from proof_core.configuration import ConfigurationError, resolve_scan_configuration
from proof_core.input_closure import InputClosureError, build_input_closure
from proof_core.operation_normalization import normalize_operations
from proof_core.run_assembly import (
    EntrypointAnalysis,
    RunAssemblyError,
    analysis_artifacts_v1,
    assemble_analysis_run,
    assemble_completed_run,
    assemble_configuration_error_run,
    assemble_input_closure_run,
    assemble_input_error_run,
    assemble_worker_error_run,
    evaluate_gate,
    finding_fingerprint,
    input_attempt_identity,
    normalize_rule_findings,
    normalize_validator_findings,
)
from proof_core.validator_client import (
    ValidatorDiagnostic,
    ValidatorResult,
    WorkerFailure,
)
from proof_rulepack import (
    AGENT_CONTRACT_IDENTITY,
    RuleEvaluation,
    evaluate_agent_contract,
)

EVALUATION_TIME = "2026-08-12T00:00:00Z"
ARTIFACTS = analysis_artifacts_v1()


def _configuration(*entrypoints: str, fail_on: str = "high"):
    return resolve_scan_configuration(
        {
            "schemaVersion": "1.0.0",
            "specifications": list(entrypoints),
            "rulePack": AGENT_CONTRACT_IDENTITY.to_dict(),
            "failOn": fail_on,
        }
    )


def _write_spec(root: Path, path: str, operation: dict) -> None:
    target = root.joinpath(*path.split("/"))
    target.parent.mkdir(parents=True, exist_ok=True)
    document = {
        "openapi": "3.1.0",
        "info": {"title": "Assembly", "version": "1.0.0"},
        "paths": {"/items": operation},
    }
    target.write_text(json.dumps(document), encoding="utf-8")


def _analysis(closure, entrypoint: str) -> EntrypointAnalysis:
    operations = normalize_operations(closure, entrypoint)
    return EntrypointAnalysis(
        validator=ValidatorResult(
            entrypoint=entrypoint,
            manifest_digest=closure.manifest.digest,
            outcome="valid",
            diagnostics=(),
            diagnostics_observed=0,
            diagnostics_truncated=0,
        ),
        operations=operations,
        rules=evaluate_agent_contract(operations),
    )


def _assemble(root: Path, path: str, operation: dict, *, fail_on: str = "high"):
    _write_spec(root, path, operation)
    closure = build_input_closure(root, path)
    return assemble_completed_run(
        evaluation_time=EVALUATION_TIME,
        configuration=_configuration(path, fail_on=fail_on),
        input_manifest=closure.manifest,
        analyses=(_analysis(closure, path),),
        artifacts=ARTIFACTS,
    )


def test_default_high_threshold_emits_medium_only_as_advisory(tmp_path: Path) -> None:
    run = _assemble(
        tmp_path,
        "api/medium.json",
        {"get": {"responses": {"200": {"description": "ok"}}}},
    )

    value = run.to_dict()
    assert [finding["severity"] for finding in value["findings"]] == ["medium"]
    assert value["gate"] == {
        "outcome": "advisory",
        "failOn": "high",
        "causingFindingFingerprints": [value["findings"][0]["fingerprint"]],
    }


def test_default_high_threshold_blocks_high_finding(tmp_path: Path) -> None:
    run = _assemble(
        tmp_path,
        "api/high.json",
        {
            "delete": {
                "operationId": "deleteItem",
                "summary": "Delete item",
                "responses": {
                    "default": {
                        "description": "problem",
                        "content": {"application/json": {"schema": {"type": "object"}}},
                    }
                },
            }
        },
    )

    value = run.to_dict()
    assert value["gate"]["outcome"] == "blocked"
    assert value["gate"]["causingFindingFingerprints"] == sorted(
        finding["fingerprint"]
        for finding in value["findings"]
        if finding["severity"] in {"error", "high"}
    )


def test_completed_pass_is_byte_stable_and_digest_excludes_itself(
    tmp_path: Path,
) -> None:
    operation = {
        "get": {
            "operationId": "getItems",
            "summary": "Get items",
            "responses": {"200": {"description": "ok"}},
        }
    }
    first = _assemble(tmp_path, "api/pass.json", operation)
    second = _assemble(tmp_path, "api/pass.json", operation)
    content = first.to_dict()
    digest = content.pop("resultDigest")

    from proof_core.canonical_json import content_digest

    assert first.canonical_bytes() == second.canonical_bytes()
    assert digest == content_digest(content)
    assert first.to_dict()["gate"]["outcome"] == "pass"


def test_multi_entrypoint_order_does_not_change_result(tmp_path: Path) -> None:
    operation = {
        "get": {
            "operationId": "getItems",
            "summary": "Get items",
            "responses": {"200": {"description": "ok"}},
        }
    }
    _write_spec(tmp_path, "a.json", operation)
    _write_spec(tmp_path, "b.json", operation)
    closure = build_input_closure(tmp_path, ("a.json", "b.json"))
    analyses = (_analysis(closure, "a.json"), _analysis(closure, "b.json"))
    arguments = {
        "evaluation_time": EVALUATION_TIME,
        "configuration": _configuration("a.json", "b.json"),
        "input_manifest": closure.manifest,
        "artifacts": ARTIFACTS,
    }

    first = assemble_completed_run(analyses=analyses, **arguments)
    second = assemble_completed_run(analyses=tuple(reversed(analyses)), **arguments)

    assert first.canonical_bytes() == second.canonical_bytes()
    assert first.to_dict()["summary"]["scannedOperations"] == 2


def test_public_assembler_derives_layers_from_closure_and_hides_low_level_api(
    tmp_path: Path,
) -> None:
    operation = {
        "delete": {
            "operationId": "deleteItem",
            "summary": "Delete item",
            "responses": {
                "default": {
                    "description": "problem",
                    "content": {"application/json": {"schema": {"type": "object"}}},
                }
            },
        }
    }
    _write_spec(tmp_path, "openapi.json", operation)
    closure = build_input_closure(tmp_path, "openapi.json")

    run = assemble_input_closure_run(
        evaluation_time=EVALUATION_TIME,
        configuration=_configuration("openapi.json"),
        closure=closure,
    ).to_dict()

    assert run["status"] == "completed"
    assert run["gate"]["outcome"] == "blocked"
    assert not hasattr(proof_core, "assemble_completed_run")
    assert not hasattr(proof_core, "EntrypointAnalysis")


def test_validator_instance_value_never_reaches_result(tmp_path: Path) -> None:
    secret = "SECRET_TOKEN=abc"
    document = {
        "openapi": "3.1.0",
        "info": secret,
        "paths": {},
    }
    (tmp_path / "openapi.json").write_text(json.dumps(document), encoding="utf-8")
    closure = build_input_closure(tmp_path, "openapi.json")

    run = assemble_input_closure_run(
        evaluation_time=EVALUATION_TIME,
        configuration=_configuration("openapi.json"),
        closure=closure,
    )

    assert secret.encode() not in run.canonical_bytes()
    assert run.to_dict()["findings"][0]["message"] == (
        "The OpenAPI document violates a schema constraint."
    )


def test_multiple_validator_input_failures_are_deterministic(tmp_path: Path) -> None:
    document = {
        "swagger": "2.0",
        "info": {"title": "Unsupported", "version": "1.0.0"},
        "paths": {},
    }
    for path in ("a.json", "b.json"):
        (tmp_path / path).write_text(json.dumps(document), encoding="utf-8")
    closure = build_input_closure(tmp_path, ("a.json", "b.json"))

    run = assemble_input_closure_run(
        evaluation_time=EVALUATION_TIME,
        configuration=_configuration("a.json", "b.json"),
        closure=closure,
    ).to_dict()

    assert run["status"] == "input-error"
    assert run["gate"]["outcome"] == "not-evaluated"
    assert [item["location"]["path"] for item in run["errors"]] == [
        "a.json",
        "b.json",
    ]


def test_validator_finding_has_lossless_stable_identity() -> None:
    diagnostic = ValidatorDiagnostic(
        source=None,
        line=None,
        column=None,
        pointer="/info",
        code="validator.required",
        severity="error",
        kind="schema",
        message="The info field is required.",
    )
    result = ValidatorResult(
        "openapi.json",
        f"sha256:{'4' * 64}",
        "invalid",
        (diagnostic,),
        1,
        0,
    )

    finding = normalize_validator_findings(result)[0]

    assert finding["source"] == "openapi-validator"
    assert finding["location"] == {"path": "openapi.json", "pointer": "/info"}
    assert finding["fingerprint"] == finding_fingerprint(finding)


def test_forged_invalid_validator_result_cannot_become_a_pass() -> None:
    forged = ValidatorResult(
        "openapi.json",
        f"sha256:{'4' * 64}",
        "invalid",
        (),
        0,
        0,
    )

    with pytest.raises(RunAssemblyError, match="statistics"):
        normalize_validator_findings(forged)


def test_rule_fingerprint_is_recomputed_and_corruption_is_rejected(
    tmp_path: Path,
) -> None:
    _write_spec(
        tmp_path,
        "medium.json",
        {"get": {"responses": {"200": {"description": "ok"}}}},
    )
    closure = build_input_closure(tmp_path, "medium.json")
    evaluation = evaluate_agent_contract(normalize_operations(closure))
    corrupt = replace(evaluation.findings[0], fingerprint=f"sha256:{'0' * 64}")

    with pytest.raises(RunAssemblyError, match="fingerprint"):
        normalize_rule_findings(
            RuleEvaluation(
                evaluation.rulepack,
                (corrupt,),
                evaluation.evaluated_operations,
                evaluation.indeterminate_operations,
            )
        )


def test_analysis_identity_mismatch_cannot_complete(tmp_path: Path) -> None:
    operation = {
        "get": {
            "operationId": "getItems",
            "summary": "Get items",
            "responses": {"200": {"description": "ok"}},
        }
    }
    _write_spec(tmp_path, "openapi.json", operation)
    closure = build_input_closure(tmp_path, "openapi.json")
    analysis = _analysis(closure, "openapi.json")
    wrong = replace(analysis.validator, manifest_digest=f"sha256:{'9' * 64}")

    with pytest.raises(RunAssemblyError, match="identity"):
        assemble_completed_run(
            evaluation_time=EVALUATION_TIME,
            configuration=_configuration("openapi.json"),
            input_manifest=closure.manifest,
            analyses=(replace(analysis, validator=wrong),),
            artifacts=ARTIFACTS,
        )


def test_caller_cannot_forge_analysis_artifact_provenance(tmp_path: Path) -> None:
    operation = {
        "get": {
            "operationId": "getItems",
            "summary": "Get items",
            "responses": {"200": {"description": "ok"}},
        }
    }
    _write_spec(tmp_path, "openapi.json", operation)
    closure = build_input_closure(tmp_path, "openapi.json")
    forged = replace(
        ARTIFACTS,
        validator=replace(ARTIFACTS.validator, digest=f"sha256:{'0' * 64}"),
    )

    with pytest.raises(RunAssemblyError, match="artifact identity"):
        assemble_completed_run(
            evaluation_time=EVALUATION_TIME,
            configuration=_configuration("openapi.json"),
            input_manifest=closure.manifest,
            analyses=(_analysis(closure, "openapi.json"),),
            artifacts=forged,
        )


def test_forged_input_manifest_digest_cannot_become_provenance(tmp_path: Path) -> None:
    operation = {
        "get": {
            "operationId": "getItems",
            "summary": "Get items",
            "responses": {"200": {"description": "ok"}},
        }
    }
    _write_spec(tmp_path, "openapi.json", operation)
    closure = build_input_closure(tmp_path, "openapi.json")
    forged = replace(closure.manifest, digest=f"sha256:{'9' * 64}")

    with pytest.raises(RunAssemblyError, match="digest"):
        assemble_completed_run(
            evaluation_time=EVALUATION_TIME,
            configuration=_configuration("openapi.json"),
            input_manifest=forged,
            analyses=(_analysis(closure, "openapi.json"),),
            artifacts=ARTIFACTS,
        )


def test_validator_limit_is_input_error_and_never_partial_success(
    tmp_path: Path,
) -> None:
    operation = {
        "get": {
            "operationId": "getItems",
            "summary": "Get items",
            "responses": {"200": {"description": "ok"}},
        }
    }
    _write_spec(tmp_path, "openapi.json", operation)
    closure = build_input_closure(tmp_path, "openapi.json")
    analysis = _analysis(closure, "openapi.json")
    limit_result = replace(
        analysis.validator,
        outcome="limit-exceeded",
        diagnostics_observed=101,
        diagnostics_truncated=1,
    )

    run = assemble_analysis_run(
        evaluation_time=EVALUATION_TIME,
        configuration=_configuration("openapi.json"),
        input_manifest=closure.manifest,
        analyses=(replace(analysis, validator=limit_result),),
        artifacts=ARTIFACTS,
    ).to_dict()

    assert run["status"] == "input-error"
    assert run["findings"] == []
    assert run["gate"]["outcome"] == "not-evaluated"
    assert run["summary"]["truncatedFindings"] == 1


def test_unsupported_dialect_pair_is_input_error_not_completed(tmp_path: Path) -> None:
    document = {
        "swagger": "2.0",
        "info": {"title": "Unsupported", "version": "1.0.0"},
        "paths": {},
    }
    (tmp_path / "openapi.json").write_text(json.dumps(document), encoding="utf-8")
    closure = build_input_closure(tmp_path, "openapi.json")
    operations = normalize_operations(closure)
    diagnostic = ValidatorDiagnostic(
        source="openapi.json",
        line=1,
        column=1,
        pointer="/openapi",
        code="input.unsupported-dialect",
        severity="error",
        kind="input",
        message="Only OpenAPI 3.0 and 3.1 documents are supported.",
    )
    analysis = EntrypointAnalysis(
        validator=ValidatorResult(
            "openapi.json",
            closure.manifest.digest,
            "invalid",
            (diagnostic,),
            1,
            0,
        ),
        operations=operations,
        rules=evaluate_agent_contract(operations),
    )
    arguments = {
        "evaluation_time": EVALUATION_TIME,
        "configuration": _configuration("openapi.json"),
        "input_manifest": closure.manifest,
        "analyses": (analysis,),
        "artifacts": ARTIFACTS,
    }

    run = assemble_analysis_run(**arguments).to_dict()

    assert run["status"] == "input-error"
    assert run["findings"] == []
    assert run["errors"][0]["code"] == "input.unsupported-dialect"
    with pytest.raises(RunAssemblyError, match="input diagnostics"):
        assemble_completed_run(**arguments)


def test_shared_path_item_counts_each_effective_route(tmp_path: Path) -> None:
    document = {
        "openapi": "3.1.0",
        "info": {"title": "Shared", "version": "1.0.0"},
        "components": {
            "pathItems": {
                "Shared": {
                    "get": {
                        "operationId": "getShared",
                        "summary": "Get shared",
                        "responses": {"200": {"description": "ok"}},
                    }
                }
            }
        },
        "paths": {
            "/a": {"$ref": "#/components/pathItems/Shared"},
            "/b": {"$ref": "#/components/pathItems/Shared"},
        },
    }
    (tmp_path / "openapi.json").write_text(json.dumps(document), encoding="utf-8")
    closure = build_input_closure(tmp_path, "openapi.json")

    run = assemble_completed_run(
        evaluation_time=EVALUATION_TIME,
        configuration=_configuration("openapi.json"),
        input_manifest=closure.manifest,
        analyses=(_analysis(closure, "openapi.json"),),
        artifacts=ARTIFACTS,
    ).to_dict()

    assert run["summary"]["scannedOperations"] == 2


def test_configuration_input_and_worker_failures_are_normalized(tmp_path: Path) -> None:
    configuration_error = ConfigurationError(
        "configuration.invalid-document",
        "configuration is invalid",
        path="proof.yaml",
    )
    config_run = assemble_configuration_error_run(
        evaluation_time=EVALUATION_TIME,
        error=configuration_error,
    ).to_dict()
    assert config_run["status"] == "input-error"
    assert config_run["errors"][0]["kind"] == "configuration"

    operation = {
        "get": {
            "operationId": "getItems",
            "summary": "Get items",
            "responses": {"200": {"description": "ok"}},
        }
    }
    _write_spec(tmp_path, "openapi.json", operation)
    closure = build_input_closure(tmp_path, "openapi.json")
    configuration = _configuration("openapi.json")
    input_run = assemble_input_error_run(
        evaluation_time=EVALUATION_TIME,
        error=InputClosureError(
            "missing-resource", "referenced resource is missing", path="openapi.json"
        ),
        configuration=configuration,
    ).to_dict()
    worker_run = assemble_worker_error_run(
        evaluation_time=EVALUATION_TIME,
        error=WorkerFailure("worker.process", "process", "worker exited"),
        configuration=configuration,
        input_manifest=closure.manifest,
        artifacts=ARTIFACTS,
    ).to_dict()

    assert input_run["status"] == "input-error"
    assert input_run["errors"][0]["kind"] == "input"
    assert worker_run["status"] == "internal-error"
    assert worker_run["errors"][0] == {
        "code": "worker.process",
        "kind": "internal",
        "message": "Validator worker exited unexpectedly.",
        "retryable": True,
    }


def test_input_attempt_identity_rejects_host_paths() -> None:
    with pytest.raises(RunAssemblyError, match="repository-relative"):
        input_attempt_identity("failed", selectors=(r"C:\private\openapi.json",))


def test_gate_truth_table_covers_every_threshold() -> None:
    medium = {
        "severity": "medium",
        "fingerprint": f"sha256:{'a' * 64}",
    }
    assert evaluate_gate((), "high").outcome == "pass"
    assert evaluate_gate((medium,), "error").outcome == "advisory"
    assert evaluate_gate((medium,), "high").outcome == "advisory"
    assert evaluate_gate((medium,), "medium").outcome == "blocked"
    assert evaluate_gate((medium,), "low").outcome == "blocked"
    assert evaluate_gate((medium,), "none").outcome == "advisory"
