from __future__ import annotations

import json
from dataclasses import FrozenInstanceError

import pytest
from proof_core.canonical_json import content_digest
from proof_core.result_model import (
    AnalysisArtifacts,
    ArtifactIdentity,
    ContentIdentity,
    GateResult,
    NormalizedRun,
    RunProvenance,
    RunSummary,
    TerminalError,
)
from proof_core.result_schema import validate_normalized_run


def digest(character: str) -> str:
    return f"sha256:{character * 64}"


def artifact(name: str, character: str) -> ArtifactIdentity:
    return ArtifactIdentity(name=name, version="1.0.0", digest=digest(character))


def provenance(*, extensions: dict[str, object] | None = None) -> RunProvenance:
    return RunProvenance(
        core=artifact("proof-core", "1"),
        validator=artifact("openapi-validator", "2"),
        rule_pack=artifact("proof-rulepack", "3"),
        runtime=artifact("cpython", "4"),
        configuration=ContentIdentity(digest("5")),
        input=ContentIdentity(digest("6")),
        extensions=extensions or {},
    )


def severity_counts(**overrides: int) -> dict[str, int]:
    result = {severity: 0 for severity in ("error", "high", "medium", "low", "info")}
    result.update(overrides)
    return result


def summary(
    *,
    finding_total: int = 0,
    error_total: int = 0,
    counts: dict[str, int] | None = None,
    extensions: dict[str, object] | None = None,
) -> RunSummary:
    return RunSummary(
        finding_total=finding_total,
        error_total=error_total,
        findings_by_severity=counts or severity_counts(),
        scanned_files=1,
        scanned_operations=2,
        excluded_operations=0,
        risky_operations=0,
        truncated_findings=0,
        extensions=extensions or {},
    )


def finding(
    *,
    severity: str = "high",
    fingerprint: str | None = None,
    source: str = "agent-rule",
    rule_id: str = "AGT-POL-001",
) -> dict[str, object]:
    value: dict[str, object] = {
        "ruleId": rule_id,
        "source": source,
        "severity": severity,
        "message": "A side effect lacks an explicit safety declaration.",
        "fingerprint": digest("a"),
        "location": {
            "path": "api/openapi.yaml",
            "pointer": "/paths/~1accounts~1{id}/delete",
            "line": 20,
            "column": 3,
        },
        "operation": {
            "method": "delete",
            "path": "/accounts/{id}",
            "operationId": "deleteAccount",
        },
        "riskCategories": ["destructive", "external_side_effect"],
        "evidence": [
            {
                "kind": "method",
                "description": "The operation uses DELETE.",
                "pointer": "/paths/~1accounts~1{id}/delete",
                "value": "delete",
            }
        ],
        "remediation": {
            "recommendation": "Declare the safety policy.",
            "documentationUrl": "https://example.test/safety",
        },
    }
    value["fingerprint"] = finding_digest(value) if fingerprint is None else fingerprint
    return value


def finding_digest(value: dict[str, object]) -> str:
    location = value["location"]
    operation = value["operation"]
    evidence = value["evidence"]
    assert isinstance(location, dict)
    assert isinstance(operation, dict)
    assert isinstance(evidence, list)
    projection = {
        "fingerprintVersion": 1,
        "source": value["source"],
        "ruleId": value["ruleId"],
        "location": {
            "path": location["path"],
            "pointer": location["pointer"],
        },
        "operation": {"method": operation["method"], "path": operation["path"]},
        "riskCategories": list(value["riskCategories"]),
        "evidence": [
            {
                "kind": item["kind"],
                "pointer": item["pointer"],
                "value": item.get("value", item["description"]),
            }
            for item in evidence
        ],
    }
    return content_digest(projection)


def completed_run(
    *,
    findings: tuple[dict[str, object], ...] = (),
    gate: GateResult | None = None,
    run_summary: RunSummary | None = None,
    extensions: dict[str, object] | None = None,
) -> NormalizedRun:
    return NormalizedRun(
        evaluation_time="2026-07-25T00:00:00Z",
        status="completed",
        findings=findings,
        errors=(),
        summary=run_summary or summary(),
        gate=gate or GateResult(outcome="pass", fail_on="high"),
        provenance=provenance(),
        extensions=extensions or {},
    )


@pytest.mark.parametrize(
    ("name", "version", "artifact_digest"),
    [
        ("", "1", digest("a")),
        ("   ", "1", digest("a")),
        ("core", "", digest("a")),
        ("core", "1", "sha256:ABC"),
        ("core", "1", "a" * 64),
    ],
)
def test_artifact_identity_rejects_values_outside_exact_contract(
    name: str, version: str, artifact_digest: str
) -> None:
    with pytest.raises(ValueError):
        ArtifactIdentity(name=name, version=version, digest=artifact_digest)


def test_identity_and_analysis_artifact_values_are_frozen_and_serializable() -> None:
    identity = artifact("proof-core", "a")
    analysis = AnalysisArtifacts(
        core=identity,
        validator=artifact("validator", "b"),
        runtime=artifact("runtime", "c"),
    )

    assert analysis.to_dict()["core"] == identity.to_dict()
    with pytest.raises(FrozenInstanceError):
        identity.name = "changed"
    with pytest.raises(ValueError):
        ContentIdentity("sha256:" + "A" * 64)


def test_provenance_freezes_extensions_and_returns_detached_values() -> None:
    source = {"x-proof.meta": {"labels": ["stable"]}}
    value = provenance(extensions=source)
    source["x-proof.meta"]["labels"].append("changed")

    first = value.to_dict()
    first["x-proof.meta"]["labels"].append("detached")

    assert value.to_dict()["x-proof.meta"] == {"labels": ["stable"]}
    with pytest.raises(TypeError):
        value.extensions["x-other"] = True
    with pytest.raises(ValueError, match="namespaced"):
        provenance(extensions={"metadata": True})


@pytest.mark.parametrize(
    "gate",
    [
        GateResult("pass", "high"),
        GateResult("advisory", "high", (digest("a"),)),
        GateResult("advisory", "none", (digest("a"),)),
        GateResult("blocked", "medium", (digest("a"),)),
        GateResult("not-evaluated", "high"),
    ],
)
def test_gate_result_accepts_semantically_valid_states(gate: GateResult) -> None:
    assert gate.to_dict()["outcome"] == gate.outcome


@pytest.mark.parametrize(
    ("outcome", "fail_on", "causes"),
    [
        ("pass", "high", (digest("a"),)),
        ("not-evaluated", "high", (digest("a"),)),
        ("advisory", "high", ()),
        ("blocked", "high", ()),
        ("blocked", "none", (digest("a"),)),
        ("blocked", "high", (digest("b"), digest("a"))),
        ("blocked", "high", (digest("a"), digest("a"))),
    ],
)
def test_gate_result_rejects_inconsistent_states(
    outcome: str, fail_on: str, causes: tuple[str, ...]
) -> None:
    with pytest.raises(ValueError):
        GateResult(
            outcome=outcome,
            fail_on=fail_on,
            causing_finding_fingerprints=causes,
        )


def test_summary_enforces_nonnegative_exact_counts_and_freezes_input() -> None:
    counts = severity_counts(high=1)
    value = summary(finding_total=1, counts=counts)
    counts["high"] = 0

    assert value.to_dict()["findingsBySeverity"]["high"] == 1
    with pytest.raises(TypeError):
        value.findings_by_severity["high"] = 2
    with pytest.raises(ValueError, match="severity counts"):
        summary(finding_total=2, counts=severity_counts(high=1))
    with pytest.raises(ValueError, match="non-negative"):
        RunSummary(
            finding_total=True,
            error_total=0,
            findings_by_severity=severity_counts(),
            scanned_files=0,
            scanned_operations=0,
            excluded_operations=0,
            risky_operations=0,
            truncated_findings=0,
        )
    with pytest.raises(ValueError, match="riskyOperations"):
        RunSummary(
            finding_total=0,
            error_total=0,
            findings_by_severity=severity_counts(),
            scanned_files=1,
            scanned_operations=1,
            excluded_operations=0,
            risky_operations=2,
            truncated_findings=0,
        )


def test_terminal_error_validates_and_detaches_location_and_extensions() -> None:
    location = {"path": "api/openapi.yaml", "pointer": "", "line": 1}
    error = TerminalError(
        code="input.invalid-yaml",
        kind="input",
        message="The input cannot be parsed.",
        retryable=False,
        location=location,
        extensions={"x-proof.context": {"parser": "yaml"}},
    )
    location["path"] = "changed"
    serialized = error.to_dict()
    serialized["location"]["path"] = "also-changed"

    assert error.to_dict()["location"]["path"] == "api/openapi.yaml"


@pytest.mark.parametrize(
    "kwargs",
    [
        {"code": "UPPER", "kind": "input", "message": "bad", "retryable": False},
        {"code": "bad", "kind": "unknown", "message": "bad", "retryable": False},
        {"code": "bad", "kind": "input", "message": " ", "retryable": False},
        {"code": "bad", "kind": "input", "message": "bad", "retryable": 0},
        {
            "code": "bad",
            "kind": "input",
            "message": "bad",
            "retryable": False,
            "location": {"path": "C:\\secret.yaml", "pointer": ""},
        },
        {
            "code": "bad",
            "kind": "input",
            "message": "bad",
            "retryable": False,
            "location": {"path": "openapi.yaml", "pointer": "/bad~2pointer"},
        },
    ],
)
def test_terminal_error_rejects_invalid_contract_values(
    kwargs: dict[str, object],
) -> None:
    with pytest.raises(ValueError):
        TerminalError(**kwargs)


def test_empty_completed_run_computes_digest_and_satisfies_result_schema() -> None:
    run = completed_run()
    serialized = run.to_dict()
    digest_input = dict(serialized)
    digest_input.pop("resultDigest")

    assert run.result_digest == content_digest(digest_input)
    assert json.loads(run.canonical_bytes()) == serialized
    assert run.canonical_bytes() == run.canonical_bytes()
    validate_normalized_run(serialized)


def test_default_high_threshold_makes_medium_finding_advisory() -> None:
    medium = finding(severity="medium")
    fingerprint = str(medium["fingerprint"])
    run = completed_run(
        findings=(medium,),
        gate=GateResult("advisory", "high", (fingerprint,)),
        run_summary=summary(finding_total=1, counts=severity_counts(medium=1)),
    )

    assert run.gate.outcome == "advisory"
    assert run.gate.causing_finding_fingerprints == (fingerprint,)


def test_threshold_match_blocks_with_only_blocking_fingerprints() -> None:
    high = finding(severity="high")
    medium = finding(severity="medium", rule_id="AGT-POL-002")
    high_fingerprint = str(high["fingerprint"])
    run = completed_run(
        findings=(high, medium),
        gate=GateResult("blocked", "high", (high_fingerprint,)),
        run_summary=summary(finding_total=2, counts=severity_counts(high=1, medium=1)),
    )

    assert run.gate.causing_finding_fingerprints == (high_fingerprint,)


def test_fail_on_none_is_advisory_with_all_finding_fingerprints() -> None:
    high = finding(severity="high")
    fingerprint = str(high["fingerprint"])
    run = completed_run(
        findings=(high,),
        gate=GateResult("advisory", "none", (fingerprint,)),
        run_summary=summary(finding_total=1, counts=severity_counts(high=1)),
    )

    assert run.gate.outcome == "advisory"


def test_terminal_states_enforce_errors_findings_summary_and_gate() -> None:
    input_error = TerminalError(
        code="input.missing", kind="input", message="Input is missing.", retryable=False
    )
    run = NormalizedRun(
        evaluation_time="2026-07-25T00:00:00Z",
        status="input-error",
        findings=(),
        errors=(input_error,),
        summary=summary(error_total=1),
        gate=GateResult("not-evaluated", "high"),
        provenance=provenance(),
    )
    assert run.status == "input-error"

    with pytest.raises(ValueError, match="input-error"):
        NormalizedRun(
            evaluation_time="2026-07-25T00:00:00Z",
            status="input-error",
            findings=(),
            errors=(
                TerminalError(
                    code="runtime.timeout",
                    kind="timeout",
                    message="Timed out.",
                    retryable=True,
                ),
            ),
            summary=summary(error_total=1),
            gate=GateResult("not-evaluated", "high"),
            provenance=provenance(),
        )


def test_internal_error_accepts_only_internal_terminal_kinds() -> None:
    error = TerminalError(
        code="runtime.timeout",
        kind="timeout",
        message="Timed out.",
        retryable=True,
    )
    run = NormalizedRun(
        evaluation_time="2026-07-25T00:00:00Z",
        status="internal-error",
        findings=(),
        errors=(error,),
        summary=summary(error_total=1),
        gate=GateResult("not-evaluated", "high"),
        provenance=provenance(),
    )

    assert run.status == "internal-error"


@pytest.mark.parametrize(
    "evaluation_time",
    [
        "2026-07-25T00:00:00+00:00",
        "2026-07-25T00:00:00.000Z",
        "2026-7-25T00:00:00Z",
        "2026-02-30T00:00:00Z",
        "not-a-time",
    ],
)
def test_evaluation_time_requires_exact_valid_whole_second_utc(
    evaluation_time: str,
) -> None:
    with pytest.raises(ValueError, match="evaluationTime"):
        NormalizedRun(
            evaluation_time=evaluation_time,
            status="completed",
            findings=(),
            errors=(),
            summary=summary(),
            gate=GateResult("pass", "high"),
            provenance=provenance(),
        )


def test_normalized_run_rejects_noncanonical_findings_and_errors() -> None:
    high = finding(severity="high")
    medium = finding(severity="medium", rule_id="AGT-POL-002")
    with pytest.raises(ValueError, match="canonical result ordering"):
        completed_run(
            findings=(medium, high),
            gate=GateResult("blocked", "high", (str(high["fingerprint"]),)),
            run_summary=summary(
                finding_total=2, counts=severity_counts(high=1, medium=1)
            ),
        )

    later = TerminalError("z-code", "input", "Later", False)
    earlier = TerminalError("a-code", "input", "Earlier", False)
    with pytest.raises(ValueError, match="canonical result ordering"):
        NormalizedRun(
            evaluation_time="2026-07-25T00:00:00Z",
            status="input-error",
            findings=(),
            errors=(later, earlier),
            summary=summary(error_total=2),
            gate=GateResult("not-evaluated", "high"),
            provenance=provenance(),
        )


def test_normalized_run_rejects_duplicate_fingerprints_and_summary_mismatch() -> None:
    first = finding(rule_id="A")
    with pytest.raises(ValueError, match="fingerprints must be unique"):
        completed_run(
            findings=(first, first),
            gate=GateResult("blocked", "high", (str(first["fingerprint"]),)),
            run_summary=summary(finding_total=2, counts=severity_counts(high=2)),
        )

    with pytest.raises(ValueError, match="summary"):
        completed_run(run_summary=summary(error_total=1))


def test_normalized_run_rejects_gate_that_does_not_match_findings() -> None:
    medium = finding(severity="medium")
    with pytest.raises(ValueError, match="gate does not match"):
        completed_run(
            findings=(medium,),
            gate=GateResult("blocked", "high", (str(medium["fingerprint"]),)),
            run_summary=summary(finding_total=1, counts=severity_counts(medium=1)),
        )


def test_finding_validation_rejects_invalid_nested_or_noncanonical_values() -> None:
    invalid_risks = finding()
    invalid_risks["riskCategories"] = ["unknown"]
    with pytest.raises(ValueError, match="riskCategories"):
        completed_run(
            findings=(invalid_risks,),
            gate=GateResult("blocked", "high", (digest("a"),)),
            run_summary=summary(finding_total=1, counts=severity_counts(high=1)),
        )

    invalid_evidence = finding()
    invalid_evidence["evidence"] = [
        {"kind": "text", "description": "z"},
        {"kind": "text", "description": "a"},
    ]
    with pytest.raises(ValueError, match="canonical projection ordering"):
        completed_run(
            findings=(invalid_evidence,),
            gate=GateResult("blocked", "high", (digest("a"),)),
            run_summary=summary(finding_total=1, counts=severity_counts(high=1)),
        )


def test_normalized_run_is_deeply_detached_and_extensions_change_digest() -> None:
    source = finding()
    fingerprint = str(source["fingerprint"])
    first = completed_run(
        findings=(source,),
        gate=GateResult("blocked", "high", (fingerprint,)),
        run_summary=summary(finding_total=1, counts=severity_counts(high=1)),
        extensions={"x-proof.mode": {"name": "local"}},
    )
    source["message"] = "mutated"
    serialized = first.to_dict()
    serialized["findings"][0]["message"] = "detached mutation"
    second = completed_run(
        findings=(finding(),),
        gate=GateResult("blocked", "high", (fingerprint,)),
        run_summary=summary(finding_total=1, counts=severity_counts(high=1)),
        extensions={"x-proof.mode": {"name": "hosted"}},
    )

    assert first.to_dict()["findings"][0]["message"].startswith("A side effect")
    assert first.result_digest != second.result_digest
