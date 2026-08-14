from __future__ import annotations

import re

import pytest
from proof_cli.reporters import render_report
from proof_core import (
    ArtifactIdentity,
    ContentIdentity,
    GateResult,
    NormalizedRun,
    RunProvenance,
    RunSummary,
    TerminalError,
    finding_fingerprint,
    validate_normalized_run,
)


def _digest(character: str) -> str:
    return f"sha256:{character * 64}"


def _provenance() -> RunProvenance:
    def artifact(name: str, character: str) -> ArtifactIdentity:
        return ArtifactIdentity(name, "1.0.0", _digest(character))

    return RunProvenance(
        artifact("proof-core", "1"),
        artifact("openapi-validator", "2"),
        artifact("proof-rulepack", "3"),
        artifact("cpython", "4"),
        ContentIdentity(_digest("5")),
        ContentIdentity(_digest("6")),
    )


def _finding() -> dict[str, object]:
    finding: dict[str, object] = {
        "ruleId": "AGT-POL-001",
        "source": "agent-rule",
        "severity": "high",
        "message": "A side effect lacks an explicit safety declaration.",
        "location": {"path": "openapi.json", "pointer": "/paths/~1items/delete"},
        "operation": {
            "method": "delete",
            "path": "/items",
            "operationId": "deleteItems",
        },
        "riskCategories": ["destructive"],
        "evidence": [
            {
                "kind": "method",
                "description": "DELETE can cause an external side effect.",
                "pointer": "/paths/~1items/delete",
                "value": "delete",
            }
        ],
        "remediation": {"recommendation": "Declare an explicit safety boundary."},
    }
    finding["fingerprint"] = finding_fingerprint(finding)
    return finding


def _run(kind: str) -> NormalizedRun:
    findings = (_finding(),) if kind in {"advisory", "blocked"} else ()
    errors: tuple[TerminalError, ...] = ()
    status = "completed"
    gate = GateResult("pass", "high")
    if kind == "advisory":
        gate = GateResult("advisory", "none", (str(findings[0]["fingerprint"]),))
    elif kind == "blocked":
        gate = GateResult("blocked", "high", (str(findings[0]["fingerprint"]),))
    elif kind == "input-error":
        status = "input-error"
        errors = (
            TerminalError(
                "configuration.missing-file",
                "configuration",
                "Configuration file is unavailable.",
                False,
                location={"path": "proof.yaml", "pointer": ""},
            ),
        )
        gate = GateResult("not-evaluated", "high")
    elif kind == "internal-error":
        status = "internal-error"
        errors = (
            TerminalError("runtime.failure", "internal", "Failed safely.", False),
        )
        gate = GateResult("not-evaluated", "high")
    counts = {severity: 0 for severity in ("error", "high", "medium", "low", "info")}
    for finding in findings:
        counts[str(finding["severity"])] += 1
    return NormalizedRun(
        evaluation_time="2026-08-14T00:00:00Z",
        status=status,  # type: ignore[arg-type]
        findings=findings,
        errors=errors,
        summary=RunSummary(
            finding_total=len(findings),
            error_total=len(errors),
            findings_by_severity=counts,
            scanned_files=1,
            scanned_operations=1,
            excluded_operations=0,
            risky_operations=1 if findings else 0,
            truncated_findings=2 if kind == "blocked" else 0,
        ),
        gate=gate,
        provenance=_provenance(),
    )


@pytest.mark.parametrize(
    ("kind", "headline", "detail"),
    (
        ("pass", "PROOF scan: COMPLETED — PASS", "Findings: 0"),
        ("advisory", "PROOF scan: COMPLETED — ADVISORY", "[HIGH] AGT-POL-001"),
        ("blocked", "PROOF scan: COMPLETED — BLOCKED", "Truncated findings: 2"),
        (
            "input-error",
            "PROOF scan: INPUT-ERROR — NOT-EVALUATED",
            (
                "[configuration/configuration.missing-file] "
                "Configuration file is unavailable."
            ),
        ),
        (
            "internal-error",
            "PROOF scan: INTERNAL-ERROR — NOT-EVALUATED",
            "[internal/runtime.failure] Failed safely.",
        ),
    ),
)
def test_console_snapshots_cover_terminal_and_gate_states(
    kind: str, headline: str, detail: str
) -> None:
    run = _run(kind)

    snapshot = render_report(run, "console").decode("utf-8")

    assert snapshot.startswith(headline + "\n")
    assert detail in snapshot
    assert "Gate: " in snapshot
    assert "Provenance:\n" in snapshot
    assert "rule-pack: proof-rulepack@1.0.0" in snapshot
    assert snapshot.endswith("\n")


def test_console_detail_preserves_normalized_finding_fields() -> None:
    snapshot = render_report(_run("blocked"), "console").decode("utf-8")

    assert "DELETE /items (deleteItems)" in snapshot
    assert "Evidence:\n      - method:" in snapshot
    assert "Remediation: Declare an explicit safety boundary." in snapshot
    assert "Risks: destructive" in snapshot


def test_json_report_is_the_exact_schema_valid_normalized_run() -> None:
    run = _run("blocked")
    payload = render_report(run, "json")

    assert payload == run.canonical_bytes() + b"\n"
    assert run.result_digest.encode("ascii") in payload
    validate_normalized_run(run.to_dict())


def test_color_is_presentation_only_and_does_not_change_ordering() -> None:
    run = _run("blocked")
    original = run.canonical_bytes()
    plain = render_report(run, "console", color=False)
    colored = render_report(run, "console", color=True)

    assert b"\x1b[" in colored
    assert re.sub(rb"\x1b\[[0-9;]*m", b"", colored) == plain
    assert run.canonical_bytes() == original
