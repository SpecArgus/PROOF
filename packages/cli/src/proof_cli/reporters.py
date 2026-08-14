"""Presentation-only renderers for immutable normalized result-v1 runs."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Literal

from proof_core import NormalizedRun

ReportFormat = Literal["console", "json"]

_SEVERITIES = ("error", "high", "medium", "low", "info")
_COLOR = {
    "error": "31",
    "high": "31",
    "medium": "33",
    "low": "36",
    "info": "37",
    "pass": "32",
    "advisory": "33",
    "blocked": "31",
    "not-evaluated": "33",
}


def render_report(
    run: NormalizedRun, report_format: ReportFormat, *, color: bool = False
) -> bytes:
    """Render ``run`` without filtering, changing, or reclassifying it."""

    if report_format == "json":
        return run.canonical_bytes() + b"\n"
    return _render_console(run, color=color).encode("utf-8")


def _render_console(run: NormalizedRun, *, color: bool) -> str:
    summary = run.summary
    lines = [
        f"PROOF scan: {run.status.upper()} — "
        f"{_styled(run.gate.outcome.upper(), run.gate.outcome, color)}",
        (
            "Findings: "
            f"{summary.finding_total} ("
            + ", ".join(
                f"{severity}={summary.findings_by_severity[severity]}"
                for severity in _SEVERITIES
            )
            + ")"
        ),
        (
            "Scanned: "
            f"files={summary.scanned_files}, operations={summary.scanned_operations}, "
            f"excluded={summary.excluded_operations}, risky={summary.risky_operations}"
        ),
        f"Gate: {run.gate.outcome} (fail-on: {run.gate.fail_on})",
        f"Truncated findings: {summary.truncated_findings}",
        f"Result digest: {run.result_digest}",
    ]
    if run.findings:
        lines.append("Findings detail:")
        for finding in run.findings:
            lines.extend(_render_finding(finding, color=color))
    if run.errors:
        lines.append("Errors:")
        for error in run.errors:
            location = ""
            if error.location is not None:
                location = f" at {_location_text(error.location)}"
            lines.append(f"  - [{error.kind}/{error.code}] {error.message}{location}")
    lines.append("Provenance:")
    for name, identity in (
        ("core", run.provenance.core),
        ("validator", run.provenance.validator),
        ("rule-pack", run.provenance.rule_pack),
        ("runtime", run.provenance.runtime),
    ):
        lines.append(
            f"  {name}: {identity.name}@{identity.version} ({identity.digest})"
        )
    lines.append(f"  configuration: {run.provenance.configuration.digest}")
    lines.append(f"  input: {run.provenance.input.digest}")
    return "\n".join(lines) + "\n"


def _render_finding(finding: Mapping[str, object], *, color: bool) -> list[str]:
    severity = str(finding["severity"])
    operation = finding.get("operation")
    operation_text = ""
    if isinstance(operation, Mapping):
        operation_text = f" — {operation['method'].upper()} {operation['path']}"
        if "operationId" in operation:
            operation_text += f" ({operation['operationId']})"
    lines = [
        "  - "
        f"[{_styled(severity.upper(), severity, color)}] {finding['ruleId']}"
        f"{operation_text}",
        f"    Message: {finding['message']}",
        f"    Location: {_location_text(finding['location'])}",
        f"    Fingerprint: {finding['fingerprint']}",
    ]
    risks = finding.get("riskCategories")
    if isinstance(risks, (list, tuple)) and risks:
        lines.append("    Risks: " + ", ".join(str(risk) for risk in risks))
    lines.append("    Evidence:")
    for evidence in finding["evidence"]:
        assert isinstance(evidence, Mapping)
        suffix = ""
        if "pointer" in evidence:
            suffix += f" at {evidence['pointer']}"
        if "value" in evidence:
            suffix += f" = {evidence['value']}"
        lines.append(f"      - {evidence['kind']}: {evidence['description']}{suffix}")
    remediation = finding["remediation"]
    assert isinstance(remediation, Mapping)
    lines.append(f"    Remediation: {remediation['recommendation']}")
    if "documentationUrl" in remediation:
        lines.append(f"    Documentation: {remediation['documentationUrl']}")
    return lines


def _location_text(location: object) -> str:
    assert isinstance(location, Mapping)
    position = ""
    if "line" in location:
        position = f":{location['line']}"
        if "column" in location:
            position += f":{location['column']}"
    return f"{location['path']}{position}{location['pointer']}"


def _styled(value: str, category: str, color: bool) -> str:
    if not color:
        return value
    return f"\x1b[{_COLOR[category]}m{value}\x1b[0m"
