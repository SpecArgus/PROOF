"""Built-in, deterministic Agent contract rules."""

from proof_rulepack.agent_contract import (
    AGENT_CONTRACT_IDENTITY,
    Evidence,
    Finding,
    FindingLocation,
    FindingOperation,
    Remediation,
    RuleEvaluation,
    RulePackIdentity,
    evaluate_agent_contract,
)

__all__ = [
    "AGENT_CONTRACT_IDENTITY",
    "Evidence",
    "Finding",
    "FindingLocation",
    "FindingOperation",
    "Remediation",
    "RuleEvaluation",
    "RulePackIdentity",
    "evaluate_agent_contract",
]

__version__ = "0.1.0"
