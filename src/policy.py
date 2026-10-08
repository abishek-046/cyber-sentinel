"""
Policy Enforcement Module
Implements --max-risk guardrail with exit code semantics.
"""
import logging
from typing import List, Tuple

import pandas as pd

from config import DEFAULT_MAX_RISK

logger = logging.getLogger(__name__)

POLICY_PASS_EXIT_CODE = 0
POLICY_FAIL_EXIT_CODE = 1


class PolicyResult:
    """Result of a policy evaluation."""

    def __init__(
        self,
        max_risk_threshold: int,
        violations: List[dict],
        total_alerts: int,
    ):
        self.max_risk_threshold = max_risk_threshold
        self.violations = violations
        self.total_alerts = total_alerts
        self.passed = len(violations) == 0
        self.exit_code = POLICY_PASS_EXIT_CODE if self.passed else POLICY_FAIL_EXIT_CODE

    @property
    def status_label(self) -> str:
        return "PASS" if self.passed else "FAIL"

    @property
    def summary(self) -> str:
        if self.passed:
            return (
                f"Policy PASS — All {self.total_alerts} alert(s) are within "
                f"the maximum risk threshold of {self.max_risk_threshold}."
            )
        return (
            f"Policy FAIL — {len(self.violations)} alert(s) exceed the "
            f"maximum risk threshold of {self.max_risk_threshold}. "
            f"Exit code: {self.exit_code}"
        )

    def to_dict(self) -> dict:
        return {
            "passed": self.passed,
            "exit_code": self.exit_code,
            "status_label": self.status_label,
            "max_risk_threshold": self.max_risk_threshold,
            "total_alerts": self.total_alerts,
            "violation_count": len(self.violations),
            "violations": self.violations,
            "summary": self.summary,
        }


def evaluate_policy(
    alerts_df: pd.DataFrame,
    max_risk: int = DEFAULT_MAX_RISK,
) -> PolicyResult:
    """
    Evaluate policy guardrail against alert results.

    Args:
        alerts_df:  DataFrame with risk_score column.
        max_risk:   Maximum acceptable risk score (inclusive).

    Returns:
        PolicyResult with pass/fail status and exit code.
    """
    max_risk = int(max_risk)

    if alerts_df.empty or "risk_score" not in alerts_df.columns:
        return PolicyResult(
            max_risk_threshold=max_risk,
            violations=[],
            total_alerts=0,
        )

    violations = []
    for _, row in alerts_df.iterrows():
        risk = int(row.get("risk_score", 0))
        if risk > max_risk:
            violations.append({
                "source_ip": str(row.get("source_ip", "unknown")),
                "classification": str(row.get("classification", "Unknown")),
                "risk_score": risk,
                "risk_band": str(row.get("risk_band", "Unknown")),
                "max_risk_threshold": max_risk,
            })

    result = PolicyResult(
        max_risk_threshold=max_risk,
        violations=violations,
        total_alerts=len(alerts_df),
    )

    if result.passed:
        logger.info("Policy PASS: threshold=%d, alerts=%d", max_risk, len(alerts_df))
    else:
        logger.warning(
            "Policy FAIL: threshold=%d, violations=%d/%d",
            max_risk, len(violations), len(alerts_df),
        )

    return result
