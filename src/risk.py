"""
Risk Scoring Module
Deterministic 0-100 risk scoring combining anomaly signal, classifier confidence,
and security evidence.

Risk Formula:
    base_score = (anomaly_score * 0.35) + (classifier_confidence * 0.35) + (evidence_score * 0.30)
    risk_score = round(base_score * 100)

Where:
    - anomaly_score:           [0, 1] normalized Isolation Forest signal
    - classifier_confidence:   [0, 1] Random Forest max class probability
    - evidence_score:          [0, 1] normalized evidence strength (0 for Normal class)

Risk Bands:
    0-30:  Normal
    31-70: Suspicious
    71-100: Malicious
"""
import logging

import numpy as np
import pandas as pd

from config import RISK_MALICIOUS_MIN, RISK_NORMAL_MAX, RISK_SUSPICIOUS_MAX

logger = logging.getLogger(__name__)


def compute_evidence_score(evidence: list) -> float:
    """
    Convert evidence list to a normalized [0, 1] score.
    Evidence items carry an 'impact' weight.
    """
    if not evidence:
        return 0.0
    total = sum(item.get("impact", 0.5) for item in evidence)
    # Normalize: max ~5 high-impact items = 1.0
    normalized = min(total / 4.0, 1.0)
    return float(normalized)


def compute_risk_score(
    anomaly_score: float,
    classifier_confidence: float,
    classification: str,
    evidence: list,
) -> int:
    """
    Compute deterministic integer risk score in [0, 100].

    Args:
        anomaly_score:          Isolation Forest signal [0, 1]
        classifier_confidence:  RF max probability [0, 1]
        classification:         Predicted threat class string
        evidence:               List of evidence dicts

    Returns:
        Integer risk score in [0, 100]
    """
    # Clamp inputs
    anomaly_score = float(np.clip(anomaly_score, 0.0, 1.0))
    classifier_confidence = float(np.clip(classifier_confidence, 0.0, 1.0))

    # If classification is Normal, reduce risk contribution
    is_threat = classification not in ("Normal", "normal", "")

    # Evidence score — zero for Normal classification
    evidence_score = compute_evidence_score(evidence) if is_threat else 0.0

    # For Normal classification: reduce anomaly weight
    if not is_threat:
        # Low risk: only anomaly signal matters, but downweighted
        base = (anomaly_score * 0.4) + (classifier_confidence * 0.1)
    else:
        base = (
            anomaly_score * 0.35
            + classifier_confidence * 0.35
            + evidence_score * 0.30
        )

    risk = round(base * 100)
    return int(np.clip(risk, 0, 100))


def classify_risk_band(risk_score: int) -> str:
    """Map risk score to risk band label."""
    if risk_score <= RISK_NORMAL_MAX:
        return "Normal"
    elif risk_score <= RISK_SUSPICIOUS_MAX:
        return "Suspicious"
    else:
        return "Malicious"


def score_risks(feature_df: pd.DataFrame) -> pd.DataFrame:
    """
    Add risk_score and risk_band columns to the feature DataFrame.

    Args:
        feature_df: DataFrame with anomaly_score, classifier_confidence,
                    classification, and evidence columns.

    Returns:
        feature_df with risk_score and risk_band columns added.
    """
    if feature_df.empty:
        return feature_df

    feature_df = feature_df.copy()
    risk_scores = []
    risk_bands = []

    for _, row in feature_df.iterrows():
        anomaly_score = float(row.get("anomaly_score", 0.0))
        classifier_confidence = float(row.get("classifier_confidence", 0.0))
        classification = str(row.get("classification", "Normal"))
        evidence = row.get("evidence", [])

        # Handle case where evidence might be stored as string
        if isinstance(evidence, str):
            import json as _json
            try:
                evidence = _json.loads(evidence)
            except Exception:
                evidence = []

        risk = compute_risk_score(
            anomaly_score, classifier_confidence, classification, evidence
        )
        band = classify_risk_band(risk)
        risk_scores.append(risk)
        risk_bands.append(band)

    feature_df["risk_score"] = risk_scores
    feature_df["risk_band"] = risk_bands

    logger.info(
        "Risk scoring complete: %d IPs — Normal:%d, Suspicious:%d, Malicious:%d",
        len(feature_df),
        (feature_df["risk_band"] == "Normal").sum(),
        (feature_df["risk_band"] == "Suspicious").sum(),
        (feature_df["risk_band"] == "Malicious").sum(),
    )
    return feature_df
