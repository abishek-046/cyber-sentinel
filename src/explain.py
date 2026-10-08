"""
Explainable Evidence Engine
Generates human-readable, factual evidence for each alert.
Maps observed feature values to specific threat indicators.
"""
import logging
from typing import Any, Dict, List, Optional

import pandas as pd

from config import EVIDENCE_THRESHOLDS, FEATURE_COLUMNS

logger = logging.getLogger(__name__)


def _fmt_bytes(b: float) -> str:
    """Format bytes into human-readable string."""
    b = float(b)
    if b >= 1e9:
        return f"{b/1e9:.2f} GB"
    elif b >= 1e6:
        return f"{b/1e6:.2f} MB"
    elif b >= 1e3:
        return f"{b/1e3:.2f} KB"
    return f"{int(b)} bytes"


def _fmt_rate(r: float) -> str:
    return f"{r:.1f}/min"


def _make_evidence_item(
    indicator: str,
    observed_value: Any,
    threshold: Any,
    description: str,
    impact: float,
) -> Dict:
    return {
        "indicator": indicator,
        "observed_value": observed_value,
        "threshold": threshold,
        "description": description,
        "impact": round(float(impact), 3),
    }


def generate_evidence(row: pd.Series, classification: str) -> List[Dict]:
    """
    Generate ordered evidence list for a single source IP based on
    observed feature values and threat classification.

    Args:
        row:            Feature row (pd.Series) with computed feature values.
        classification: Predicted threat class.

    Returns:
        List of evidence dicts, ordered by impact descending (max 5 items).
    """
    evidence = []
    t = EVIDENCE_THRESHOLDS

    def get(col: str, default=0.0):
        val = row.get(col, default)
        try:
            return float(val)
        except (TypeError, ValueError):
            return float(default)

    unique_dest_ports = get("unique_destination_port_count")
    connection_rate = get("connection_rate")
    failed_logins = get("failed_login_count")
    successful_logins = get("successful_login_count")
    success_ratio = get("success_failure_ratio")
    bytes_sent = get("bytes_sent")
    bytes_received = get("bytes_received")
    unique_dests = get("unique_destination_count")
    dest_diversity = get("destination_diversity")
    unusual_peer = get("unusual_peer_indicator")
    unusual_service = get("unusual_service_indicator")
    event_count = get("event_count")
    outbound_indicator = get("outbound_transfer_indicator")
    protocol_diversity = get("protocol_diversity")

    if classification == "Port Scan":
        if unique_dest_ports >= t["port_scan_unique_ports"]:
            impact = min(1.0, unique_dest_ports / 500)
            evidence.append(_make_evidence_item(
                "high_unique_destination_ports",
                int(unique_dest_ports),
                int(t["port_scan_unique_ports"]),
                f"Unique destination ports scanned: {int(unique_dest_ports)} "
                f"(threshold: {int(t['port_scan_unique_ports'])})",
                impact,
            ))

        if connection_rate >= t["port_scan_connection_rate"]:
            impact = min(1.0, connection_rate / 100)
            evidence.append(_make_evidence_item(
                "high_connection_rate",
                f"{connection_rate:.1f}/min",
                f"{t['port_scan_connection_rate']}/min",
                f"Connection rate: {connection_rate:.1f}/min "
                f"(threshold: {t['port_scan_connection_rate']}/min)",
                impact,
            ))

        if unusual_service > 0.3:
            evidence.append(_make_evidence_item(
                "high_unusual_service_access",
                f"{unusual_service:.2f}",
                "0.30",
                f"Proportion of connections to unusual/high-risk services: "
                f"{unusual_service:.2%}",
                unusual_service,
            ))

        if event_count > 100:
            evidence.append(_make_evidence_item(
                "high_event_volume",
                int(event_count),
                100,
                f"Total connection events: {int(event_count)} (indicative of automated scanning)",
                min(1.0, event_count / 1000),
            ))

    elif classification == "Brute Force":
        if failed_logins >= t["brute_force_failed_logins"]:
            impact = min(1.0, failed_logins / 100)
            evidence.append(_make_evidence_item(
                "high_failed_login_count",
                int(failed_logins),
                int(t["brute_force_failed_logins"]),
                f"Failed authentication attempts: {int(failed_logins)} "
                f"(threshold: {int(t['brute_force_failed_logins'])})",
                impact,
            ))

        if success_ratio <= t["brute_force_success_failure_ratio"] and \
                (failed_logins + successful_logins) > 0:
            evidence.append(_make_evidence_item(
                "low_success_failure_ratio",
                f"{success_ratio:.3f}",
                f"{t['brute_force_success_failure_ratio']:.2f}",
                f"Auth success rate: {success_ratio:.1%} — "
                f"consistent with repeated failed login attempts",
                min(1.0, 1.0 - success_ratio),
            ))

        total_auth = failed_logins + successful_logins
        if total_auth > 10:
            evidence.append(_make_evidence_item(
                "high_total_auth_attempts",
                int(total_auth),
                10,
                f"Total authentication attempts: {int(total_auth)}",
                min(1.0, total_auth / 150),
            ))

        if connection_rate > 5:
            evidence.append(_make_evidence_item(
                "sustained_connection_rate",
                f"{connection_rate:.1f}/min",
                "5.0/min",
                f"Sustained connection rate: {connection_rate:.1f}/min",
                min(1.0, connection_rate / 50),
            ))

    elif classification == "Lateral Movement":
        if unusual_peer >= t["lateral_movement_unusual_peer"]:
            evidence.append(_make_evidence_item(
                "unusual_internal_peer_connections",
                f"{unusual_peer:.2f}",
                f"{t['lateral_movement_unusual_peer']:.2f}",
                f"Cross-subnet internal connections: "
                f"{unusual_peer:.1%} of traffic to unusual internal peers",
                unusual_peer,
            ))

        if unique_dests > 10:
            evidence.append(_make_evidence_item(
                "high_unique_internal_destinations",
                int(unique_dests),
                10,
                f"Unique internal destinations reached: {int(unique_dests)} "
                f"— indicative of lateral traversal",
                min(1.0, unique_dests / 50),
            ))

        if unusual_service > 0.2:
            evidence.append(_make_evidence_item(
                "unusual_internal_service_access",
                f"{unusual_service:.2f}",
                "0.20",
                f"Access to admin/management services: {unusual_service:.1%} of connections",
                unusual_service,
            ))

        if dest_diversity > 0.5:
            evidence.append(_make_evidence_item(
                "high_destination_diversity",
                f"{dest_diversity:.2f}",
                "0.50",
                f"Destination diversity score: {dest_diversity:.2f} — "
                f"contacting many unique hosts relative to total events",
                dest_diversity,
            ))

    elif classification == "Data Exfiltration":
        if bytes_sent >= t["exfiltration_bytes_sent"]:
            impact = min(1.0, bytes_sent / 50_000_000)
            evidence.append(_make_evidence_item(
                "high_outbound_data_volume",
                _fmt_bytes(bytes_sent),
                _fmt_bytes(t["exfiltration_bytes_sent"]),
                f"Outbound data volume: {_fmt_bytes(bytes_sent)} "
                f"(threshold: {_fmt_bytes(t['exfiltration_bytes_sent'])})",
                impact,
            ))

        if dest_diversity >= t["exfiltration_destination_diversity"]:
            evidence.append(_make_evidence_item(
                "unusual_destination_diversity",
                f"{dest_diversity:.2f}",
                f"{t['exfiltration_destination_diversity']:.2f}",
                f"Destination diversity: {dest_diversity:.2f} — "
                f"data distributed to many external endpoints",
                dest_diversity,
            ))

        if outbound_indicator > 0.5:
            evidence.append(_make_evidence_item(
                "abnormal_outbound_ratio",
                f"{outbound_indicator:.2f}",
                "0.50",
                f"Outbound transfer ratio indicator: {outbound_indicator:.2f} — "
                f"outbound traffic dominates session",
                outbound_indicator,
            ))

        if unique_dests > 8:
            evidence.append(_make_evidence_item(
                "multiple_external_destinations",
                int(unique_dests),
                8,
                f"Unique destinations contacted: {int(unique_dests)}",
                min(1.0, unique_dests / 40),
            ))

    # For all classifications — add anomaly context if present
    anomaly_score = float(row.get("anomaly_score", 0.0))
    if anomaly_score > 0.7 and not evidence:
        evidence.append(_make_evidence_item(
            "statistical_anomaly",
            f"{anomaly_score:.3f}",
            "0.700",
            f"Statistical anomaly score: {anomaly_score:.3f} — "
            f"behavior deviates significantly from baseline",
            anomaly_score,
        ))

    # Sort by impact descending, keep top 5
    evidence.sort(key=lambda x: x["impact"], reverse=True)
    return evidence[:5]


def add_evidence(feature_df: pd.DataFrame) -> pd.DataFrame:
    """
    Add 'evidence' and 'recommended_action' columns to the feature DataFrame.

    Args:
        feature_df: DataFrame with classification, anomaly_score, and feature columns.

    Returns:
        feature_df with 'evidence' and 'recommended_action' columns added.
    """
    if feature_df.empty:
        return feature_df

    feature_df = feature_df.copy()
    evidence_list = []
    action_list = []

    for _, row in feature_df.iterrows():
        classification = str(row.get("classification", "Normal"))
        risk_score = int(row.get("risk_score", 0))
        evidence = generate_evidence(row, classification)
        evidence_list.append(evidence)

        # Recommended action based on risk and classification
        action = _recommend_action(classification, risk_score, evidence)
        action_list.append(action)

    feature_df["evidence"] = evidence_list
    feature_df["recommended_action"] = action_list

    return feature_df


def _recommend_action(classification: str, risk_score: int, evidence: list) -> str:
    """Generate recommended action for an alert."""
    if classification == "Normal" or risk_score <= 30:
        return "Monitor: Continue standard network monitoring. No immediate action required."

    if risk_score <= 70:
        actions = {
            "Port Scan": "Investigate: Review firewall logs for source IP. Consider rate-limiting "
                         "or blocking if scanning continues. Assess whether source is authorized.",
            "Brute Force": "Investigate: Review authentication logs for source IP. "
                           "Consider temporary account lockout or IP block. "
                           "Verify no accounts were compromised.",
            "Lateral Movement": "Escalate: Review access logs for internal host connections. "
                                "Verify credentials are not compromised. "
                                "Check for new user account creation.",
            "Data Exfiltration": "Investigate: Identify outbound destination endpoints. "
                                 "Review DLP logs. Verify data classification of transferred content.",
        }
        return actions.get(classification,
                           "Investigate: Review activity for source IP and assess threat context.")

    # High risk
    actions = {
        "Port Scan": "Block: Immediately block source IP at perimeter firewall. "
                     "Capture full packet data. File security incident.",
        "Brute Force": "Block & Contain: Block source IP. Lock targeted accounts. "
                       "Reset credentials for any compromised accounts. File incident.",
        "Lateral Movement": "Contain & Isolate: Isolate affected host from network. "
                            "Conduct forensic investigation. Reset all credentials. "
                            "File P1 security incident.",
        "Data Exfiltration": "Emergency Response: Block outbound connections from source. "
                             "Identify and classify exfiltrated data. "
                             "Notify data protection officer. File P1 incident.",
    }
    return actions.get(classification,
                       "Escalate: Immediately escalate to security operations team.")
