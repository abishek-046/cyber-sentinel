"""
Behavioral Feature Engineering Module
Generates time-windowed behavioral features per source IP.
"""
import logging
from typing import Optional

import numpy as np
import pandas as pd

from config import FEATURE_COLUMNS, TIME_WINDOW_SECONDS

logger = logging.getLogger(__name__)


def _safe_ratio(numerator: float, denominator: float, default: float = 0.0) -> float:
    """Compute ratio safely."""
    if denominator == 0:
        return default
    return numerator / denominator


def _compute_protocol_diversity(protocols: pd.Series) -> float:
    """Shannon entropy-based protocol diversity (normalized 0-1)."""
    if protocols.empty:
        return 0.0
    counts = protocols.value_counts(normalize=True)
    if len(counts) <= 1:
        return 0.0
    entropy = -np.sum(counts * np.log2(counts + 1e-10))
    max_entropy = np.log2(len(counts))
    return float(entropy / max_entropy) if max_entropy > 0 else 0.0


def _compute_destination_diversity(dest_ips: pd.Series) -> float:
    """Destination IP diversity (unique ratio)."""
    if dest_ips.empty or len(dest_ips) == 0:
        return 0.0
    return float(dest_ips.nunique() / len(dest_ips))


def _is_private_ip(ip: str) -> bool:
    """Check if IP is RFC-1918 private."""
    if not isinstance(ip, str):
        return False
    try:
        parts = [int(p) for p in ip.split(".")]
        if len(parts) != 4:
            return False
        if parts[0] == 10:
            return True
        if parts[0] == 172 and 16 <= parts[1] <= 31:
            return True
        if parts[0] == 192 and parts[1] == 168:
            return True
    except (ValueError, AttributeError):
        pass
    return False


def engineer_features(
    df: pd.DataFrame,
    time_window_seconds: int = TIME_WINDOW_SECONDS,
    reference_window_df: Optional[pd.DataFrame] = None,
) -> pd.DataFrame:
    """
    Generate behavioral features aggregated per source IP over time windows.

    Args:
        df: Normalized telemetry DataFrame from ingestion.
        time_window_seconds: Window size for connection rate calculation.
        reference_window_df: Optional historical baseline for anomaly context.

    Returns:
        DataFrame with one row per source IP, indexed by source_ip.
        Contains all FEATURE_COLUMNS plus source_ip and timestamp metadata.
    """
    if df.empty:
        return pd.DataFrame(columns=["source_ip"] + FEATURE_COLUMNS)

    # Ensure timestamp is datetime
    df = df.copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df = df.dropna(subset=["timestamp"])

    if df.empty:
        return pd.DataFrame(columns=["source_ip"] + FEATURE_COLUMNS)

    feature_rows = []

    for src_ip, group in df.groupby("source_ip"):
        group = group.sort_values("timestamp")

        # Time span of this IP's activity
        ts_min = group["timestamp"].min()
        ts_max = group["timestamp"].max()
        duration_seconds = max(
            (ts_max - ts_min).total_seconds(), 1.0
        )

        # Basic counts
        event_count = len(group)
        unique_dest_count = group["dest_ip"].nunique() if "dest_ip" in group else 0
        unique_dest_port_count = group["dest_port"].nunique() if "dest_port" in group else 0

        # Auth events
        failed_logins = 0
        successful_logins = 0
        if "auth_status" in group.columns:
            failed_logins = int((group["auth_status"] == "failure").sum())
            successful_logins = int((group["auth_status"] == "success").sum())
        success_failure_ratio = _safe_ratio(
            successful_logins, failed_logins + successful_logins, 1.0
        )

        # Bytes and packets
        bytes_total = float(group["bytes"].sum()) if "bytes" in group else 0.0
        packets_total = float(group["packets"].sum()) if "packets" in group else 0.0

        # Estimate directional bytes
        # Events with dest_port < 1024 are likely outbound client requests
        if "dest_port" in group.columns:
            outbound_mask = group["dest_port"] >= 1024
            bytes_sent = float(group.loc[outbound_mask, "bytes"].sum()) \
                if "bytes" in group.columns else bytes_total * 0.5
            bytes_received = bytes_total - bytes_sent
        else:
            bytes_sent = bytes_total * 0.6
            bytes_received = bytes_total * 0.4

        # Connection rate per minute
        connection_rate = float(event_count / (duration_seconds / 60.0))

        # Protocol diversity
        proto_diversity = _compute_protocol_diversity(group["protocol"]) \
            if "protocol" in group.columns else 0.0

        # Destination diversity
        dest_diversity = _compute_destination_diversity(group["dest_ip"]) \
            if "dest_ip" in group.columns else 0.0

        # Unusual peer indicator: contacting private IPs from different subnet
        unusual_peer = 0.0
        if "dest_ip" in group.columns:
            src_is_private = _is_private_ip(str(src_ip))
            if src_is_private:
                # Get src subnet prefix
                src_parts = str(src_ip).split(".")
                src_prefix = ".".join(src_parts[:2]) if len(src_parts) >= 2 else ""
                private_dests = group["dest_ip"].apply(
                    lambda ip: _is_private_ip(str(ip))
                )
                if private_dests.any():
                    cross_subnet_dests = group.loc[private_dests, "dest_ip"].apply(
                        lambda ip: not str(ip).startswith(src_prefix) if src_prefix else True
                    )
                    unusual_peer = float(cross_subnet_dests.sum() / max(event_count, 1))

        # Unusual service indicator: accessing high-risk/uncommon ports
        unusual_service = 0.0
        if "dest_port" in group.columns:
            high_risk_ports = {22, 23, 445, 3389, 1433, 3306, 5432, 6379, 27017, 5900}
            unusual_port_count = group["dest_port"].isin(high_risk_ports).sum()
            unusual_service = float(unusual_port_count / max(event_count, 1))

        # Outbound transfer indicator: heavy outbound relative to inbound
        outbound_indicator = 0.0
        if bytes_total > 0:
            outbound_ratio = bytes_sent / bytes_total
            # Flag if outbound ratio is significantly above normal (> 70%)
            outbound_indicator = float(max(0.0, (outbound_ratio - 0.5) * 2))

        feature_rows.append({
            "source_ip": src_ip,
            "first_seen": ts_min,
            "last_seen": ts_max,
            "event_count": float(event_count),
            "unique_destination_count": float(unique_dest_count),
            "unique_destination_port_count": float(unique_dest_port_count),
            "failed_login_count": float(failed_logins),
            "successful_login_count": float(successful_logins),
            "success_failure_ratio": float(success_failure_ratio),
            "bytes_sent": float(bytes_sent),
            "bytes_received": float(bytes_received),
            "packet_count": float(packets_total),
            "connection_rate": float(connection_rate),
            "protocol_diversity": float(proto_diversity),
            "destination_diversity": float(dest_diversity),
            "unusual_peer_indicator": float(unusual_peer),
            "unusual_service_indicator": float(unusual_service),
            "outbound_transfer_indicator": float(outbound_indicator),
        })

    if not feature_rows:
        return pd.DataFrame(columns=["source_ip"] + FEATURE_COLUMNS)

    feature_df = pd.DataFrame(feature_rows)

    # Clamp all feature values
    for col in FEATURE_COLUMNS:
        if col in feature_df.columns:
            feature_df[col] = feature_df[col].clip(lower=0.0)

    # Fill any NaN
    feature_df[FEATURE_COLUMNS] = feature_df[FEATURE_COLUMNS].fillna(0.0)

    logger.info(
        "Feature engineering complete: %d source IPs, %d features",
        len(feature_df), len(FEATURE_COLUMNS),
    )
    return feature_df


def get_feature_matrix(feature_df: pd.DataFrame) -> np.ndarray:
    """Extract numpy feature matrix from feature DataFrame."""
    available = [c for c in FEATURE_COLUMNS if c in feature_df.columns]
    return feature_df[available].values.astype(np.float64)
