"""
Telemetry Ingestion Module
Handles CSV and JSON/JSONL telemetry with full validation and normalization.
"""
import io
import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Tuple

import numpy as np
import pandas as pd

from config import BACKGROUND_EVENT_TYPES, OPTIONAL_TELEMETRY_FIELDS, REQUIRED_TELEMETRY_FIELDS

logger = logging.getLogger(__name__)

# Valid protocols
VALID_PROTOCOLS = {"tcp", "udp", "icmp", "http", "https", "dns", "ssh", "ftp",
                   "smtp", "dhcp", "arp", "rdp", "smb", "unknown"}

# Valid auth statuses
VALID_AUTH_STATUSES = {"success", "failure", "none", "unknown", ""}

# IP address pattern
IP_PATTERN = re.compile(
    r"^(\d{1,3}\.){3}\d{1,3}$"
)


@dataclass
class IngestionResult:
    """Result of a telemetry ingestion operation."""
    records: pd.DataFrame
    total_raw: int = 0
    valid_count: int = 0
    skipped_count: int = 0
    skip_reasons: List[dict] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    @property
    def skip_summary(self) -> dict:
        reasons = {}
        for r in self.skip_reasons:
            reason = r.get("reason", "unknown")
            reasons[reason] = reasons.get(reason, 0) + 1
        return reasons


def _is_valid_ip(ip: str) -> bool:
    """Validate IPv4 address."""
    if not isinstance(ip, str):
        return False
    ip = ip.strip()
    if not IP_PATTERN.match(ip):
        return False
    parts = ip.split(".")
    return all(0 <= int(p) <= 255 for p in parts)


def _normalize_ip(ip) -> Optional[str]:
    """Normalize IP address string."""
    if pd.isna(ip) or ip is None:
        return None
    ip = str(ip).strip()
    if _is_valid_ip(ip):
        return ip
    return None


def _normalize_timestamp(ts) -> Optional[datetime]:
    """Parse and normalize timestamp."""
    if pd.isna(ts) or ts is None:
        return None
    if isinstance(ts, datetime):
        return ts
    ts_str = str(ts).strip()
    formats = [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S.%f",
        "%d/%m/%Y %H:%M:%S",
        "%m/%d/%Y %H:%M:%S",
        "%Y%m%d%H%M%S",
    ]
    for fmt in formats:
        try:
            return datetime.strptime(ts_str, fmt)
        except (ValueError, TypeError):
            continue
    try:
        return pd.to_datetime(ts_str).to_pydatetime()
    except Exception:
        return None


def _normalize_protocol(proto) -> str:
    """Normalize protocol field."""
    if pd.isna(proto) or proto is None:
        return "unknown"
    proto = str(proto).strip().lower()
    return proto if proto in VALID_PROTOCOLS else "unknown"


def _safe_int(val, default=0) -> int:
    """Safely convert to int."""
    try:
        if pd.isna(val):
            return default
        return int(float(val))
    except (ValueError, TypeError):
        return default


def _safe_float(val, default=0.0) -> float:
    """Safely convert to float."""
    try:
        if pd.isna(val):
            return default
        result = float(val)
        if np.isnan(result) or np.isinf(result):
            return default
        return result
    except (ValueError, TypeError):
        return default


def _normalize_port(port, default=0) -> int:
    """Normalize port number."""
    p = _safe_int(port, default)
    return p if 0 <= p <= 65535 else default


def _normalize_auth_status(status) -> str:
    """Normalize auth_status field."""
    if pd.isna(status) or status is None:
        return "none"
    s = str(status).strip().lower()
    return s if s in VALID_AUTH_STATUSES else "unknown"


def _normalize_event_type(event_type) -> str:
    """Normalize event_type field."""
    if pd.isna(event_type) or event_type is None:
        return "network_flow"
    et = str(event_type).strip().lower().replace(" ", "_").replace("-", "_")
    return et


def _validate_record(row: pd.Series, idx: int) -> Tuple[bool, str]:
    """Validate a single record. Returns (is_valid, reason_if_invalid)."""
    # Check required fields exist and are non-empty
    for field_name in REQUIRED_TELEMETRY_FIELDS:
        val = row.get(field_name)
        if val is None or (isinstance(val, float) and np.isnan(val)):
            return False, f"missing_required_field:{field_name}"

    # Validate timestamp
    if row.get("_ts_valid") is False:
        return False, "invalid_timestamp"

    # Validate IPs
    if row.get("_src_ip_valid") is False:
        return False, "invalid_source_ip"
    if row.get("_dst_ip_valid") is False:
        return False, "invalid_dest_ip"

    # Validate bytes and packets are non-negative
    if row.get("bytes", 0) < 0:
        return False, "negative_bytes"
    if row.get("packets", 0) < 0:
        return False, "negative_packets"

    return True, ""


def _normalize_row(row: dict) -> dict:
    """Normalize a single row dict."""
    normalized = {}

    # Timestamp
    ts = _normalize_timestamp(row.get("timestamp"))
    normalized["timestamp"] = ts
    normalized["_ts_valid"] = ts is not None

    # IPs
    src_ip = _normalize_ip(row.get("source_ip"))
    dst_ip = _normalize_ip(row.get("dest_ip"))
    normalized["source_ip"] = src_ip if src_ip else row.get("source_ip", "")
    normalized["dest_ip"] = dst_ip if dst_ip else row.get("dest_ip", "")
    normalized["_src_ip_valid"] = src_ip is not None
    normalized["_dst_ip_valid"] = dst_ip is not None

    # Ports
    normalized["src_port"] = _normalize_port(row.get("src_port", 0))
    normalized["dest_port"] = _normalize_port(row.get("dest_port", 0))

    # Protocol
    normalized["protocol"] = _normalize_protocol(row.get("protocol"))

    # Numeric
    normalized["bytes"] = _safe_float(row.get("bytes", 0))
    normalized["packets"] = _safe_float(row.get("packets", 0))

    # Auth status
    normalized["auth_status"] = _normalize_auth_status(row.get("auth_status"))

    # Event type
    normalized["event_type"] = _normalize_event_type(row.get("event_type"))

    return normalized


def _load_csv(source) -> pd.DataFrame:
    """Load CSV from file path or file-like object."""
    try:
        if hasattr(source, "read"):
            content = source.read()
            if isinstance(content, bytes):
                content = content.decode("utf-8", errors="replace")
            return pd.read_csv(io.StringIO(content), dtype=str)
        else:
            return pd.read_csv(source, dtype=str)
    except Exception as e:
        raise ValueError(f"Failed to read CSV: {e}") from e


def _load_json(source) -> pd.DataFrame:
    """Load JSON/JSONL from file path or file-like object."""
    try:
        if hasattr(source, "read"):
            content = source.read()
            if isinstance(content, bytes):
                content = content.decode("utf-8", errors="replace")
        else:
            with open(source, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()

        content = content.strip()
        # Try JSONL first
        if content.startswith("{"):
            lines = [l.strip() for l in content.splitlines() if l.strip()]
            records = []
            for line in lines:
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
            if records:
                return pd.DataFrame(records)
        # Try JSON array
        data = json.loads(content)
        if isinstance(data, list):
            return pd.DataFrame(data)
        elif isinstance(data, dict):
            return pd.DataFrame([data])
        raise ValueError("Unexpected JSON structure")
    except Exception as e:
        raise ValueError(f"Failed to read JSON: {e}") from e


def ingest_telemetry(source, file_format: str = "csv") -> IngestionResult:
    """
    Ingest telemetry from a CSV or JSON/JSONL source.

    Args:
        source: File path string or file-like object.
        file_format: 'csv' or 'json'

    Returns:
        IngestionResult with validated and normalized records.
    """
    result = IngestionResult(records=pd.DataFrame())

    # Load raw data
    try:
        if file_format.lower() in ("json", "jsonl"):
            raw_df = _load_json(source)
        else:
            raw_df = _load_csv(source)
    except ValueError as e:
        result.warnings.append(str(e))
        logger.error("Ingestion load error: %s", e)
        return result

    result.total_raw = len(raw_df)
    if result.total_raw == 0:
        result.warnings.append("Empty telemetry source — no records to process.")
        return result

    # Normalize column names
    raw_df.columns = [c.strip().lower().replace(" ", "_").replace("-", "_")
                      for c in raw_df.columns]

    # Handle column aliases
    col_aliases = {
        "src_ip": "source_ip",
        "dst_ip": "dest_ip",
        "destination_ip": "dest_ip",
        "dport": "dest_port",
        "sport": "src_port",
        "byte_count": "bytes",
        "pkt_count": "packets",
        "packet_count": "packets",
        "auth": "auth_status",
        "type": "event_type",
    }
    raw_df.rename(columns={k: v for k, v in col_aliases.items()
                            if k in raw_df.columns}, inplace=True)

    normalized_rows = []
    skip_reasons = []

    for idx, row in raw_df.iterrows():
        row_dict = row.to_dict()
        try:
            norm = _normalize_row(row_dict)
        except Exception as e:
            skip_reasons.append({"row": idx, "reason": "normalization_error",
                                  "detail": str(e)})
            logger.debug("Row %d normalization error: %s", idx, e)
            continue

        # Validate
        norm_series = pd.Series(norm)
        is_valid, reason = _validate_record(norm_series, idx)
        if not is_valid:
            skip_reasons.append({"row": idx, "reason": reason})
            logger.debug("Row %d skipped: %s", idx, reason)
            continue

        # Remove internal validation flags
        norm.pop("_ts_valid", None)
        norm.pop("_src_ip_valid", None)
        norm.pop("_dst_ip_valid", None)

        normalized_rows.append(norm)

    result.skip_reasons = skip_reasons
    result.skipped_count = len(skip_reasons)

    if not normalized_rows:
        result.warnings.append("No valid records after normalization/validation.")
        return result

    df = pd.DataFrame(normalized_rows)

    # Sort by timestamp
    df.sort_values("timestamp", inplace=True)
    df.reset_index(drop=True, inplace=True)

    result.records = df
    result.valid_count = len(df)

    logger.info(
        "Ingestion complete: %d raw, %d valid, %d skipped",
        result.total_raw, result.valid_count, result.skipped_count,
    )
    return result


def filter_background_traffic(df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """
    Separate background/noise traffic from analytically relevant events.

    Returns:
        (foreground_df, background_df)
    """
    if df.empty:
        return df, pd.DataFrame(columns=df.columns)

    is_background = df["event_type"].isin(BACKGROUND_EVENT_TYPES)
    # Also filter broadcast/multicast dest IPs
    if "dest_ip" in df.columns:
        is_background = is_background | df["dest_ip"].str.endswith(".255", na=False)
        is_background = is_background | (df["dest_ip"] == "255.255.255.255")
        is_background = is_background | df["dest_ip"].str.startswith("224.", na=False)
        is_background = is_background | df["dest_ip"].str.startswith("239.", na=False)

    return df[~is_background].copy(), df[is_background].copy()
