"""
SQLite Audit Database Module
Stores and retrieves security alerts with full traceability.
"""
import json
import logging
import os
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime
from typing import Dict, List, Optional

import pandas as pd

from config import DATABASE_DIR, DEFAULT_DB_PATH, MODEL_VERSION

logger = logging.getLogger(__name__)

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS alerts (
    alert_id            TEXT PRIMARY KEY,
    timestamp           TEXT NOT NULL,
    source_ip           TEXT NOT NULL,
    dest_ip             TEXT,
    classification      TEXT NOT NULL,
    threat_category     TEXT NOT NULL,
    risk_score          INTEGER NOT NULL,
    anomaly_score       REAL NOT NULL,
    confidence          REAL NOT NULL,
    evidence_features   TEXT,
    feature_values      TEXT,
    recommended_action  TEXT,
    model_version       TEXT NOT NULL,
    status              TEXT NOT NULL DEFAULT 'new',
    created_at          TEXT NOT NULL,
    updated_at          TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ingestion_runs (
    run_id          TEXT PRIMARY KEY,
    run_timestamp   TEXT NOT NULL,
    source_file     TEXT,
    total_raw       INTEGER,
    valid_count     INTEGER,
    skipped_count   INTEGER,
    alert_count     INTEGER,
    skip_reasons    TEXT
);

CREATE INDEX IF NOT EXISTS idx_alerts_source_ip ON alerts(source_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_risk_score ON alerts(risk_score);
CREATE INDEX IF NOT EXISTS idx_alerts_classification ON alerts(classification);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts(created_at);
"""

VALID_STATUSES = {"new", "reviewed", "resolved"}


@contextmanager
def get_connection(db_path: str = DEFAULT_DB_PATH):
    """Context manager for SQLite connections."""
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def initialize_database(db_path: str = DEFAULT_DB_PATH) -> None:
    """Create database schema if it doesn't exist."""
    os.makedirs(os.path.dirname(db_path) if os.path.dirname(db_path) else ".", exist_ok=True)
    with get_connection(db_path) as conn:
        conn.executescript(SCHEMA_SQL)
    logger.info("Database initialized: %s", db_path)


def _serialize(obj) -> str:
    """Safely serialize to JSON string."""
    try:
        return json.dumps(obj, default=str)
    except Exception:
        return json.dumps(str(obj))


def store_alerts(
    alerts_df: pd.DataFrame,
    db_path: str = DEFAULT_DB_PATH,
) -> int:
    """
    Store alerts DataFrame to SQLite.

    Args:
        alerts_df: DataFrame with alert records.
        db_path:   Path to SQLite database.

    Returns:
        Number of alerts stored.
    """
    if alerts_df.empty:
        return 0

    initialize_database(db_path)

    now = datetime.utcnow().isoformat()
    stored = 0

    with get_connection(db_path) as conn:
        for _, row in alerts_df.iterrows():
            alert_id = str(uuid.uuid4())

            # Serialize evidence
            evidence = row.get("evidence", [])
            if isinstance(evidence, list):
                evidence_features_json = _serialize(
                    [e.get("indicator") for e in evidence]
                )
                feature_values_json = _serialize(
                    {e.get("indicator"): e.get("observed_value") for e in evidence}
                )
            else:
                evidence_features_json = _serialize([])
                feature_values_json = _serialize({})

            try:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO alerts (
                        alert_id, timestamp, source_ip, dest_ip,
                        classification, threat_category,
                        risk_score, anomaly_score, confidence,
                        evidence_features, feature_values,
                        recommended_action, model_version,
                        status, created_at, updated_at
                    ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        alert_id,
                        str(row.get("last_seen", now)),
                        str(row.get("source_ip", "")),
                        str(row.get("dest_ip_primary", "")),
                        str(row.get("classification", "Normal")),
                        str(row.get("risk_band", "Normal")),
                        int(row.get("risk_score", 0)),
                        float(row.get("anomaly_score", 0.0)),
                        float(row.get("classifier_confidence", 0.0)),
                        evidence_features_json,
                        feature_values_json,
                        str(row.get("recommended_action", "")),
                        MODEL_VERSION,
                        "new",
                        now,
                        now,
                    ),
                )
                stored += 1
            except Exception as e:
                logger.error("Failed to store alert for %s: %s", row.get("source_ip"), e)

    logger.info("Stored %d alerts to database: %s", stored, db_path)
    return stored


def store_ingestion_run(
    run_id: str,
    source_file: str,
    total_raw: int,
    valid_count: int,
    skipped_count: int,
    alert_count: int,
    skip_reasons: dict,
    db_path: str = DEFAULT_DB_PATH,
) -> None:
    """Record an ingestion run for audit trail."""
    initialize_database(db_path)
    now = datetime.utcnow().isoformat()
    with get_connection(db_path) as conn:
        conn.execute(
            """
            INSERT INTO ingestion_runs
            (run_id, run_timestamp, source_file, total_raw, valid_count,
             skipped_count, alert_count, skip_reasons)
            VALUES (?,?,?,?,?,?,?,?)
            """,
            (
                run_id, now, source_file, total_raw, valid_count,
                skipped_count, alert_count, _serialize(skip_reasons),
            ),
        )


def fetch_alerts(
    db_path: str = DEFAULT_DB_PATH,
    limit: int = 1000,
    status_filter: Optional[str] = None,
    min_risk: int = 0,
) -> pd.DataFrame:
    """
    Retrieve alerts from database.

    Args:
        db_path:       Path to SQLite database.
        limit:         Maximum number of records to return.
        status_filter: Filter by status ('new', 'reviewed', 'resolved').
        min_risk:      Minimum risk score filter.

    Returns:
        DataFrame of alert records.
    """
    if not os.path.exists(db_path):
        return pd.DataFrame()

    try:
        with get_connection(db_path) as conn:
            query = "SELECT * FROM alerts WHERE risk_score >= ?"
            params: list = [min_risk]

            if status_filter and status_filter in VALID_STATUSES:
                query += " AND status = ?"
                params.append(status_filter)

            query += " ORDER BY created_at DESC LIMIT ?"
            params.append(limit)

            cursor = conn.execute(query, params)
            rows = cursor.fetchall()
            if not rows:
                return pd.DataFrame()

            df = pd.DataFrame([dict(r) for r in rows])
            return df
    except Exception as e:
        logger.error("Failed to fetch alerts: %s", e)
        return pd.DataFrame()


def update_alert_status(
    alert_id: str,
    new_status: str,
    db_path: str = DEFAULT_DB_PATH,
) -> bool:
    """
    Update an alert's status.

    Args:
        alert_id:   UUID of the alert.
        new_status: One of 'new', 'reviewed', 'resolved'.
        db_path:    Path to SQLite database.

    Returns:
        True if updated, False otherwise.
    """
    if new_status not in VALID_STATUSES:
        logger.warning("Invalid status: %s", new_status)
        return False

    try:
        now = datetime.utcnow().isoformat()
        with get_connection(db_path) as conn:
            conn.execute(
                "UPDATE alerts SET status=?, updated_at=? WHERE alert_id=?",
                (new_status, now, alert_id),
            )
        return True
    except Exception as e:
        logger.error("Failed to update alert %s: %s", alert_id, e)
        return False


def get_alert_stats(db_path: str = DEFAULT_DB_PATH) -> Dict:
    """Return summary statistics from the alerts database."""
    if not os.path.exists(db_path):
        return {}

    try:
        with get_connection(db_path) as conn:
            row = conn.execute("""
                SELECT
                    COUNT(*) as total_alerts,
                    AVG(risk_score) as avg_risk,
                    MAX(risk_score) as max_risk,
                    SUM(CASE WHEN threat_category='Normal' THEN 1 ELSE 0 END) as normal_count,
                    SUM(CASE WHEN threat_category='Suspicious' THEN 1 ELSE 0 END) as suspicious_count,
                    SUM(CASE WHEN threat_category='Malicious' THEN 1 ELSE 0 END) as malicious_count,
                    SUM(CASE WHEN status='new' THEN 1 ELSE 0 END) as new_count,
                    SUM(CASE WHEN status='reviewed' THEN 1 ELSE 0 END) as reviewed_count,
                    SUM(CASE WHEN status='resolved' THEN 1 ELSE 0 END) as resolved_count
                FROM alerts
            """).fetchone()
            return dict(row) if row else {}
    except Exception as e:
        logger.error("Failed to get alert stats: %s", e)
        return {}
