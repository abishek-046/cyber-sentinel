"""
Detection Pipeline Orchestration
Coordinates all stages: ingestion → features → anomaly → classification → risk → evidence → audit.
Maintains full traceability from raw event through to alert.
"""
import logging
import os
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional

import pandas as pd

from config import DEFAULT_DB_PATH, DEFAULT_MAX_RISK
from src.classification import classify_threats
from src.database import fetch_alerts, store_alerts, store_ingestion_run
from src.detection import detect_anomalies
from src.explain import add_evidence
from src.features import engineer_features
from src.ingestion import IngestionResult, filter_background_traffic, ingest_telemetry
from src.policy import PolicyResult, evaluate_policy
from src.risk import score_risks

logger = logging.getLogger(__name__)


@dataclass
class PipelineResult:
    """Complete result of a detection pipeline run."""
    run_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    source_file: str = ""

    # Ingestion stats
    total_raw: int = 0
    valid_count: int = 0
    skipped_count: int = 0
    skip_reasons: dict = field(default_factory=dict)
    background_count: int = 0

    # Detection results
    alerts_df: pd.DataFrame = field(default_factory=pd.DataFrame)
    alert_count: int = 0
    normal_count: int = 0
    suspicious_count: int = 0
    malicious_count: int = 0

    # Policy
    policy_result: Optional[PolicyResult] = None

    # Timing
    started_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    completed_at: str = ""

    # Errors
    errors: List[str] = field(default_factory=list)

    @property
    def success(self) -> bool:
        return len(self.errors) == 0

    @property
    def summary(self) -> dict:
        return {
            "run_id": self.run_id,
            "source_file": self.source_file,
            "total_raw": self.total_raw,
            "valid_count": self.valid_count,
            "skipped_count": self.skipped_count,
            "background_count": self.background_count,
            "alert_count": self.alert_count,
            "normal_count": self.normal_count,
            "suspicious_count": self.suspicious_count,
            "malicious_count": self.malicious_count,
            "policy": self.policy_result.to_dict() if self.policy_result else None,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
        }


def run_pipeline(
    source,
    file_format: str = "csv",
    source_file: str = "",
    max_risk: int = DEFAULT_MAX_RISK,
    db_path: str = DEFAULT_DB_PATH,
    store_to_db: bool = True,
) -> PipelineResult:
    """
    Execute the complete detection pipeline.

    Pipeline stages:
        1. Telemetry Ingestion & Validation
        2. Background Traffic Filtering
        3. Behavioral Feature Engineering
        4. Anomaly Detection (Isolation Forest)
        5. Threat Classification (Random Forest)
        6. Risk Scoring
        7. Evidence Generation
        8. SQLite Audit Storage
        9. Policy Evaluation

    Args:
        source:       File path or file-like object.
        file_format:  'csv' or 'json'.
        source_file:  Original filename for audit trail.
        max_risk:     Policy maximum risk threshold.
        db_path:      SQLite database path.
        store_to_db:  Whether to persist alerts.

    Returns:
        PipelineResult with all outputs.
    """
    result = PipelineResult(source_file=source_file)
    logger.info("Pipeline started: run_id=%s source=%s", result.run_id, source_file)

    # ── Stage 1: Ingestion ───────────────────────────────────────────────────
    try:
        ingest_result: IngestionResult = ingest_telemetry(source, file_format)
        result.total_raw = ingest_result.total_raw
        result.valid_count = ingest_result.valid_count
        result.skipped_count = ingest_result.skipped_count
        result.skip_reasons = ingest_result.skip_summary

        if ingest_result.records.empty:
            result.errors.append("No valid records after ingestion.")
            result.completed_at = datetime.utcnow().isoformat()
            return result
    except Exception as e:
        result.errors.append(f"Ingestion error: {e}")
        logger.exception("Ingestion failed")
        result.completed_at = datetime.utcnow().isoformat()
        return result

    # ── Stage 2: Background Filtering ────────────────────────────────────────
    try:
        foreground_df, background_df = filter_background_traffic(ingest_result.records)
        result.background_count = len(background_df)
        logger.info(
            "Traffic filtering: %d foreground, %d background",
            len(foreground_df), len(background_df),
        )

        if foreground_df.empty:
            result.alerts_df = pd.DataFrame()
            result.completed_at = datetime.utcnow().isoformat()
            return result
    except Exception as e:
        result.errors.append(f"Background filtering error: {e}")
        foreground_df = ingest_result.records
        logger.warning("Background filtering failed, using all records: %s", e)

    # ── Stage 3: Feature Engineering ─────────────────────────────────────────
    try:
        feature_df = engineer_features(foreground_df)
        if feature_df.empty:
            result.errors.append("Feature engineering produced no output.")
            result.completed_at = datetime.utcnow().isoformat()
            return result
    except Exception as e:
        result.errors.append(f"Feature engineering error: {e}")
        logger.exception("Feature engineering failed")
        result.completed_at = datetime.utcnow().isoformat()
        return result

    # ── Stage 4: Anomaly Detection ───────────────────────────────────────────
    try:
        feature_df = detect_anomalies(feature_df)
    except Exception as e:
        result.errors.append(f"Anomaly detection error: {e}")
        logger.exception("Anomaly detection failed")
        feature_df["anomaly_score"] = 0.5

    # ── Stage 5: Threat Classification ──────────────────────────────────────
    try:
        feature_df = classify_threats(feature_df)
    except Exception as e:
        result.errors.append(f"Classification error: {e}")
        logger.exception("Classification failed")
        feature_df["classification"] = "Normal"
        feature_df["classifier_confidence"] = 0.0

    # ── Stage 6: Risk Scoring ────────────────────────────────────────────────
    try:
        # Temporarily add empty evidence for risk scoring
        if "evidence" not in feature_df.columns:
            feature_df["evidence"] = [[] for _ in range(len(feature_df))]
        feature_df = score_risks(feature_df)
    except Exception as e:
        result.errors.append(f"Risk scoring error: {e}")
        logger.exception("Risk scoring failed")
        feature_df["risk_score"] = 0
        feature_df["risk_band"] = "Normal"

    # ── Stage 7: Evidence Generation ─────────────────────────────────────────
    try:
        feature_df = add_evidence(feature_df)
        # Re-score with actual evidence
        feature_df = score_risks(feature_df)
    except Exception as e:
        result.errors.append(f"Evidence generation error: {e}")
        logger.exception("Evidence generation failed")

    # ── Compute primary dest_ip per source IP for audit ──────────────────────
    if "dest_ip" in ingest_result.records.columns:
        dest_map = (
            ingest_result.records
            .groupby("source_ip")["dest_ip"]
            .agg(lambda x: x.mode().iloc[0] if len(x) > 0 else "")
        )
        feature_df["dest_ip_primary"] = feature_df["source_ip"].map(dest_map).fillna("")

    # ── Stage 8: SQLite Audit ─────────────────────────────────────────────────
    if store_to_db:
        try:
            stored = store_alerts(feature_df, db_path=db_path)
            store_ingestion_run(
                run_id=result.run_id,
                source_file=source_file,
                total_raw=result.total_raw,
                valid_count=result.valid_count,
                skipped_count=result.skipped_count,
                alert_count=stored,
                skip_reasons=result.skip_reasons,
                db_path=db_path,
            )
        except Exception as e:
            result.errors.append(f"Database storage error: {e}")
            logger.exception("Database storage failed")

    # ── Stage 9: Policy Evaluation ───────────────────────────────────────────
    result.policy_result = evaluate_policy(feature_df, max_risk=max_risk)

    # ── Compile results ───────────────────────────────────────────────────────
    result.alerts_df = feature_df
    result.alert_count = len(feature_df)
    result.normal_count = int((feature_df["risk_band"] == "Normal").sum())
    result.suspicious_count = int((feature_df["risk_band"] == "Suspicious").sum())
    result.malicious_count = int((feature_df["risk_band"] == "Malicious").sum())
    result.completed_at = datetime.utcnow().isoformat()

    logger.info(
        "Pipeline complete: %d alerts (Normal:%d, Suspicious:%d, Malicious:%d), "
        "policy=%s",
        result.alert_count,
        result.normal_count,
        result.suspicious_count,
        result.malicious_count,
        result.policy_result.status_label if result.policy_result else "N/A",
    )
    return result
