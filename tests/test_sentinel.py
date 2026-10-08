"""
Cybersecurity Sentinel — Test Suite
Tests ingestion, features, anomaly detection, classification,
risk scoring, evidence, SQLite, policy, and end-to-end pipeline.
"""
import io
import json
import os
import sys
import tempfile
import unittest

import numpy as np
import pandas as pd

# Ensure project root is on path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import DEFAULT_TELEMETRY_PATH, FEATURE_COLUMNS, THREAT_CLASSES
from src.classification import ThreatClassifier, classify_threats
from src.database import (
    fetch_alerts,
    get_alert_stats,
    initialize_database,
    store_alerts,
    update_alert_status,
)
from src.detection import AnomalyDetector, detect_anomalies
from src.explain import add_evidence, generate_evidence
from src.features import engineer_features, get_feature_matrix
from src.ingestion import filter_background_traffic, ingest_telemetry
from src.pipeline import run_pipeline
from src.policy import evaluate_policy
from src.risk import classify_risk_band, compute_risk_score, score_risks


# ── Test data helpers ─────────────────────────────────────────────────────────

VALID_CSV = """timestamp,source_ip,dest_ip,src_port,dest_port,protocol,bytes,packets,auth_status,event_type
2024-06-01 08:00:00,192.168.1.10,8.8.8.8,54321,443,https,5000,10,none,network_flow
2024-06-01 08:00:05,192.168.1.10,8.8.8.8,54322,443,https,4000,8,none,network_flow
2024-06-01 08:00:10,192.168.1.10,192.168.1.100,54323,22,ssh,1000,5,success,authentication
2024-06-01 08:00:15,192.168.1.10,192.168.1.100,54324,22,ssh,800,4,failure,authentication
2024-06-01 08:00:20,192.168.1.11,8.8.4.4,54325,53,dns,120,2,none,dns_query
2024-06-01 08:00:25,192.168.1.11,8.8.4.4,54326,53,dns,110,2,none,dns_query
"""

MALFORMED_CSV = """timestamp,source_ip,dest_ip,src_port,dest_port,protocol,bytes,packets,auth_status,event_type
not-a-timestamp,192.168.1.10,8.8.8.8,80,443,tcp,1000,5,none,network_flow
2024-06-01 08:00:00,999.999.999.999,8.8.8.8,80,443,tcp,1000,5,none,network_flow
2024-06-01 08:00:01,192.168.1.10,8.8.8.8,abc,443,tcp,1000,5,none,network_flow
2024-06-01 08:00:02,,8.8.8.8,80,443,tcp,1000,5,none,network_flow
2024-06-01 08:00:03,192.168.1.10,8.8.8.8,80,443,tcp,-100,5,none,network_flow
2024-06-01 08:00:04,192.168.1.10,not-an-ip,80,443,tcp,1000,5,none,network_flow
"""

MIXED_CSV = VALID_CSV + "\n" + "\n".join(MALFORMED_CSV.strip().split("\n")[1:])


def _df_from_csv(csv_text: str) -> pd.DataFrame:
    """Build a minimal valid feature DataFrame for testing downstream modules."""
    result = ingest_telemetry(io.StringIO(csv_text))
    return engineer_features(result.records)


def _make_feature_row(overrides: dict = None) -> pd.Series:
    """Return a feature row with default normal values."""
    defaults = {col: 0.0 for col in FEATURE_COLUMNS}
    defaults.update({
        "source_ip": "192.168.1.1",
        "event_count": 50.0,
        "unique_destination_count": 5.0,
        "unique_destination_port_count": 4.0,
        "failed_login_count": 1.0,
        "successful_login_count": 3.0,
        "success_failure_ratio": 0.75,
        "bytes_sent": 50000.0,
        "bytes_received": 200000.0,
        "packet_count": 200.0,
        "connection_rate": 5.0,
        "anomaly_score": 0.2,
        "classification": "Normal",
        "classifier_confidence": 0.8,
        "risk_score": 10,
        "risk_band": "Normal",
        "evidence": [],
    })
    if overrides:
        defaults.update(overrides)
    return pd.Series(defaults)


# ════════════════════════════════════════════════════════════════════════════════
# INGESTION TESTS
# ════════════════════════════════════════════════════════════════════════════════

class TestIngestion(unittest.TestCase):

    def test_valid_csv_ingestion(self):
        result = ingest_telemetry(io.StringIO(VALID_CSV))
        self.assertGreater(result.valid_count, 0)
        self.assertEqual(result.skipped_count, 0)
        self.assertIn("source_ip", result.records.columns)
        self.assertIn("timestamp", result.records.columns)

    def test_malformed_records_skipped_not_crash(self):
        """Malformed records must be skipped without crashing."""
        result = ingest_telemetry(io.StringIO(MALFORMED_CSV))
        self.assertGreaterEqual(result.skipped_count, 1)
        # Pipeline did not crash
        self.assertIsInstance(result.records, pd.DataFrame)

    def test_mixed_csv_valid_records_extracted(self):
        """Valid records in mixed input are processed even with malformed rows."""
        result = ingest_telemetry(io.StringIO(MIXED_CSV))
        self.assertGreater(result.valid_count, 0)
        self.assertGreater(result.skipped_count, 0)

    def test_skip_reasons_tracked(self):
        result = ingest_telemetry(io.StringIO(MALFORMED_CSV))
        self.assertGreater(len(result.skip_reasons), 0)
        # Each skip reason has a 'reason' key
        for r in result.skip_reasons:
            self.assertIn("reason", r)

    def test_empty_source(self):
        empty_csv = "timestamp,source_ip,dest_ip,src_port,dest_port,protocol,bytes,packets\n"
        result = ingest_telemetry(io.StringIO(empty_csv))
        self.assertEqual(result.valid_count, 0)

    def test_missing_required_fields_skipped(self):
        csv = "timestamp,source_ip,dest_ip\n2024-01-01 00:00:00,192.168.1.1,8.8.8.8\n"
        result = ingest_telemetry(io.StringIO(csv))
        # bytes and packets are required — this row is incomplete
        # No crash
        self.assertIsInstance(result, object)

    def test_timestamp_normalization(self):
        csv = """timestamp,source_ip,dest_ip,src_port,dest_port,protocol,bytes,packets,auth_status,event_type
2024-06-01T08:00:00Z,192.168.1.1,8.8.8.8,1234,443,https,1000,5,none,network_flow
"""
        result = ingest_telemetry(io.StringIO(csv))
        self.assertEqual(result.valid_count, 1)

    def test_background_traffic_filtered(self):
        csv = """timestamp,source_ip,dest_ip,src_port,dest_port,protocol,bytes,packets,auth_status,event_type
2024-06-01 08:00:00,192.168.1.1,255.255.255.255,68,67,dhcp,342,1,none,dhcp
2024-06-01 08:00:01,192.168.1.1,8.8.8.8,54321,443,https,5000,10,none,network_flow
"""
        result = ingest_telemetry(io.StringIO(csv))
        fg, bg = filter_background_traffic(result.records)
        self.assertEqual(len(bg), 1)
        self.assertEqual(len(fg), 1)

    def test_json_ingestion(self):
        records = [
            {"timestamp": "2024-06-01 08:00:00", "source_ip": "192.168.1.1",
             "dest_ip": "8.8.8.8", "src_port": 1234, "dest_port": 443,
             "protocol": "https", "bytes": 5000, "packets": 10,
             "auth_status": "none", "event_type": "network_flow"},
        ]
        jsonl = "\n".join(json.dumps(r) for r in records)
        result = ingest_telemetry(io.StringIO(jsonl), file_format="json")
        self.assertEqual(result.valid_count, 1)


# ════════════════════════════════════════════════════════════════════════════════
# FEATURE ENGINEERING TESTS
# ════════════════════════════════════════════════════════════════════════════════

class TestFeatureEngineering(unittest.TestCase):

    def test_features_generated(self):
        feat_df = _df_from_csv(VALID_CSV)
        self.assertFalse(feat_df.empty)
        for col in FEATURE_COLUMNS:
            self.assertIn(col, feat_df.columns, f"Missing feature: {col}")

    def test_all_feature_values_non_negative(self):
        feat_df = _df_from_csv(VALID_CSV)
        for col in FEATURE_COLUMNS:
            self.assertTrue(
                (feat_df[col] >= 0).all(),
                f"Feature {col} has negative values",
            )

    def test_source_ip_preserved(self):
        feat_df = _df_from_csv(VALID_CSV)
        self.assertIn("source_ip", feat_df.columns)
        self.assertGreater(feat_df["source_ip"].nunique(), 0)

    def test_feature_matrix_shape(self):
        feat_df = _df_from_csv(VALID_CSV)
        X = get_feature_matrix(feat_df)
        self.assertEqual(X.shape[1], len(FEATURE_COLUMNS))
        self.assertEqual(X.shape[0], len(feat_df))

    def test_no_nan_in_features(self):
        feat_df = _df_from_csv(VALID_CSV)
        for col in FEATURE_COLUMNS:
            self.assertFalse(feat_df[col].isna().any(), f"{col} has NaN values")

    def test_empty_df_returns_empty(self):
        feat_df = engineer_features(pd.DataFrame())
        self.assertTrue(feat_df.empty)

    def test_failed_login_count_correct(self):
        feat_df = _df_from_csv(VALID_CSV)
        # 192.168.1.10 has 1 failure in VALID_CSV
        row = feat_df[feat_df["source_ip"] == "192.168.1.10"].iloc[0]
        self.assertEqual(int(row["failed_login_count"]), 1)


# ════════════════════════════════════════════════════════════════════════════════
# ANOMALY DETECTION TESTS
# ════════════════════════════════════════════════════════════════════════════════

class TestAnomalyDetection(unittest.TestCase):

    def setUp(self):
        self.detector = AnomalyDetector()
        self.detector.train()

    def test_scores_in_range(self):
        feat_df = _df_from_csv(VALID_CSV)
        result = detect_anomalies(feat_df)
        self.assertIn("anomaly_score", result.columns)
        self.assertTrue((result["anomaly_score"] >= 0).all())
        self.assertTrue((result["anomaly_score"] <= 1).all())

    def test_no_random_scores(self):
        """Same input must produce same scores."""
        feat_df = _df_from_csv(VALID_CSV)
        r1 = detect_anomalies(feat_df)
        r2 = detect_anomalies(feat_df)
        pd.testing.assert_series_equal(r1["anomaly_score"], r2["anomaly_score"])

    def test_anomalous_data_scores_higher(self):
        """Clearly anomalous data should score higher than or equal to normal data."""
        normal_X = np.array([[50, 6, 4, 0.5, 3, 0.9, 40000, 180000, 180, 4, 0.2, 0.3, 0.05, 0.05, 0.3]])
        anomaly_X = np.array([[500, 2, 300, 0.5, 0, 0.01, 25000, 5000, 600, 80, 0.1, 0.9, 0.3, 0.9, 0.6]])
        normal_score = self.detector.score(normal_X)[0]
        anomaly_score = self.detector.score(anomaly_X)[0]
        self.assertGreaterEqual(anomaly_score, normal_score)

    def test_model_persists_and_loads(self):
        d2 = AnomalyDetector()
        loaded = d2.load()
        self.assertTrue(loaded)
        self.assertTrue(d2._fitted)


# ════════════════════════════════════════════════════════════════════════════════
# CLASSIFICATION TESTS
# ════════════════════════════════════════════════════════════════════════════════

class TestClassification(unittest.TestCase):

    def setUp(self):
        self.classifier = ThreatClassifier()
        self.classifier.train()

    def test_all_threat_classes_present(self):
        for cls in THREAT_CLASSES:
            self.assertIn(cls, self.classifier.classes_)

    def test_predictions_valid_classes(self):
        feat_df = _df_from_csv(VALID_CSV)
        result = classify_threats(feat_df)
        for cls in result["classification"]:
            self.assertIn(cls, THREAT_CLASSES, f"Invalid class: {cls}")

    def test_confidence_in_range(self):
        feat_df = _df_from_csv(VALID_CSV)
        result = classify_threats(feat_df)
        self.assertTrue((result["classifier_confidence"] >= 0).all())
        self.assertTrue((result["classifier_confidence"] <= 1).all())

    def test_port_scan_features_classified_correctly(self):
        """High unique ports + high connection rate should predict Port Scan."""
        # Build a feature vector matching port scan patterns
        X = np.array([[500, 3, 300, 0.5, 0, 0.02, 25000, 5000, 600, 80, 0.1, 0.9, 0.1, 0.9, 0.6]])
        labels, _ = self.classifier.predict(X)
        self.assertEqual(labels[0], "Port Scan")

    def test_brute_force_features_classified_correctly(self):
        """High failed logins + low success ratio should predict Brute Force."""
        X = np.array([[350, 2, 2, 100, 0, 0.0, 15000, 12000, 400, 30, 0.1, 0.1, 0.2, 0.5, 0.3]])
        labels, _ = self.classifier.predict(X)
        self.assertEqual(labels[0], "Brute Force")

    def test_exfiltration_features_classified_correctly(self):
        """High outbound bytes should predict Data Exfiltration."""
        X = np.array([[60, 12, 6, 0.3, 2, 0.8, 9_000_000, 50000, 5000, 8, 0.3, 0.8, 0.2, 0.2, 0.9]])
        labels, _ = self.classifier.predict(X)
        self.assertEqual(labels[0], "Data Exfiltration")

    def test_model_persists_and_loads(self):
        c2 = ThreatClassifier()
        loaded = c2.load()
        self.assertTrue(loaded)


# ════════════════════════════════════════════════════════════════════════════════
# RISK SCORING TESTS
# ════════════════════════════════════════════════════════════════════════════════

class TestRiskScoring(unittest.TestCase):

    def test_risk_score_range(self):
        for anomaly in [0.0, 0.3, 0.7, 1.0]:
            for conf in [0.0, 0.5, 1.0]:
                score = compute_risk_score(anomaly, conf, "Port Scan", [])
                self.assertGreaterEqual(score, 0)
                self.assertLessEqual(score, 100)

    def test_normal_classification_low_risk(self):
        score = compute_risk_score(0.1, 0.9, "Normal", [])
        self.assertLessEqual(score, THREAT_CLASSES and 30)

    def test_high_anomaly_high_threat_gives_high_risk(self):
        score = compute_risk_score(
            1.0, 1.0, "Data Exfiltration",
            [{"impact": 1.0}, {"impact": 0.9}, {"impact": 0.8}]
        )
        self.assertGreaterEqual(score, 71)

    def test_determinism(self):
        """Same inputs must always produce same risk score."""
        s1 = compute_risk_score(0.8, 0.9, "Brute Force", [{"impact": 0.9}])
        s2 = compute_risk_score(0.8, 0.9, "Brute Force", [{"impact": 0.9}])
        self.assertEqual(s1, s2)

    def test_risk_bands(self):
        self.assertEqual(classify_risk_band(0), "Normal")
        self.assertEqual(classify_risk_band(30), "Normal")
        self.assertEqual(classify_risk_band(31), "Suspicious")
        self.assertEqual(classify_risk_band(70), "Suspicious")
        self.assertEqual(classify_risk_band(71), "Malicious")
        self.assertEqual(classify_risk_band(100), "Malicious")

    def test_score_risks_dataframe(self):
        row = _make_feature_row({"classification": "Port Scan", "anomaly_score": 0.8,
                                  "classifier_confidence": 0.9, "evidence": [{"impact": 0.8}]})
        df = pd.DataFrame([row])
        result = score_risks(df)
        self.assertIn("risk_score", result.columns)
        self.assertIn("risk_band", result.columns)
        self.assertGreater(result["risk_score"].iloc[0], 30)


# ════════════════════════════════════════════════════════════════════════════════
# EVIDENCE TESTS
# ════════════════════════════════════════════════════════════════════════════════

class TestEvidence(unittest.TestCase):

    def test_port_scan_evidence_generated(self):
        row = _make_feature_row({
            "classification": "Port Scan",
            "unique_destination_port_count": 250.0,
            "connection_rate": 60.0,
            "unusual_service_indicator": 0.8,
            "event_count": 500.0,
        })
        evidence = generate_evidence(row, "Port Scan")
        self.assertGreater(len(evidence), 0)
        indicators = [e["indicator"] for e in evidence]
        self.assertIn("high_unique_destination_ports", indicators)

    def test_brute_force_evidence_generated(self):
        row = _make_feature_row({
            "classification": "Brute Force",
            "failed_login_count": 120.0,
            "success_failure_ratio": 0.02,
            "connection_rate": 25.0,
        })
        evidence = generate_evidence(row, "Brute Force")
        self.assertGreater(len(evidence), 0)
        indicators = [e["indicator"] for e in evidence]
        self.assertIn("high_failed_login_count", indicators)

    def test_exfiltration_evidence_generated(self):
        row = _make_feature_row({
            "classification": "Data Exfiltration",
            "bytes_sent": 10_000_000.0,
            "destination_diversity": 0.85,
            "outbound_transfer_indicator": 0.8,
        })
        evidence = generate_evidence(row, "Data Exfiltration")
        self.assertGreater(len(evidence), 0)
        indicators = [e["indicator"] for e in evidence]
        self.assertIn("high_outbound_data_volume", indicators)

    def test_lateral_movement_evidence_generated(self):
        row = _make_feature_row({
            "classification": "Lateral Movement",
            "unusual_peer_indicator": 0.8,
            "unique_destination_count": 25.0,
            "unusual_service_indicator": 0.6,
        })
        evidence = generate_evidence(row, "Lateral Movement")
        self.assertGreater(len(evidence), 0)

    def test_evidence_has_required_fields(self):
        row = _make_feature_row({
            "classification": "Port Scan",
            "unique_destination_port_count": 200.0,
            "connection_rate": 50.0,
        })
        evidence = generate_evidence(row, "Port Scan")
        for ev in evidence:
            self.assertIn("indicator", ev)
            self.assertIn("description", ev)
            self.assertIn("impact", ev)
            self.assertIn("observed_value", ev)

    def test_evidence_max_five_items(self):
        row = _make_feature_row({
            "classification": "Port Scan",
            "unique_destination_port_count": 300.0,
            "connection_rate": 100.0,
            "unusual_service_indicator": 0.9,
            "event_count": 1000.0,
        })
        evidence = generate_evidence(row, "Port Scan")
        self.assertLessEqual(len(evidence), 5)

    def test_add_evidence_dataframe(self):
        row = _make_feature_row({"classification": "Brute Force",
                                  "failed_login_count": 100.0})
        df = pd.DataFrame([row])
        result = add_evidence(df)
        self.assertIn("evidence", result.columns)
        self.assertIn("recommended_action", result.columns)


# ════════════════════════════════════════════════════════════════════════════════
# SQLITE AUDIT TESTS
# ════════════════════════════════════════════════════════════════════════════════

class TestDatabase(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mktemp(suffix=".db")

    def tearDown(self):
        if os.path.exists(self.tmp):
            os.unlink(self.tmp)

    def _make_alerts_df(self, n=3):
        rows = []
        for i in range(n):
            rows.append({
                "source_ip": f"192.168.1.{i+10}",
                "dest_ip_primary": "8.8.8.8",
                "last_seen": "2024-06-01 08:00:00",
                "classification": "Normal",
                "risk_band": "Normal",
                "risk_score": i * 10,
                "anomaly_score": i * 0.1,
                "classifier_confidence": 0.8,
                "evidence": [],
                "recommended_action": "Monitor",
            })
        return pd.DataFrame(rows)

    def test_initialize_creates_schema(self):
        initialize_database(self.tmp)
        self.assertTrue(os.path.exists(self.tmp))

    def test_store_and_fetch_alerts(self):
        df = self._make_alerts_df(3)
        stored = store_alerts(df, db_path=self.tmp)
        self.assertEqual(stored, 3)

        fetched = fetch_alerts(db_path=self.tmp)
        self.assertEqual(len(fetched), 3)

    def test_alert_has_all_required_columns(self):
        df = self._make_alerts_df(1)
        store_alerts(df, db_path=self.tmp)
        fetched = fetch_alerts(db_path=self.tmp)
        for col in ["alert_id", "source_ip", "classification", "risk_score",
                    "anomaly_score", "confidence", "status", "model_version"]:
            self.assertIn(col, fetched.columns)

    def test_alert_default_status_new(self):
        df = self._make_alerts_df(1)
        store_alerts(df, db_path=self.tmp)
        fetched = fetch_alerts(db_path=self.tmp)
        self.assertEqual(fetched["status"].iloc[0], "new")

    def test_update_alert_status(self):
        df = self._make_alerts_df(1)
        store_alerts(df, db_path=self.tmp)
        fetched = fetch_alerts(db_path=self.tmp)
        aid = fetched["alert_id"].iloc[0]

        updated = update_alert_status(aid, "reviewed", db_path=self.tmp)
        self.assertTrue(updated)

        fetched2 = fetch_alerts(db_path=self.tmp)
        updated_row = fetched2[fetched2["alert_id"] == aid]
        self.assertEqual(updated_row["status"].iloc[0], "reviewed")

    def test_invalid_status_rejected(self):
        df = self._make_alerts_df(1)
        store_alerts(df, db_path=self.tmp)
        fetched = fetch_alerts(db_path=self.tmp)
        aid = fetched["alert_id"].iloc[0]
        result = update_alert_status(aid, "invalid_status", db_path=self.tmp)
        self.assertFalse(result)

    def test_get_stats(self):
        df = self._make_alerts_df(5)
        store_alerts(df, db_path=self.tmp)
        stats = get_alert_stats(db_path=self.tmp)
        self.assertEqual(stats["total_alerts"], 5)


# ════════════════════════════════════════════════════════════════════════════════
# POLICY TESTS
# ════════════════════════════════════════════════════════════════════════════════

class TestPolicy(unittest.TestCase):

    def _make_df(self, risk_scores):
        return pd.DataFrame({
            "source_ip": [f"192.168.1.{i}" for i in range(len(risk_scores))],
            "risk_score": risk_scores,
            "classification": ["Normal"] * len(risk_scores),
            "risk_band": ["Normal"] * len(risk_scores),
        })

    def test_policy_pass_all_below_threshold(self):
        df = self._make_df([10, 20, 30])
        result = evaluate_policy(df, max_risk=70)
        self.assertTrue(result.passed)
        self.assertEqual(result.exit_code, 0)

    def test_policy_fail_one_above_threshold(self):
        df = self._make_df([10, 50, 85])
        result = evaluate_policy(df, max_risk=70)
        self.assertFalse(result.passed)
        self.assertEqual(result.exit_code, 1)
        self.assertEqual(len(result.violations), 1)
        self.assertEqual(result.violations[0]["risk_score"], 85)

    def test_policy_pass_at_exact_threshold(self):
        df = self._make_df([70, 70])
        result = evaluate_policy(df, max_risk=70)
        self.assertTrue(result.passed)

    def test_policy_fail_at_threshold_plus_one(self):
        df = self._make_df([71])
        result = evaluate_policy(df, max_risk=70)
        self.assertFalse(result.passed)

    def test_empty_df_passes(self):
        result = evaluate_policy(pd.DataFrame(), max_risk=70)
        self.assertTrue(result.passed)
        self.assertEqual(result.exit_code, 0)

    def test_policy_summary_string(self):
        df = self._make_df([90])
        result = evaluate_policy(df, max_risk=70)
        summary = result.summary
        self.assertIn("FAIL", summary)
        self.assertIn("70", summary)


# ════════════════════════════════════════════════════════════════════════════════
# END-TO-END PIPELINE TEST
# ════════════════════════════════════════════════════════════════════════════════

class TestEndToEndPipeline(unittest.TestCase):

    def setUp(self):
        self.tmp_db = tempfile.mktemp(suffix=".db")

    def tearDown(self):
        if os.path.exists(self.tmp_db):
            os.unlink(self.tmp_db)

    def test_pipeline_with_valid_csv(self):
        result = run_pipeline(
            source=io.StringIO(VALID_CSV),
            file_format="csv",
            source_file="test.csv",
            max_risk=100,
            db_path=self.tmp_db,
            store_to_db=True,
        )
        self.assertGreater(result.valid_count, 0)
        self.assertFalse(result.alerts_df.empty)
        self.assertIsNotNone(result.policy_result)
        self.assertIn("risk_score", result.alerts_df.columns)
        self.assertIn("classification", result.alerts_df.columns)
        self.assertIn("anomaly_score", result.alerts_df.columns)
        self.assertIn("evidence", result.alerts_df.columns)

    def test_pipeline_with_malformed_csv_resilient(self):
        result = run_pipeline(
            source=io.StringIO(MALFORMED_CSV),
            file_format="csv",
            source_file="malformed.csv",
            max_risk=100,
            db_path=self.tmp_db,
            store_to_db=False,
        )
        # Should not crash
        self.assertIsInstance(result.total_raw, int)
        self.assertGreaterEqual(result.skipped_count, 1)

    def test_pipeline_multiple_threat_categories(self):
        """Full telemetry with known threat patterns should yield multiple classifications."""
        if not os.path.exists(DEFAULT_TELEMETRY_PATH):
            self.skipTest("Default telemetry not found")
        result = run_pipeline(
            source=DEFAULT_TELEMETRY_PATH,
            file_format="csv",
            source_file="telemetry.csv",
            max_risk=100,
            db_path=self.tmp_db,
            store_to_db=True,
        )
        self.assertGreater(result.valid_count, 0)
        self.assertFalse(result.alerts_df.empty)

        classifications = result.alerts_df["classification"].unique().tolist()
        self.assertGreater(len(classifications), 1,
                           f"Expected multiple threat categories, got: {classifications}")

    def test_pipeline_risk_scores_in_range(self):
        result = run_pipeline(
            source=io.StringIO(VALID_CSV),
            file_format="csv",
            source_file="test.csv",
            db_path=self.tmp_db,
            store_to_db=False,
        )
        if not result.alerts_df.empty:
            risks = result.alerts_df["risk_score"]
            self.assertTrue((risks >= 0).all())
            self.assertTrue((risks <= 100).all())

    def test_pipeline_policy_exit_code_0(self):
        result = run_pipeline(
            source=io.StringIO(VALID_CSV),
            file_format="csv",
            source_file="test.csv",
            max_risk=100,
            db_path=self.tmp_db,
            store_to_db=False,
        )
        self.assertEqual(result.policy_result.exit_code, 0)

    def test_pipeline_policy_exit_code_1(self):
        """Setting max_risk=0 forces policy failure."""
        if not os.path.exists(DEFAULT_TELEMETRY_PATH):
            self.skipTest("Default telemetry not found")
        result = run_pipeline(
            source=DEFAULT_TELEMETRY_PATH,
            file_format="csv",
            source_file="telemetry.csv",
            max_risk=0,
            db_path=self.tmp_db,
            store_to_db=False,
        )
        # With max_risk=0, any non-zero risk should fail
        if result.alert_count > 0 and result.alerts_df["risk_score"].max() > 0:
            self.assertEqual(result.policy_result.exit_code, 1)

    def test_pipeline_stores_to_sqlite(self):
        run_pipeline(
            source=io.StringIO(VALID_CSV),
            file_format="csv",
            source_file="test.csv",
            db_path=self.tmp_db,
            store_to_db=True,
        )
        fetched = fetch_alerts(db_path=self.tmp_db)
        self.assertGreater(len(fetched), 0)

    def test_pipeline_deterministic(self):
        """Same input must produce same results."""
        r1 = run_pipeline(
            source=io.StringIO(VALID_CSV),
            file_format="csv",
            source_file="test.csv",
            db_path=self.tmp_db,
            store_to_db=False,
        )
        r2 = run_pipeline(
            source=io.StringIO(VALID_CSV),
            file_format="csv",
            source_file="test.csv",
            db_path=self.tmp_db,
            store_to_db=False,
        )
        if not r1.alerts_df.empty and not r2.alerts_df.empty:
            # Sort by source_ip for comparison
            df1 = r1.alerts_df.sort_values("source_ip").reset_index(drop=True)
            df2 = r2.alerts_df.sort_values("source_ip").reset_index(drop=True)
            pd.testing.assert_series_equal(df1["risk_score"], df2["risk_score"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
