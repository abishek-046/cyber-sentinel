"""
Threat Classification Module
Random Forest multi-class classifier for threat type identification.
"""
import logging
import os
from typing import Dict, List, Optional, Tuple

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder

from config import (
    FEATURE_COLUMNS,
    MODELS_DIR,
    RANDOM_FOREST_MODEL_PATH,
    RANDOM_STATE,
    RF_N_ESTIMATORS,
    RF_TEST_SIZE,
    THREAT_CLASSES,
)
from src.features import get_feature_matrix

logger = logging.getLogger(__name__)

LABEL_ENCODER_PATH = os.path.join(MODELS_DIR, "label_encoder.joblib")


def _generate_training_data() -> Tuple[np.ndarray, np.ndarray]:
    """
    Generate deterministic labeled training data based on realistic
    behavioral patterns for each threat class.

    This is generated training data used to bootstrap the classifier
    since no external labeled dataset is provided.
    """
    rng = np.random.RandomState(RANDOM_STATE)
    n_per_class = 400

    def make_samples(patterns: dict) -> np.ndarray:
        rows = []
        for _ in range(n_per_class):
            row = []
            for col in FEATURE_COLUMNS:
                if col in patterns:
                    dist = patterns[col]
                    if dist[0] == "normal":
                        val = rng.normal(dist[1], dist[2])
                    elif dist[0] == "uniform":
                        val = rng.uniform(dist[1], dist[2])
                    elif dist[0] == "exponential":
                        val = rng.exponential(dist[1]) + dist[2]
                    elif dist[0] == "beta":
                        val = rng.beta(dist[1], dist[2])
                    elif dist[0] == "constant":
                        val = dist[1]
                    else:
                        val = 0.0
                    row.append(max(0.0, val))
                else:
                    row.append(0.0)
            rows.append(row)
        return np.array(rows)

    # --- Normal Traffic ---
    normal_patterns = {
        "event_count": ("normal", 40, 15),
        "unique_destination_count": ("normal", 6, 3),
        "unique_destination_port_count": ("normal", 4, 2),
        "failed_login_count": ("exponential", 0.3, 0),
        "successful_login_count": ("normal", 2, 1),
        "success_failure_ratio": ("normal", 0.9, 0.08),
        "bytes_sent": ("exponential", 40000, 1000),
        "bytes_received": ("exponential", 180000, 5000),
        "packet_count": ("normal", 180, 60),
        "connection_rate": ("exponential", 4, 0.5),
        "protocol_diversity": ("beta", 2, 5),
        "destination_diversity": ("beta", 2, 5),
        "unusual_peer_indicator": ("beta", 1, 15),
        "unusual_service_indicator": ("beta", 1, 12),
        "outbound_transfer_indicator": ("beta", 2, 4),
    }

    # --- Port Scan ---
    port_scan_patterns = {
        "event_count": ("normal", 500, 150),
        "unique_destination_count": ("normal", 3, 2),
        "unique_destination_port_count": ("normal", 250, 80),
        "failed_login_count": ("exponential", 0.5, 0),
        "successful_login_count": ("exponential", 0.2, 0),
        "success_failure_ratio": ("beta", 1, 5),
        "bytes_sent": ("normal", 25000, 8000),
        "bytes_received": ("exponential", 5000, 100),
        "packet_count": ("normal", 600, 150),
        "connection_rate": ("normal", 45, 15),
        "protocol_diversity": ("beta", 1, 8),
        "destination_diversity": ("beta", 8, 2),
        "unusual_peer_indicator": ("beta", 3, 5),
        "unusual_service_indicator": ("beta", 8, 2),
        "outbound_transfer_indicator": ("beta", 3, 2),
    }

    # --- Brute Force ---
    brute_force_patterns = {
        "event_count": ("normal", 350, 100),
        "unique_destination_count": ("normal", 2, 1),
        "unique_destination_port_count": ("normal", 2, 1),
        "failed_login_count": ("normal", 80, 30),
        "successful_login_count": ("exponential", 0.5, 0),
        "success_failure_ratio": ("beta", 1, 15),
        "bytes_sent": ("normal", 15000, 5000),
        "bytes_received": ("normal", 12000, 4000),
        "packet_count": ("normal", 400, 120),
        "connection_rate": ("normal", 30, 10),
        "protocol_diversity": ("beta", 1, 10),
        "destination_diversity": ("beta", 1, 8),
        "unusual_peer_indicator": ("beta", 2, 5),
        "unusual_service_indicator": ("beta", 5, 2),
        "outbound_transfer_indicator": ("beta", 2, 5),
    }

    # --- Lateral Movement ---
    lateral_movement_patterns = {
        "event_count": ("normal", 80, 25),
        "unique_destination_count": ("normal", 20, 8),
        "unique_destination_port_count": ("normal", 8, 3),
        "failed_login_count": ("normal", 5, 3),
        "successful_login_count": ("normal", 8, 4),
        "success_failure_ratio": ("beta", 4, 3),
        "bytes_sent": ("exponential", 80000, 1000),
        "bytes_received": ("exponential", 120000, 1000),
        "packet_count": ("normal", 300, 80),
        "connection_rate": ("normal", 12, 5),
        "protocol_diversity": ("beta", 3, 3),
        "destination_diversity": ("beta", 6, 2),
        "unusual_peer_indicator": ("beta", 8, 2),
        "unusual_service_indicator": ("beta", 5, 2),
        "outbound_transfer_indicator": ("beta", 3, 3),
    }

    # --- Data Exfiltration ---
    exfil_patterns = {
        "event_count": ("normal", 60, 20),
        "unique_destination_count": ("normal", 12, 5),
        "unique_destination_port_count": ("normal", 6, 3),
        "failed_login_count": ("exponential", 0.3, 0),
        "successful_login_count": ("normal", 2, 1),
        "success_failure_ratio": ("beta", 5, 2),
        "bytes_sent": ("normal", 8_000_000, 2_000_000),
        "bytes_received": ("exponential", 50000, 1000),
        "packet_count": ("normal", 5000, 1500),
        "connection_rate": ("normal", 8, 4),
        "protocol_diversity": ("beta", 2, 4),
        "destination_diversity": ("beta", 6, 2),
        "unusual_peer_indicator": ("beta", 2, 5),
        "unusual_service_indicator": ("beta", 2, 4),
        "outbound_transfer_indicator": ("beta", 8, 2),
    }

    class_patterns = {
        "Normal": normal_patterns,
        "Port Scan": port_scan_patterns,
        "Brute Force": brute_force_patterns,
        "Lateral Movement": lateral_movement_patterns,
        "Data Exfiltration": exfil_patterns,
    }

    X_parts = []
    y_parts = []
    for label, patterns in class_patterns.items():
        X_class = make_samples(patterns)
        X_parts.append(X_class)
        y_parts.extend([label] * n_per_class)

    X = np.vstack(X_parts)
    y = np.array(y_parts)

    return X, y


class ThreatClassifier:
    """Random Forest multi-class threat classifier."""

    def __init__(self):
        self.model: Optional[RandomForestClassifier] = None
        self.label_encoder: Optional[LabelEncoder] = None
        self._fitted = False
        self.classes_: List[str] = THREAT_CLASSES[:]

    def train(self, X: Optional[np.ndarray] = None,
              y: Optional[np.ndarray] = None) -> Dict:
        """
        Train the classifier.

        Args:
            X: Feature matrix. Generated if None.
            y: Labels. Generated if None.

        Returns:
            Dictionary with training metrics.
        """
        os.makedirs(MODELS_DIR, exist_ok=True)

        if X is None or y is None:
            logger.info("Generating training data for threat classifier...")
            X, y = _generate_training_data()

        self.label_encoder = LabelEncoder()
        y_encoded = self.label_encoder.fit_transform(y)
        self.classes_ = list(self.label_encoder.classes_)

        X_train, X_test, y_train, y_test = train_test_split(
            X, y_encoded,
            test_size=RF_TEST_SIZE,
            random_state=RANDOM_STATE,
            stratify=y_encoded,
        )

        self.model = RandomForestClassifier(
            n_estimators=RF_N_ESTIMATORS,
            random_state=RANDOM_STATE,
            n_jobs=-1,
            class_weight="balanced",
        )
        self.model.fit(X_train, y_train)
        self._fitted = True

        # Evaluate
        y_pred = self.model.predict(X_test)
        report = classification_report(
            y_test, y_pred,
            target_names=self.label_encoder.classes_,
            output_dict=True,
        )

        # Persist
        joblib.dump(self.model, RANDOM_FOREST_MODEL_PATH)
        joblib.dump(self.label_encoder, LABEL_ENCODER_PATH)

        accuracy = float(report.get("accuracy", 0.0))
        logger.info(
            "Threat classifier trained: %d samples, accuracy=%.3f",
            len(X), accuracy,
        )
        return {"accuracy": accuracy, "report": report}

    def load(self) -> bool:
        """Load persisted model. Returns True if successful."""
        try:
            if os.path.exists(RANDOM_FOREST_MODEL_PATH) and \
               os.path.exists(LABEL_ENCODER_PATH):
                self.model = joblib.load(RANDOM_FOREST_MODEL_PATH)
                self.label_encoder = joblib.load(LABEL_ENCODER_PATH)
                self.classes_ = list(self.label_encoder.classes_)
                self._fitted = True
                logger.info("Threat classifier loaded from disk.")
                return True
        except Exception as e:
            logger.warning("Failed to load classifier: %s. Will retrain.", e)
        return False

    def ensure_fitted(self) -> None:
        """Load from disk or train fresh."""
        if not self._fitted:
            if not self.load():
                self.train()

    def predict(self, X: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """
        Predict threat class and confidence.

        Args:
            X: Feature matrix.

        Returns:
            (class_labels, probabilities_array)
            probabilities_array shape: (n_samples, n_classes)
        """
        self.ensure_fitted()

        if X.shape[0] == 0:
            return np.array([]), np.array([]).reshape(0, len(self.classes_))

        # Align features
        expected = len(FEATURE_COLUMNS)
        if X.shape[1] != expected:
            if X.shape[1] < expected:
                pad = np.zeros((X.shape[0], expected - X.shape[1]))
                X = np.hstack([X, pad])
            else:
                X = X[:, :expected]

        y_pred = self.model.predict(X)
        y_proba = self.model.predict_proba(X)

        labels = self.label_encoder.inverse_transform(y_pred)
        return labels, y_proba


# Module-level singleton
_classifier: Optional[ThreatClassifier] = None


def get_classifier() -> ThreatClassifier:
    """Get or create singleton classifier."""
    global _classifier
    if _classifier is None:
        _classifier = ThreatClassifier()
    return _classifier


def classify_threats(feature_df: pd.DataFrame) -> pd.DataFrame:
    """
    Add classification, classifier_confidence columns to feature DataFrame.

    Args:
        feature_df: Feature DataFrame with anomaly_score column.

    Returns:
        feature_df with classification and classifier_confidence columns.
    """
    if feature_df.empty:
        return feature_df

    classifier = get_classifier()
    classifier.ensure_fitted()

    X = get_feature_matrix(feature_df)

    labels, probas = classifier.predict(X)
    max_confidences = probas.max(axis=1)

    feature_df = feature_df.copy()
    feature_df["classification"] = labels
    feature_df["classifier_confidence"] = max_confidences
    feature_df["class_probabilities"] = [
        dict(zip(classifier.classes_, row.tolist())) for row in probas
    ]

    logger.info(
        "Threat classification complete: %d IPs classified",
        len(feature_df),
    )
    return feature_df
