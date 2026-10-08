"""
Anomaly Detection Module
Implements Isolation Forest for unsupervised anomaly detection.
"""
import logging
import os
from typing import Optional, Tuple

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from config import (
    FEATURE_COLUMNS,
    ISOLATION_FOREST_CONTAMINATION,
    ISOLATION_FOREST_MODEL_PATH,
    ISOLATION_FOREST_N_ESTIMATORS,
    MODELS_DIR,
    RANDOM_STATE,
    SCALER_MODEL_PATH,
)
from src.features import engineer_features, get_feature_matrix

logger = logging.getLogger(__name__)


def _generate_normal_baseline() -> np.ndarray:
    """
    Generate a deterministic normal baseline dataset for Isolation Forest training.
    Represents typical enterprise network behavior patterns.
    """
    rng = np.random.RandomState(RANDOM_STATE)
    n_samples = 1000

    # Normal behavioral patterns
    baseline = {
        "event_count": rng.normal(50, 20, n_samples).clip(1, 200),
        "unique_destination_count": rng.normal(8, 4, n_samples).clip(1, 30),
        "unique_destination_port_count": rng.normal(5, 2, n_samples).clip(1, 15),
        "failed_login_count": rng.exponential(0.5, n_samples).clip(0, 5),
        "successful_login_count": rng.normal(3, 2, n_samples).clip(0, 15),
        "success_failure_ratio": rng.normal(0.85, 0.1, n_samples).clip(0, 1),
        "bytes_sent": rng.exponential(50000, n_samples).clip(100, 500000),
        "bytes_received": rng.exponential(200000, n_samples).clip(100, 2000000),
        "packet_count": rng.normal(200, 80, n_samples).clip(10, 1000),
        "connection_rate": rng.exponential(5, n_samples).clip(0.1, 30),
        "protocol_diversity": rng.beta(2, 5, n_samples),
        "destination_diversity": rng.beta(2, 4, n_samples),
        "unusual_peer_indicator": rng.beta(1, 10, n_samples),
        "unusual_service_indicator": rng.beta(1, 8, n_samples),
        "outbound_transfer_indicator": rng.beta(2, 3, n_samples),
    }
    return np.column_stack([baseline[col] for col in FEATURE_COLUMNS])


class AnomalyDetector:
    """Isolation Forest-based anomaly detector."""

    def __init__(self):
        self.model: Optional[IsolationForest] = None
        self.scaler: Optional[StandardScaler] = None
        self._fitted = False

    def train(self, X: Optional[np.ndarray] = None) -> None:
        """
        Train the anomaly detector on normal baseline data.

        Args:
            X: Optional custom training data. Uses generated baseline if None.
        """
        os.makedirs(MODELS_DIR, exist_ok=True)

        if X is None:
            X = _generate_normal_baseline()

        # Scale features
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)

        # Train Isolation Forest
        self.model = IsolationForest(
            n_estimators=ISOLATION_FOREST_N_ESTIMATORS,
            contamination=ISOLATION_FOREST_CONTAMINATION,
            random_state=RANDOM_STATE,
            n_jobs=-1,
        )
        self.model.fit(X_scaled)
        self._fitted = True

        # Persist
        joblib.dump(self.model, ISOLATION_FOREST_MODEL_PATH)
        joblib.dump(self.scaler, SCALER_MODEL_PATH)
        logger.info(
            "Anomaly detector trained and saved: %d samples, %d features",
            X.shape[0], X.shape[1],
        )

    def load(self) -> bool:
        """Load persisted model. Returns True if successful."""
        try:
            if os.path.exists(ISOLATION_FOREST_MODEL_PATH) and \
               os.path.exists(SCALER_MODEL_PATH):
                self.model = joblib.load(ISOLATION_FOREST_MODEL_PATH)
                self.scaler = joblib.load(SCALER_MODEL_PATH)
                self._fitted = True
                logger.info("Anomaly detector loaded from disk.")
                return True
        except Exception as e:
            logger.warning("Failed to load anomaly detector: %s. Will retrain.", e)
        return False

    def ensure_fitted(self) -> None:
        """Load from disk or train fresh if not fitted."""
        if not self._fitted:
            if not self.load():
                self.train()

    def score(self, X: np.ndarray) -> np.ndarray:
        """
        Generate normalized anomaly scores in [0, 1].
        Higher score = more anomalous.

        Args:
            X: Feature matrix, shape (n_samples, n_features)

        Returns:
            Anomaly scores array, shape (n_samples,)
        """
        self.ensure_fitted()

        if X.shape[0] == 0:
            return np.array([])

        # Align feature count
        expected_features = len(FEATURE_COLUMNS)
        if X.shape[1] != expected_features:
            logger.warning(
                "Feature count mismatch: got %d, expected %d",
                X.shape[1], expected_features,
            )
            # Pad or trim
            if X.shape[1] < expected_features:
                pad = np.zeros((X.shape[0], expected_features - X.shape[1]))
                X = np.hstack([X, pad])
            else:
                X = X[:, :expected_features]

        X_scaled = self.scaler.transform(X)

        # Isolation Forest decision_function: negative = more anomalous
        raw_scores = self.model.decision_function(X_scaled)

        # Normalize to [0, 1]: lower decision_function -> higher anomaly score
        # decision_function ranges roughly from -0.5 to 0.5
        # We invert and normalize
        anomaly_scores = 1.0 - (raw_scores - raw_scores.min()) / (
            raw_scores.max() - raw_scores.min() + 1e-10
        )
        # Clamp
        anomaly_scores = np.clip(anomaly_scores, 0.0, 1.0)

        return anomaly_scores


# Module-level singleton
_detector: Optional[AnomalyDetector] = None


def get_detector() -> AnomalyDetector:
    """Get or create the singleton anomaly detector."""
    global _detector
    if _detector is None:
        _detector = AnomalyDetector()
    return _detector


def detect_anomalies(feature_df: pd.DataFrame) -> pd.DataFrame:
    """
    Add anomaly_score column to feature DataFrame.

    Args:
        feature_df: Output from engineer_features().

    Returns:
        feature_df with 'anomaly_score' column added.
    """
    if feature_df.empty:
        return feature_df

    detector = get_detector()
    detector.ensure_fitted()

    X = get_feature_matrix(feature_df)
    if X.shape[0] == 0:
        feature_df = feature_df.copy()
        feature_df["anomaly_score"] = 0.0
        return feature_df

    scores = detector.score(X)

    feature_df = feature_df.copy()
    feature_df["anomaly_score"] = scores

    logger.info(
        "Anomaly detection complete: %d IPs, mean score=%.3f, max=%.3f",
        len(feature_df),
        float(np.mean(scores)),
        float(np.max(scores)),
    )
    return feature_df
