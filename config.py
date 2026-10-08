"""
Cybersecurity Sentinel - Global Configuration
Supports both local execution and cloud deployment (Streamlit Cloud).
On cloud, writable artefacts go to /tmp to avoid read-only filesystem errors.
"""
import os
import tempfile

# Base paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")

# Detect cloud / read-only filesystem: use /tmp for writable artefacts
# when the repo root is not writable (Streamlit Cloud mounts it read-only).
def _writable(path: str) -> bool:
    try:
        os.makedirs(path, exist_ok=True)
        test = os.path.join(path, ".write_test")
        with open(test, "w") as f:
            f.write("x")
        os.remove(test)
        return True
    except OSError:
        return False

_default_models = os.path.join(BASE_DIR, "models")
_default_db_dir = os.path.join(BASE_DIR, "database")

if _writable(_default_models):
    MODELS_DIR = _default_models
    DATABASE_DIR = _default_db_dir
else:
    # Cloud: use /tmp
    MODELS_DIR = os.path.join(tempfile.gettempdir(), "sentinel_models")
    DATABASE_DIR = os.path.join(tempfile.gettempdir(), "sentinel_db")

# Ensure directories exist
for _d in [DATA_DIR, MODELS_DIR, DATABASE_DIR]:
    os.makedirs(_d, exist_ok=True)

# Default paths
DEFAULT_DB_PATH = os.path.join(DATABASE_DIR, "sentinel.db")
DEFAULT_TELEMETRY_PATH = os.path.join(DATA_DIR, "telemetry.csv")
ISOLATION_FOREST_MODEL_PATH = os.path.join(MODELS_DIR, "isolation_forest.joblib")
RANDOM_FOREST_MODEL_PATH = os.path.join(MODELS_DIR, "random_forest.joblib")
SCALER_MODEL_PATH = os.path.join(MODELS_DIR, "scaler.joblib")

# Model version
MODEL_VERSION = "1.0.0"

# Random seeds for determinism
RANDOM_STATE = 42

# Anomaly detection config
ISOLATION_FOREST_CONTAMINATION = 0.1
ISOLATION_FOREST_N_ESTIMATORS = 100

# Classification config
RF_N_ESTIMATORS = 100
RF_TEST_SIZE = 0.2

# Threat classes
THREAT_CLASSES = [
    "Normal",
    "Port Scan",
    "Brute Force",
    "Lateral Movement",
    "Data Exfiltration",
]

# Risk bands
RISK_NORMAL_MAX = 30
RISK_SUSPICIOUS_MAX = 70
RISK_MALICIOUS_MIN = 71

# Feature engineering time window (seconds)
TIME_WINDOW_SECONDS = 300  # 5 minutes

# Feature columns used by models
FEATURE_COLUMNS = [
    "event_count",
    "unique_destination_count",
    "unique_destination_port_count",
    "failed_login_count",
    "successful_login_count",
    "success_failure_ratio",
    "bytes_sent",
    "bytes_received",
    "packet_count",
    "connection_rate",
    "protocol_diversity",
    "destination_diversity",
    "unusual_peer_indicator",
    "unusual_service_indicator",
    "outbound_transfer_indicator",
]

# Policy defaults
DEFAULT_MAX_RISK = 100

# Expected telemetry fields
REQUIRED_TELEMETRY_FIELDS = [
    "timestamp",
    "source_ip",
    "dest_ip",
    "protocol",
    "bytes",
    "packets",
]

OPTIONAL_TELEMETRY_FIELDS = [
    "src_port",
    "dest_port",
    "auth_status",
    "event_type",
]

# Background/noise event types to deprioritize
BACKGROUND_EVENT_TYPES = {
    "dhcp", "arp", "mdns", "ssdp", "igmp",
    "broadcast", "multicast", "service_discovery", "ntp",
}

# Known high-risk ports for evidence
HIGH_RISK_PORTS = {22, 23, 445, 3389, 1433, 3306, 5432, 6379, 27017}
COMMON_PORTS = {80, 443, 53, 25, 110, 143, 993, 995, 587}

# Evidence thresholds
EVIDENCE_THRESHOLDS = {
    "port_scan_unique_ports": 15,
    "port_scan_connection_rate": 10,
    "brute_force_failed_logins": 5,
    "brute_force_success_failure_ratio": 0.1,
    "lateral_movement_unusual_peer": 0.5,
    "exfiltration_bytes_sent": 5_000_000,
    "exfiltration_destination_diversity": 0.7,
}
