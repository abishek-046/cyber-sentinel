# Cybersecurity Sentinel

**Intelligent Threat Detection and Network Anomaly Analysis**

A complete cybersecurity operations tool that ingests network telemetry, engineers behavioral features, detects anomalies with machine learning, classifies threats, calculates risk, generates explainable evidence, and presents results through a Security Operations Dashboard and CLI.

---

## System Overview

The Cybersecurity Sentinel processes raw network telemetry through a seven-stage detection pipeline that produces actionable, explainable security alerts. Every alert traces back to specific observed feature values — no black-box AI explanations.

### Problem

Security operations teams face high volumes of network telemetry containing both benign activity and genuine threats. Manual analysis does not scale. The Sentinel automates threat detection across five attack categories while maintaining full explainability and auditability.

---

## Architecture

```
Telemetry (CSV/JSON)
        │
        ▼
┌─────────────────┐
│  Ingestion &    │  Validates, normalizes, handles malformed records
│  Validation     │  Fields: timestamp, IPs, ports, protocol, bytes, auth
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Background     │  Filters DHCP, ARP, multicast, broadcast noise
│  Filtering      │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Behavioral     │  15 time-windowed features per source IP:
│  Feature Eng.   │  event_count, unique_dest_ports, failed_logins, etc.
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Isolation      │  Unsupervised anomaly detection
│  Forest         │  Normalized anomaly signal [0–1]
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Random Forest  │  Multi-class threat classification:
│  Classifier     │  Normal / Port Scan / Brute Force /
│                 │  Lateral Movement / Data Exfiltration
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Risk Scoring   │  Deterministic 0–100 score
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Evidence       │  Factual observed-value evidence per alert
│  Engine         │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  SQLite Audit   │  Persistent alert storage with status tracking
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Policy         │  --max-risk threshold, exit code 0/1
│  Enforcement    │
└─────────────────┘
         │
    ┌────┴────┐
    │         │
  CLI      Dashboard
```

---

## Data Flow

```
RAW EVENT → VALIDATION → NORMALIZATION → FEATURE VECTOR →
ANOMALY SCORE → CLASSIFICATION → RISK SCORE → EVIDENCE → ALERT → SQLITE
```

---

## Telemetry Schema

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `timestamp` | string | Yes | ISO 8601 or common datetime formats |
| `source_ip` | string | Yes | Source IPv4 address |
| `dest_ip` | string | Yes | Destination IPv4 address |
| `src_port` | integer | No | Source port (0–65535) |
| `dest_port` | integer | No | Destination port (0–65535) |
| `protocol` | string | Yes | tcp, udp, https, ssh, smb, etc. |
| `bytes` | integer | Yes | Total bytes transferred |
| `packets` | integer | Yes | Total packets |
| `auth_status` | string | No | success, failure, none |
| `event_type` | string | No | network_flow, authentication, dns_query, etc. |

Records with invalid timestamps, invalid IPs, negative bytes, or missing required fields are skipped and tracked with their rejection reason. Processing continues on all valid records.

---

## Behavioral Features

Fifteen features are computed per source IP aggregated across the observation window:

| Feature | Description |
|---------|-------------|
| `event_count` | Total connection events |
| `unique_destination_count` | Number of unique destination IPs |
| `unique_destination_port_count` | Number of unique destination ports |
| `failed_login_count` | Count of failed authentication events |
| `successful_login_count` | Count of successful authentication events |
| `success_failure_ratio` | Successful / (successful + failed) auth ratio |
| `bytes_sent` | Total estimated outbound bytes |
| `bytes_received` | Total estimated inbound bytes |
| `packet_count` | Total packets |
| `connection_rate` | Connections per minute |
| `protocol_diversity` | Shannon entropy of protocol distribution [0–1] |
| `destination_diversity` | Unique destinations / total events [0–1] |
| `unusual_peer_indicator` | Proportion of cross-subnet internal connections |
| `unusual_service_indicator` | Proportion of connections to high-risk services |
| `outbound_transfer_indicator` | Normalized outbound byte dominance [0–1] |

---

## Anomaly Detection

**Algorithm:** Isolation Forest (scikit-learn)

- Trained on a deterministic 1,000-sample normal baseline representing typical enterprise network behavior
- Fixed `random_state=42` ensures reproducibility
- `contamination=0.1` (10% expected anomaly rate)
- Output: normalized anomaly signal in [0, 1] where 1 = maximally anomalous
- Model persisted to `models/isolation_forest.joblib` + `models/scaler.joblib`

---

## Threat Classification

**Algorithm:** Random Forest (scikit-learn), multi-class

**Classes:** Normal, Port Scan, Brute Force, Lateral Movement, Data Exfiltration

The classifier is trained on generated training data — 400 samples per class with realistic behavioral patterns derived from known attack techniques. This training data bootstraps the classifier since no external labeled dataset is bundled.

- Fixed `random_state=42`, `n_estimators=100`, `class_weight=balanced`
- 80/20 train/test split
- Output: predicted class label + per-class probabilities
- `classifier_confidence` = maximum class probability

---

## Risk Formula

```
For non-Normal classifications:
  risk = round((anomaly_score × 0.35) + (classifier_confidence × 0.35) + (evidence_score × 0.30)) × 100

For Normal classification:
  risk = round((anomaly_score × 0.40) + (classifier_confidence × 0.10)) × 100

evidence_score = min(sum(evidence_item.impact) / 4.0, 1.0)
risk_score     = clamp(risk, 0, 100)
```

**Risk Bands:**

| Range | Band |
|-------|------|
| 0–30 | Normal |
| 31–70 | Suspicious |
| 71–100 | Malicious |

The same input always produces the same risk score (deterministic).

---

## Explainable Evidence

Every alert with risk > 0 contains factual observed-value evidence. Examples:

- `Unique destination ports scanned: 287 (threshold: 15)`
- `Failed authentication attempts: 143 (threshold: 5)`
- `Outbound data volume: 18.50 MB (threshold: 5.00 MB)`
- `Connection rate: 62.4/min (threshold: 10.0/min)`
- `Cross-subnet internal connections: 78.5% of traffic`

Evidence items carry an impact weight (0–1) and are ordered highest-impact first. Maximum 5 items per alert.

---

## SQLite Audit

Database: `database/sentinel.db` (created automatically)

**Table: alerts**

| Column | Type | Description |
|--------|------|-------------|
| `alert_id` | TEXT (UUID) | Primary key |
| `timestamp` | TEXT | Last-seen timestamp for this source IP |
| `source_ip` | TEXT | Source IP address |
| `dest_ip` | TEXT | Primary destination IP |
| `classification` | TEXT | Threat class |
| `threat_category` | TEXT | Risk band (Normal/Suspicious/Malicious) |
| `risk_score` | INTEGER | 0–100 |
| `anomaly_score` | REAL | Isolation Forest signal |
| `confidence` | REAL | Classifier confidence |
| `evidence_features` | TEXT (JSON) | List of evidence indicator names |
| `feature_values` | TEXT (JSON) | Observed values per indicator |
| `recommended_action` | TEXT | Suggested response |
| `model_version` | TEXT | Model version string |
| `status` | TEXT | new / reviewed / resolved |
| `created_at` | TEXT | Record creation time |
| `updated_at` | TEXT | Last update time |

---

## Policy Enforcement

```bash
python sentinel.py --input data/telemetry.csv --max-risk 70
```

- Evaluates all detected alerts against the configured threshold
- **Exit code 0**: All alerts within threshold (policy passes)
- **Exit code 1**: At least one alert exceeds the threshold (policy fails)
- **Exit code 2**: Fatal error (e.g., file not found)

Suitable for integration in CI/CD pipelines and automated security gates.

---

## Security Operations Dashboard

```bash
streamlit run app.py
```

**Pages:**
- **Overview**: Telemetry summary, detection metrics, risk distribution, threat categories, top source IPs, recent alerts, policy status
- **Alert Table**: Filterable/searchable alert table with CSV export
- **Alert Detail**: Full inspection of a selected IP — scores, evidence, features, recommended action
- **Audit History**: Historical alerts from SQLite, status management, audit log export

---

## CLI Reference

```bash
python sentinel.py [OPTIONS]

Options:
  --input, -i    Path to telemetry file (CSV or JSON/JSONL) [default: data/telemetry.csv]
  --max-risk, -r Maximum acceptable risk score 0-100 [default: 100]
  --db, -d       SQLite database path [default: database/sentinel.db]
  --output, -o   Optional path to save JSON output
  --format, -f   Input format: csv or json [default: csv]
  --verbose, -v  Enable verbose logging
  --no-db        Skip SQLite audit storage
```

---

## Installation

```bash
# Clone the repository
git clone <repository-url>
cd cyber-sentinel

# Install dependencies
pip install -r requirements.txt

# Generate the validation telemetry dataset
python data/generate_telemetry.py
```

---

## Running the System

### CLI

```bash
# Basic run with default telemetry
python sentinel.py

# With policy threshold
python sentinel.py --input data/telemetry.csv --max-risk 70

# Save results to JSON
python sentinel.py --input data/telemetry.csv --output results.json

# Custom database
python sentinel.py --input data/telemetry.csv --db /path/to/audit.db
```

### Dashboard

```bash
streamlit run app.py
```

Open http://localhost:8501 in a browser. Upload a telemetry file or use the default dataset, then click **Run Detection**.

### Tests

```bash
python -m pytest tests/ -v
# or
python -m unittest tests/test_sentinel.py -v
```

---

## Project Structure

```
cyber-sentinel/
├── app.py                      # Streamlit SOC dashboard
├── sentinel.py                 # CLI entry point
├── config.py                   # Global configuration
├── requirements.txt
├── README.md
├── .gitignore
├── src/
│   ├── __init__.py
│   ├── ingestion.py            # Telemetry ingestion and validation
│   ├── features.py             # Behavioral feature engineering
│   ├── detection.py            # Isolation Forest anomaly detection
│   ├── classification.py       # Random Forest threat classification
│   ├── risk.py                 # Deterministic risk scoring
│   ├── explain.py              # Explainable evidence generation
│   ├── database.py             # SQLite audit storage
│   ├── policy.py               # Policy enforcement
│   └── pipeline.py             # Pipeline orchestration
├── data/
│   ├── telemetry.csv           # Validation telemetry dataset
│   └── generate_telemetry.py   # Telemetry generator
├── models/                     # Trained model files (auto-generated)
├── database/                   # SQLite database (auto-created)
└── tests/
    └── test_sentinel.py        # Test suite
```

---

## Limitations

- The Isolation Forest is trained on a generated normal baseline rather than organization-specific historical data. Production deployment should include a calibration phase on known-good traffic.
- The Random Forest classifier uses generated training data. Accuracy improves with real labeled network data.
- Feature engineering uses per-IP aggregation. Behavioral context is limited to the telemetry file provided — longer observation windows yield more reliable features.
- The system does not perform deep packet inspection; it operates on flow-level metadata.

---

## Future Extensibility

- Real-time streaming telemetry ingestion (Kafka, syslog)
- Integration with SIEM platforms (Splunk, Elastic SIEM)
- MITRE ATT&CK framework mapping for each threat class
- Supervised fine-tuning on labeled organizational data
- Alert correlation across multiple source IPs
- Automated threat response integration (firewall API, SOAR)
- Time-series anomaly detection for long-running sessions
- Geographic IP enrichment
