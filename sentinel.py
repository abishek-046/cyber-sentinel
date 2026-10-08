#!/usr/bin/env python3
"""
Cybersecurity Sentinel - Command-Line Interface

Usage:
    python sentinel.py --input data/telemetry.csv
    python sentinel.py --input data/telemetry.csv --max-risk 70
    python sentinel.py --input data/telemetry.csv --max-risk 70 --output results.json
    python sentinel.py --input data/telemetry.csv --db database/custom.db

Exit codes:
    0  All detected alerts are within the configured risk threshold.
    1  At least one alert exceeds the maximum risk threshold.
    2  Fatal error (e.g., input file not found).
"""
import argparse
import json
import logging
import os
import sys

# Set UTF-8 encoding for stdout to avoid codec issues on Windows
if sys.stdout.encoding and sys.stdout.encoding.lower() not in ('utf-8', 'utf8'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if sys.stderr.encoding and sys.stderr.encoding.lower() not in ('utf-8', 'utf8'):
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

# Ensure project root is on path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import DEFAULT_DB_PATH, DEFAULT_MAX_RISK, DEFAULT_TELEMETRY_PATH
from src.pipeline import run_pipeline

# ── Logging setup ────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("sentinel")


# ── Color helpers ─────────────────────────────────────────────────────────────
try:
    import colorama
    colorama.init(autoreset=True)
    RED = colorama.Fore.RED
    YELLOW = colorama.Fore.YELLOW
    GREEN = colorama.Fore.GREEN
    CYAN = colorama.Fore.CYAN
    WHITE = colorama.Fore.WHITE
    BOLD = colorama.Style.BRIGHT
    RESET = colorama.Style.RESET_ALL
except ImportError:
    RED = YELLOW = GREEN = CYAN = WHITE = BOLD = RESET = ""


def _color_risk(score: int) -> str:
    if score >= 71:
        return f"{RED}{BOLD}{score}{RESET}"
    elif score >= 31:
        return f"{YELLOW}{score}{RESET}"
    return f"{GREEN}{score}{RESET}"


def _color_band(band: str) -> str:
    colors = {"Malicious": RED + BOLD, "Suspicious": YELLOW, "Normal": GREEN}
    return f"{colors.get(band, WHITE)}{band}{RESET}"


def _color_class(cls: str) -> str:
    colors = {
        "Port Scan": YELLOW,
        "Brute Force": RED,
        "Lateral Movement": RED + BOLD,
        "Data Exfiltration": RED + BOLD,
        "Normal": GREEN,
    }
    return f"{colors.get(cls, WHITE)}{cls}{RESET}"


def _print_separator(char="-", width=72):
    print(char * width)


def _print_header():
    print()
    _print_separator("=")
    print(f"{BOLD}  CYBERSECURITY SENTINEL -- THREAT DETECTION ENGINE{RESET}")
    _print_separator("=")
    print()


def _print_ingestion_summary(result):
    print(f"{BOLD}TELEMETRY INGESTION{RESET}")
    _print_separator()
    print(f"  Total raw records   : {result.total_raw}")
    print(f"  Valid records       : {GREEN}{result.valid_count}{RESET}")
    print(f"  Skipped records     : {YELLOW if result.skipped_count else GREEN}"
          f"{result.skipped_count}{RESET}")
    print(f"  Background filtered : {result.background_count}")
    if result.skip_reasons:
        print(f"  Skip breakdown:")
        for reason, count in result.skip_reasons.items():
            print(f"    {reason}: {count}")
    print()


def _print_detection_summary(result):
    print(f"{BOLD}DETECTION RESULTS{RESET}")
    _print_separator()
    print(f"  Source IPs analyzed : {result.alert_count}")
    print(f"  Normal              : {GREEN}{result.normal_count}{RESET}")
    print(f"  Suspicious          : {YELLOW}{result.suspicious_count}{RESET}")
    print(f"  Malicious           : {RED}{result.malicious_count}{RESET}")
    print()


def _print_alert_table(alerts_df):
    if alerts_df.empty:
        print(f"{GREEN}  No alerts generated.{RESET}")
        return

    # Sort by risk descending
    df = alerts_df.sort_values("risk_score", ascending=False)

    print(f"{BOLD}ALERT DETAILS{RESET}")
    _print_separator()
    header = f"  {'Source IP':<18} {'Classification':<20} {'Risk':>5}  {'Band':<12} {'Anomaly':>8}  {'Confidence':>10}"
    print(header)
    print("  " + "-" * 70)

    for _, row in df.iterrows():
        ip = str(row.get("source_ip", ""))
        cls = str(row.get("classification", "Normal"))
        risk = int(row.get("risk_score", 0))
        band = str(row.get("risk_band", "Normal"))
        anomaly = float(row.get("anomaly_score", 0.0))
        conf = float(row.get("classifier_confidence", 0.0))

        # Only print non-normal or medium+ risk
        if risk > 0 or cls != "Normal":
            print(
                f"  {ip:<18} {_color_class(cls):<30} "
                f"{_color_risk(risk):>14}  {_color_band(band):<22} "
                f"{anomaly:>8.3f}  {conf:>10.3f}"
            )
    print()


def _print_evidence(alerts_df):
    df = alerts_df[alerts_df["risk_score"] > 30].sort_values("risk_score", ascending=False)
    if df.empty:
        return

    print(f"{BOLD}SECURITY EVIDENCE (risk > 30){RESET}")
    _print_separator()

    for _, row in df.iterrows():
        ip = str(row.get("source_ip", ""))
        cls = str(row.get("classification", ""))
        risk = int(row.get("risk_score", 0))
        evidence = row.get("evidence", [])

        if not evidence:
            continue

        print(f"  {BOLD}{ip}{RESET} [{_color_class(cls)}] Risk: {_color_risk(risk)}")
        for ev in evidence:
            print(f"    * {ev.get('description', '')}")
        action = row.get("recommended_action", "")
        if action:
            print(f"    >> ACTION: {action[:120]}")
        print()


def _print_policy(policy_result, max_risk):
    print(f"{BOLD}POLICY EVALUATION (--max-risk {max_risk}){RESET}")
    _print_separator()
    if policy_result.passed:
        print(f"  Status  : {GREEN}{BOLD}PASS{RESET}")
        print(f"  {policy_result.summary}")
    else:
        print(f"  Status  : {RED}{BOLD}FAIL{RESET}")
        print(f"  {policy_result.summary}")
        print(f"  Violations:")
        for v in policy_result.violations[:10]:
            print(
                f"    {v['source_ip']:<18} {v['classification']:<20} "
                f"risk={_color_risk(v['risk_score'])}"
            )
    print()


def _save_output(result, output_path):
    """Save pipeline results to JSON file."""
    import json

    output = {
        "run_id": result.run_id,
        "source_file": result.source_file,
        "ingestion": {
            "total_raw": result.total_raw,
            "valid_count": result.valid_count,
            "skipped_count": result.skipped_count,
            "background_count": result.background_count,
            "skip_reasons": result.skip_reasons,
        },
        "detection": {
            "alert_count": result.alert_count,
            "normal_count": result.normal_count,
            "suspicious_count": result.suspicious_count,
            "malicious_count": result.malicious_count,
        },
        "policy": result.policy_result.to_dict() if result.policy_result else None,
        "alerts": [],
    }

    if not result.alerts_df.empty:
        for _, row in result.alerts_df.iterrows():
            alert = {
                "source_ip": str(row.get("source_ip", "")),
                "classification": str(row.get("classification", "")),
                "risk_score": int(row.get("risk_score", 0)),
                "risk_band": str(row.get("risk_band", "")),
                "anomaly_score": float(row.get("anomaly_score", 0.0)),
                "classifier_confidence": float(row.get("classifier_confidence", 0.0)),
                "evidence": row.get("evidence", []),
                "recommended_action": str(row.get("recommended_action", "")),
            }
            output["alerts"].append(alert)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, default=str)
    print(f"  Results saved to: {output_path}")


def main():
    parser = argparse.ArgumentParser(
        description="Cybersecurity Sentinel - Intelligent Threat & Anomaly Detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python sentinel.py --input data/telemetry.csv
  python sentinel.py --input data/telemetry.csv --max-risk 70
  python sentinel.py --input data/telemetry.csv --max-risk 70 --output results.json
  python sentinel.py --input data/telemetry.csv --db database/audit.db

Exit codes:
  0  Policy PASS - all alerts within risk threshold
  1  Policy FAIL - one or more alerts exceed risk threshold
  2  Fatal error
        """,
    )
    parser.add_argument(
        "--input", "-i",
        default=DEFAULT_TELEMETRY_PATH,
        help="Path to telemetry file (CSV or JSON/JSONL). Default: data/telemetry.csv",
    )
    parser.add_argument(
        "--max-risk", "-r",
        type=int,
        default=DEFAULT_MAX_RISK,
        dest="max_risk",
        help="Maximum acceptable risk score (0-100). Alerts above this fail policy. Default: 100",
    )
    parser.add_argument(
        "--db", "-d",
        default=DEFAULT_DB_PATH,
        help="SQLite database path. Default: database/sentinel.db",
    )
    parser.add_argument(
        "--output", "-o",
        default=None,
        help="Optional path to save JSON output.",
    )
    parser.add_argument(
        "--format", "-f",
        default="csv",
        choices=["csv", "json"],
        dest="file_format",
        help="Input file format. Default: csv",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose logging.",
    )
    parser.add_argument(
        "--no-db",
        action="store_true",
        dest="no_db",
        help="Skip SQLite audit storage.",
    )

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.INFO)

    _print_header()

    # Validate input file
    if not os.path.exists(args.input):
        print(f"{RED}ERROR: Input file not found: {args.input}{RESET}")
        sys.exit(2)

    print(f"  Input file  : {args.input}")
    print(f"  Max risk    : {args.max_risk}")
    print(f"  Database    : {args.db}")
    print()

    # Run pipeline
    try:
        result = run_pipeline(
            source=args.input,
            file_format=args.file_format,
            source_file=args.input,
            max_risk=args.max_risk,
            db_path=args.db,
            store_to_db=not args.no_db,
        )
    except Exception as e:
        print(f"{RED}FATAL ERROR: {e}{RESET}")
        logger.exception("Pipeline fatal error")
        sys.exit(2)

    # Print results
    _print_ingestion_summary(result)
    _print_detection_summary(result)

    if not result.alerts_df.empty:
        _print_alert_table(result.alerts_df)
        _print_evidence(result.alerts_df)

    if result.policy_result:
        _print_policy(result.policy_result, args.max_risk)

    # Report pipeline errors (non-fatal)
    if result.errors:
        print(f"{YELLOW}WARNINGS:{RESET}")
        for err in result.errors:
            print(f"  - {err}")
        print()

    # Save output if requested
    if args.output:
        _save_output(result, args.output)

    # Summary line
    _print_separator("=")
    risk_scores = result.alerts_df["risk_score"].tolist() if not result.alerts_df.empty else []
    avg_risk = sum(risk_scores) / len(risk_scores) if risk_scores else 0
    max_risk_seen = max(risk_scores) if risk_scores else 0
    print(
        f"  Processed {result.valid_count} events | "
        f"{result.alert_count} IPs analyzed | "
        f"avg risk: {avg_risk:.1f} | max risk: {_color_risk(max_risk_seen)}"
    )
    _print_separator("=")
    print()

    # Exit with policy exit code
    if result.policy_result:
        sys.exit(result.policy_result.exit_code)
    sys.exit(0)


if __name__ == "__main__":
    main()
