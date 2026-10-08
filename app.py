"""
Cybersecurity Sentinel — Security Operations Dashboard
Streamlit-based SOC interface for threat detection and alert management.

Run:
    streamlit run app.py
"""
import io
import json
import logging
import os
import sys

import pandas as pd
import streamlit as st

# Ensure project root is on path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import DEFAULT_DB_PATH, DEFAULT_MAX_RISK, DEFAULT_TELEMETRY_PATH
from src.database import fetch_alerts, get_alert_stats, update_alert_status
from src.pipeline import run_pipeline

logging.basicConfig(level=logging.WARNING)

# ── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Cybersecurity Sentinel",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Styling ───────────────────────────────────────────────────────────────────
st.markdown("""
<style>
    .metric-card {
        background: #1e2130;
        border-radius: 8px;
        padding: 16px;
        text-align: center;
        border-left: 4px solid #4c8bff;
    }
    .metric-card.red { border-left-color: #ff4c4c; }
    .metric-card.yellow { border-left-color: #ffc107; }
    .metric-card.green { border-left-color: #28a745; }
    .risk-malicious { color: #ff4c4c; font-weight: bold; }
    .risk-suspicious { color: #ffc107; font-weight: bold; }
    .risk-normal { color: #28a745; }
    .stDataFrame { font-size: 13px; }
    h1, h2, h3 { color: #e0e6ff; }
    .section-header {
        background: linear-gradient(90deg, #1e2130, #2d3555);
        padding: 8px 16px;
        border-radius: 6px;
        margin: 12px 0 8px 0;
        font-weight: bold;
        color: #8eb4ff;
        letter-spacing: 0.5px;
    }
</style>
""", unsafe_allow_html=True)


# ── Session state ─────────────────────────────────────────────────────────────
def _init_state():
    defaults = {
        "pipeline_result": None,
        "alerts_df": pd.DataFrame(),
        "run_count": 0,
        "last_source": None,
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v


_init_state()


# ── Helpers ───────────────────────────────────────────────────────────────────
def _risk_color(score):
    if score >= 71:
        return "risk-malicious"
    elif score >= 31:
        return "risk-suspicious"
    return "risk-normal"


def _band_badge(band):
    colors = {"Malicious": "#ff4c4c", "Suspicious": "#ffc107", "Normal": "#28a745"}
    c = colors.get(band, "#aaaaaa")
    return f'<span style="color:{c};font-weight:bold;">{band}</span>'


def _run_detection(source, file_format, source_name, max_risk, db_path):
    with st.spinner("Running threat detection pipeline..."):
        result = run_pipeline(
            source=source,
            file_format=file_format,
            source_file=source_name,
            max_risk=max_risk,
            db_path=db_path,
            store_to_db=True,
        )
    st.session_state.pipeline_result = result
    st.session_state.alerts_df = result.alerts_df
    st.session_state.run_count += 1
    st.session_state.last_source = source_name
    return result


# ── Sidebar ───────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("## 🛡️ Cybersecurity Sentinel")
    st.markdown("---")

    st.markdown("### Input Configuration")
    input_mode = st.radio(
        "Telemetry Source",
        ["Upload File", "Default Dataset"],
        index=0,
    )

    uploaded_file = None
    if input_mode == "Upload File":
        uploaded_file = st.file_uploader(
            "Upload Telemetry (CSV or JSON)",
            type=["csv", "json", "jsonl"],
        )
        file_format = "json" if (
            uploaded_file and uploaded_file.name.endswith((".json", ".jsonl"))
        ) else "csv"
    else:
        file_format = "csv"

    st.markdown("---")
    st.markdown("### Policy Configuration")
    max_risk = st.slider(
        "Maximum Risk Threshold",
        min_value=0,
        max_value=100,
        value=DEFAULT_MAX_RISK,
        step=1,
        help="Alerts with risk score above this threshold fail the policy check.",
    )

    st.markdown("---")
    st.markdown("### Database")
    db_path = st.text_input("SQLite Path", value=DEFAULT_DB_PATH)

    st.markdown("---")
    run_button = st.button("▶  Run Detection", use_container_width=True, type="primary")

    if st.session_state.run_count > 0:
        st.success(f"Last run: {st.session_state.last_source}")

    st.markdown("---")
    st.markdown("### Navigation")
    page = st.radio(
        "View",
        ["Overview", "Alert Table", "Alert Detail", "Audit History"],
        index=0,
    )


# ── Run pipeline on button click ──────────────────────────────────────────────
if run_button:
    if input_mode == "Upload File":
        if uploaded_file is None:
            st.sidebar.error("Please upload a telemetry file.")
        else:
            content = uploaded_file.read()
            source = io.BytesIO(content)
            _run_detection(source, file_format, uploaded_file.name, max_risk, db_path)
    else:
        if not os.path.exists(DEFAULT_TELEMETRY_PATH):
            st.sidebar.error(f"Default dataset not found: {DEFAULT_TELEMETRY_PATH}")
        else:
            _run_detection(
                DEFAULT_TELEMETRY_PATH, "csv",
                DEFAULT_TELEMETRY_PATH, max_risk, db_path
            )


# ── Main content ─────────────────────────────────────────────────────────────
st.title("🛡️ Cybersecurity Sentinel")
st.markdown("**Intelligent Threat Detection and Network Anomaly Analysis**")
st.markdown("---")

result = st.session_state.pipeline_result
alerts_df = st.session_state.alerts_df


# ════════════════════════════════════════════════════════════════════════════════
# PAGE: OVERVIEW
# ════════════════════════════════════════════════════════════════════════════════
if page == "Overview":

    if result is None:
        st.info("👈 Select a telemetry source and click **Run Detection** to start analysis.")
        st.markdown("---")
        st.markdown("### System Capabilities")
        caps = [
            ("🔍 Telemetry Ingestion", "CSV/JSON telemetry with validation, normalization, and malformed-record resilience"),
            ("⚙️ Behavioral Analysis", "15 engineered features per source IP: connection rates, auth patterns, data volumes"),
            ("🤖 Anomaly Detection", "Isolation Forest trained on normal baseline — normalized anomaly signal [0–1]"),
            ("🎯 Threat Classification", "Random Forest multi-class: Normal, Port Scan, Brute Force, Lateral Movement, Data Exfiltration"),
            ("📊 Risk Scoring", "Deterministic 0–100 score combining anomaly signal, classifier confidence, and evidence"),
            ("🔎 Explainable Evidence", "Factual observed-value evidence for every alert — no vague AI explanations"),
            ("🗄️ SQLite Audit", "Full alert audit trail with traceability back to source telemetry"),
            ("🔒 Policy Enforcement", "Configurable risk threshold with pass/fail exit code for CI/CD integration"),
        ]
        for title, desc in caps:
            st.markdown(f"**{title}**: {desc}")
        st.stop()

    # ── Top metrics ──────────────────────────────────────────────────────────
    st.markdown('<div class="section-header">TELEMETRY SUMMARY</div>', unsafe_allow_html=True)
    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Total Events", f"{result.total_raw:,}")
    c2.metric("Valid Events", f"{result.valid_count:,}")
    c3.metric("Skipped", f"{result.skipped_count:,}")
    c4.metric("Background Filtered", f"{result.background_count:,}")
    c5.metric("IPs Analyzed", f"{result.alert_count:,}")

    st.markdown('<div class="section-header">DETECTION RESULTS</div>', unsafe_allow_html=True)
    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Normal", f"{result.normal_count}", delta=None)
    c2.metric("Suspicious", f"{result.suspicious_count}", delta=None)
    c3.metric("Malicious", f"{result.malicious_count}", delta=None)

    if not alerts_df.empty:
        avg_r = alerts_df["risk_score"].mean()
        max_r = alerts_df["risk_score"].max()
        c4.metric("Avg Risk Score", f"{avg_r:.1f}")
        c5.metric("Max Risk Score", f"{int(max_r)}")

    # ── Policy status ─────────────────────────────────────────────────────────
    st.markdown('<div class="section-header">POLICY STATUS</div>', unsafe_allow_html=True)
    if result.policy_result:
        pr = result.policy_result
        if pr.passed:
            st.success(
                f"✅ **Policy PASS** — All {pr.total_alerts} analyzed IPs are within "
                f"the maximum risk threshold of {pr.max_risk_threshold}."
            )
        else:
            st.error(
                f"❌ **Policy FAIL** — {len(pr.violations)} IP(s) exceed the "
                f"maximum risk threshold of {pr.max_risk_threshold}. "
                f"Exit code: {pr.exit_code}"
            )
            with st.expander("View Policy Violations"):
                viol_df = pd.DataFrame(pr.violations)
                st.dataframe(viol_df, use_container_width=True)

    # ── Risk distribution ─────────────────────────────────────────────────────
    if not alerts_df.empty:
        col1, col2 = st.columns(2)

        with col1:
            st.markdown('<div class="section-header">RISK DISTRIBUTION</div>',
                        unsafe_allow_html=True)
            try:
                import plotly.express as px
                fig = px.histogram(
                    alerts_df, x="risk_score", nbins=20,
                    color_discrete_sequence=["#4c8bff"],
                    labels={"risk_score": "Risk Score", "count": "IP Count"},
                )
                fig.update_layout(
                    paper_bgcolor="rgba(0,0,0,0)",
                    plot_bgcolor="rgba(0,0,0,0)",
                    font_color="#e0e6ff",
                    margin=dict(l=20, r=20, t=20, b=20),
                )
                fig.add_vline(x=30, line_dash="dash", line_color="#28a745", annotation_text="Normal/Suspicious")
                fig.add_vline(x=70, line_dash="dash", line_color="#ff4c4c", annotation_text="Suspicious/Malicious")
                st.plotly_chart(fig, use_container_width=True)
            except ImportError:
                risk_counts = alerts_df["risk_band"].value_counts()
                st.bar_chart(risk_counts)

        with col2:
            st.markdown('<div class="section-header">THREAT CATEGORIES</div>',
                        unsafe_allow_html=True)
            try:
                import plotly.express as px
                class_counts = alerts_df["classification"].value_counts().reset_index()
                class_counts.columns = ["Classification", "Count"]
                fig2 = px.pie(
                    class_counts, names="Classification", values="Count",
                    color_discrete_sequence=px.colors.qualitative.Bold,
                )
                fig2.update_layout(
                    paper_bgcolor="rgba(0,0,0,0)",
                    font_color="#e0e6ff",
                    margin=dict(l=20, r=20, t=20, b=20),
                )
                st.plotly_chart(fig2, use_container_width=True)
            except ImportError:
                class_counts = alerts_df["classification"].value_counts()
                st.bar_chart(class_counts)

    # ── Top source IPs ────────────────────────────────────────────────────────
    st.markdown('<div class="section-header">TOP SOURCE IPs BY RISK</div>',
                unsafe_allow_html=True)
    if not alerts_df.empty:
        top_ips = (
            alerts_df[["source_ip", "classification", "risk_score", "risk_band",
                        "anomaly_score", "classifier_confidence"]]
            .sort_values("risk_score", ascending=False)
            .head(10)
        )
        st.dataframe(top_ips, use_container_width=True)

    # ── Recent alerts ──────────────────────────────────────────────────────────
    st.markdown('<div class="section-header">RECENT ALERTS (HIGH RISK FIRST)</div>',
                unsafe_allow_html=True)
    if not alerts_df.empty:
        recent = alerts_df.sort_values("risk_score", ascending=False).head(15)
        display_cols = [c for c in [
            "source_ip", "classification", "risk_score", "risk_band",
            "anomaly_score", "classifier_confidence", "last_seen",
        ] if c in recent.columns]
        st.dataframe(recent[display_cols], use_container_width=True)

    # ── Ingestion skip reasons ────────────────────────────────────────────────
    if result.skip_reasons:
        with st.expander("📋 Skipped Record Details"):
            st.json(result.skip_reasons)


# ════════════════════════════════════════════════════════════════════════════════
# PAGE: ALERT TABLE
# ════════════════════════════════════════════════════════════════════════════════
elif page == "Alert Table":
    st.subheader("Alert Table")

    if alerts_df.empty:
        st.info("No detection results yet. Run the detection pipeline first.")
        st.stop()

    # Filters
    col1, col2, col3 = st.columns(3)
    with col1:
        filter_band = st.multiselect(
            "Risk Band",
            ["Normal", "Suspicious", "Malicious"],
            default=["Suspicious", "Malicious"],
        )
    with col2:
        filter_class = st.multiselect(
            "Classification",
            sorted(alerts_df["classification"].unique().tolist()),
            default=[],
        )
    with col3:
        min_risk_filter = st.slider("Minimum Risk Score", 0, 100, 0)

    # Search
    search_ip = st.text_input("🔍 Search by Source IP", "")

    filtered = alerts_df.copy()
    if filter_band:
        filtered = filtered[filtered["risk_band"].isin(filter_band)]
    if filter_class:
        filtered = filtered[filtered["classification"].isin(filter_class)]
    filtered = filtered[filtered["risk_score"] >= min_risk_filter]
    if search_ip:
        filtered = filtered[filtered["source_ip"].str.contains(search_ip, na=False)]

    st.write(f"**{len(filtered)} alerts matching filters**")

    display_cols = [c for c in [
        "source_ip", "classification", "risk_score", "risk_band",
        "anomaly_score", "classifier_confidence",
        "event_count", "failed_login_count",
        "unique_destination_port_count", "bytes_sent",
        "first_seen", "last_seen",
    ] if c in filtered.columns]

    st.dataframe(
        filtered[display_cols].sort_values("risk_score", ascending=False),
        use_container_width=True,
    )

    # Download
    csv_data = filtered[display_cols].to_csv(index=False)
    st.download_button(
        "⬇️ Download Filtered Results (CSV)",
        data=csv_data,
        file_name="sentinel_alerts.csv",
        mime="text/csv",
    )


# ════════════════════════════════════════════════════════════════════════════════
# PAGE: ALERT DETAIL
# ════════════════════════════════════════════════════════════════════════════════
elif page == "Alert Detail":
    st.subheader("Alert Detail Inspector")

    if alerts_df.empty:
        st.info("No detection results yet. Run the detection pipeline first.")
        st.stop()

    # IP selector — prioritize high-risk
    sorted_ips = (
        alerts_df.sort_values("risk_score", ascending=False)["source_ip"]
        .unique()
        .tolist()
    )
    selected_ip = st.selectbox("Select Source IP", sorted_ips)

    row = alerts_df[alerts_df["source_ip"] == selected_ip].iloc[0]

    # Header
    cls = str(row.get("classification", "Normal"))
    risk = int(row.get("risk_score", 0))
    band = str(row.get("risk_band", "Normal"))

    band_colors = {"Malicious": "🔴", "Suspicious": "🟡", "Normal": "🟢"}
    st.markdown(f"## {band_colors.get(band, '⚪')} {selected_ip}")
    st.markdown(f"**Classification:** {cls} | **Risk Score:** {risk} | **Risk Band:** {band}")

    st.markdown("---")

    col1, col2 = st.columns(2)
    with col1:
        st.markdown("### Detection Scores")
        st.metric("Risk Score", risk)
        st.metric("Anomaly Score", f"{float(row.get('anomaly_score', 0)):.4f}")
        st.metric("Classifier Confidence", f"{float(row.get('classifier_confidence', 0)):.4f}")

    with col2:
        st.markdown("### Activity Summary")
        st.metric("Total Events", int(row.get("event_count", 0)))
        st.metric("Unique Destinations", int(row.get("unique_destination_count", 0)))
        st.metric("Unique Dest Ports", int(row.get("unique_destination_port_count", 0)))

    st.markdown("---")

    col3, col4 = st.columns(2)
    with col3:
        st.markdown("### Network Activity")
        st.metric("Bytes Sent", f"{float(row.get('bytes_sent', 0)):,.0f}")
        st.metric("Bytes Received", f"{float(row.get('bytes_received', 0)):,.0f}")
        st.metric("Packet Count", f"{float(row.get('packet_count', 0)):,.0f}")
        st.metric("Connection Rate", f"{float(row.get('connection_rate', 0)):.2f}/min")

    with col4:
        st.markdown("### Authentication")
        st.metric("Failed Logins", int(row.get("failed_login_count", 0)))
        st.metric("Successful Logins", int(row.get("successful_login_count", 0)))
        st.metric("Auth Success Rate", f"{float(row.get('success_failure_ratio', 0)):.2%}")

    st.markdown("---")
    st.markdown("### Security Evidence")

    evidence = row.get("evidence", [])
    if isinstance(evidence, str):
        try:
            evidence = json.loads(evidence)
        except Exception:
            evidence = []

    if evidence:
        for i, ev in enumerate(evidence, 1):
            impact = ev.get("impact", 0)
            indicator = ev.get("indicator", "")
            description = ev.get("description", "")
            observed = ev.get("observed_value", "")
            threshold = ev.get("threshold", "")

            impact_bar = "█" * int(impact * 10) + "░" * (10 - int(impact * 10))
            st.markdown(
                f"**{i}. {indicator.replace('_', ' ').title()}**  \n"
                f"   {description}  \n"
                f"   Observed: `{observed}` | Threshold: `{threshold}` | "
                f"Impact: `{impact_bar}` {impact:.2f}"
            )
    else:
        st.write("No specific evidence indicators generated for this IP.")

    st.markdown("---")
    st.markdown("### Recommended Action")
    action = str(row.get("recommended_action", "No action recommended."))
    st.info(action)

    st.markdown("---")
    st.markdown("### Timing")
    c1, c2 = st.columns(2)
    c1.metric("First Seen", str(row.get("first_seen", "N/A")))
    c2.metric("Last Seen", str(row.get("last_seen", "N/A")))

    # All features expandable
    with st.expander("📊 All Feature Values"):
        from config import FEATURE_COLUMNS
        feat_data = {col: row.get(col, 0.0) for col in FEATURE_COLUMNS if col in row.index}
        feat_df = pd.DataFrame(list(feat_data.items()), columns=["Feature", "Value"])
        feat_df["Value"] = feat_df["Value"].apply(lambda x: f"{float(x):.4f}")
        st.dataframe(feat_df, use_container_width=True)


# ════════════════════════════════════════════════════════════════════════════════
# PAGE: AUDIT HISTORY
# ════════════════════════════════════════════════════════════════════════════════
elif page == "Audit History":
    st.subheader("Audit History")

    if not os.path.exists(db_path):
        st.info(f"No audit database found at: {db_path}")
        st.stop()

    stats = get_alert_stats(db_path)
    if stats:
        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Total Stored Alerts", stats.get("total_alerts", 0))
        col2.metric("Avg Risk Score", f"{stats.get('avg_risk', 0):.1f}")
        col3.metric("Max Risk Score", stats.get("max_risk", 0))
        col4.metric("Open (New)", stats.get("new_count", 0))

        col5, col6, col7 = st.columns(3)
        col5.metric("Normal", stats.get("normal_count", 0))
        col6.metric("Suspicious", stats.get("suspicious_count", 0))
        col7.metric("Malicious", stats.get("malicious_count", 0))

    st.markdown("---")
    st.markdown("### Stored Alerts")

    col1, col2 = st.columns(2)
    with col1:
        status_filter_opt = st.selectbox("Filter by Status", ["all", "new", "reviewed", "resolved"])
    with col2:
        min_risk_hist = st.slider("Minimum Risk Score", 0, 100, 0, key="hist_risk")

    status_arg = None if status_filter_opt == "all" else status_filter_opt
    hist_df = fetch_alerts(db_path=db_path, limit=500, status_filter=status_arg, min_risk=min_risk_hist)

    if hist_df.empty:
        st.info("No alerts match the current filters.")
    else:
        st.write(f"**{len(hist_df)} alerts**")
        display_cols = [c for c in [
            "alert_id", "timestamp", "source_ip", "dest_ip",
            "classification", "threat_category", "risk_score",
            "anomaly_score", "confidence", "model_version", "status",
        ] if c in hist_df.columns]
        st.dataframe(hist_df[display_cols], use_container_width=True)

        # Status update
        st.markdown("---")
        st.markdown("### Update Alert Status")
        col1, col2, col3 = st.columns([2, 1, 1])
        with col1:
            alert_ids = hist_df["alert_id"].tolist() if "alert_id" in hist_df.columns else []
            selected_alert_id = st.selectbox("Alert ID", alert_ids[:50])
        with col2:
            new_status = st.selectbox("New Status", ["new", "reviewed", "resolved"])
        with col3:
            st.markdown("&nbsp;", unsafe_allow_html=True)
            if st.button("Update Status"):
                success = update_alert_status(selected_alert_id, new_status, db_path)
                if success:
                    st.success(f"Alert {selected_alert_id[:8]}... updated to '{new_status}'")
                    st.rerun()
                else:
                    st.error("Failed to update alert status.")

        # Download audit
        csv_audit = hist_df[display_cols].to_csv(index=False)
        st.download_button(
            "⬇️ Download Audit Log (CSV)",
            data=csv_audit,
            file_name="sentinel_audit.csv",
            mime="text/csv",
        )


# ── Footer ────────────────────────────────────────────────────────────────────
st.markdown("---")
st.markdown(
    "<div style='text-align:center;color:#666;font-size:12px;'>"
    "Cybersecurity Sentinel | Threat Detection and Network Anomaly Analysis"
    "</div>",
    unsafe_allow_html=True,
)
