"""Streamlit SOC Analyst Interface for Incident Triage and Evidence Analysis."""

from datetime import datetime, timezone
import json
import os
import sys

# Ensure repository root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

import streamlit as st
import pandas as pd
from sqlalchemy import select, func, desc

from app.config import (
    AssetCriticalityLevel,
    IncidentPriority,
    IncidentStatus,
    SeverityLevel,
    settings,
)
from app.correlation.engine import CorrelationEngine
from app.database import SessionLocal, init_db
from app.ingestion.csv_ingest import parse_and_normalize_csv
from app.ingestion.json_ingest import parse_and_normalize_json
from app.models.alert import AlertModel
from app.models.incident import IncidentModel, IncidentAlertModel, IncidentStatusHistoryModel
from app.models.summary import IncidentEvidenceSummaryModel
from app.services.alert_service import AlertService
from app.services.incident_service import IncidentService

# Page Configuration
st.set_page_config(
    page_title="SOC Incident Triage & Analysis",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Initialize database
init_db()


def get_db_session():
    """Context-managed DB session for Streamlit."""
    return SessionLocal()


def priority_badge(prio: str) -> str:
    """Format priority with colored emoji."""
    prio_upper = str(prio).upper()
    if prio_upper == "CRITICAL":
        return "🔴 CRITICAL"
    if prio_upper == "HIGH":
        return "🟠 HIGH"
    if prio_upper == "MEDIUM":
        return "🟡 MEDIUM"
    if prio_upper == "LOW":
        return "🔵 LOW"
    return "⚪ INFO"


def status_badge(status_val: str) -> str:
    """Format status with indicator."""
    s = str(status_val).upper()
    if s == "NEW":
        return "✨ NEW"
    if s == "TRIAGED":
        return "👁️ TRIAGED"
    if s == "INVESTIGATING":
        return "🔍 INVESTIGATING"
    if s == "CLOSED":
        return "✅ CLOSED"
    if s == "FALSE_POSITIVE":
        return "🚫 FALSE POSITIVE"
    return s


# Sidebar
st.sidebar.title("🛡️ SOC Command")
st.sidebar.caption("Security Alert Triage & Incident Analysis")

# Metrics in sidebar
with get_db_session() as db:
    total_alerts = db.execute(select(func.count(AlertModel.id))).scalar() or 0
    total_incidents = db.execute(select(func.count(IncidentModel.id))).scalar() or 0
    active_incidents = (
        db.execute(
            select(func.count(IncidentModel.id)).where(
                IncidentModel.status.in_(["NEW", "TRIAGED", "INVESTIGATING"])
            )
        ).scalar()
        or 0
    )
    critical_incidents = (
        db.execute(
            select(func.count(IncidentModel.id)).where(IncidentModel.priority == "CRITICAL")
        ).scalar()
        or 0
    )

st.sidebar.metric("Active Incidents", active_incidents, f"{critical_incidents} Critical")
st.sidebar.metric("Total Ingested Alerts", total_alerts)
st.sidebar.metric("Total Incidents", total_incidents)

st.sidebar.divider()

# Quick action: load synthetic scenario
if st.sidebar.button("⚡ Load Synthetic Attack Scenarios", use_container_width=True):
    synthetic_path = os.path.join(os.path.dirname(__file__), "../../data/synthetic_alerts.json")
    if os.path.exists(synthetic_path):
        with open(synthetic_path, "r", encoding="utf-8") as f:
            raw_data = json.load(f)
        with get_db_session() as db:
            alerts, errs = parse_and_normalize_json(raw_data)
            saved, dupes = AlertService.save_alerts_batch(db, alerts)
            created, updated = CorrelationEngine.correlate_batch(db, saved)
            st.sidebar.success(
                f"Ingested {len(saved)} new alerts ({dupes} dupes). Created {len(created)}, updated {len(updated)} incidents."
            )
            st.rerun()
    else:
        st.sidebar.error("Synthetic alerts file not found.")

menu = st.sidebar.radio(
    "Navigation",
    [
        "🛡️ Incident Triage Queue",
        "📥 Alert Ingestion Sandbox",
        "📋 Telemetry & Raw Alerts",
        "⚙️ Engine Configuration",
    ],
)

# Main Navigation Router
if menu == "🛡️ Incident Triage Queue":
    st.title("Incident Triage Queue")
    st.caption("Review correlated incidents, inspect factor-by-factor scoring explanations, and manage triage lifecycle.")

    # Filter row
    col1, col2, col3 = st.columns([2, 2, 4])
    with col1:
        status_filter = st.selectbox(
            "Filter by Status",
            ["ALL", "NEW", "TRIAGED", "INVESTIGATING", "CLOSED", "FALSE_POSITIVE"],
        )
    with col2:
        priority_filter = st.selectbox(
            "Filter by Priority",
            ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"],
        )
    with col3:
        search_query = st.text_input("Search (ID, Host, User, Title)", placeholder="e.g. dc01, admin, mimikatz")

    # Fetch incidents
    with get_db_session() as db:
        stmt = select(IncidentModel)
        if status_filter != "ALL":
            stmt = stmt.where(IncidentModel.status == status_filter)
        if priority_filter != "ALL":
            stmt = stmt.where(IncidentModel.priority == priority_filter)
        if search_query.strip():
            pat = f"%{search_query.strip()}%"
            stmt = stmt.where(
                (IncidentModel.id.ilike(pat))
                | (IncidentModel.title.ilike(pat))
                | (IncidentModel.primary_host.ilike(pat))
                | (IncidentModel.primary_user.ilike(pat))
            )

        incidents = list(
            db.execute(stmt.order_by(desc(IncidentModel.score), desc(IncidentModel.updated_at))).scalars().all()
        )

    if not incidents:
        st.info("No incidents match the active filters. Click 'Load Synthetic Attack Scenarios' in the sidebar or ingest alerts to create incidents.")
    else:
        # Incident Table View
        table_rows = []
        for inc in incidents:
            table_rows.append({
                "Incident ID": inc.id,
                "Priority": priority_badge(inc.priority),
                "Score": f"{inc.score:.1f} / 100",
                "Status": status_badge(inc.status),
                "Title": inc.title,
                "Alerts": inc.alert_count,
                "Host": inc.primary_host or "N/A",
                "User": inc.primary_user or "N/A",
                "First Seen (UTC)": inc.first_seen.strftime("%Y-%m-%d %H:%M"),
                "Last Seen (UTC)": inc.last_seen.strftime("%Y-%m-%d %H:%M"),
            })
        st.dataframe(pd.DataFrame(table_rows), use_container_width=True, hide_index=True)

        st.divider()

        # Detailed Incident Inspector
        st.subheader("🔍 Incident Deep Dive & Evidence Inspector")
        selected_id = st.selectbox(
            "Select Incident to Inspect",
            [inc.id for inc in incidents],
            format_func=lambda x: f"{x} - {next((i.title for i in incidents if i.id == x), '')}",
        )

        with get_db_session() as db:
            selected_incident = IncidentService.get_incident(db, selected_id)
            if selected_incident:
                # Ensure evidence summary exists
                if not selected_incident.evidence_summaries:
                    IncidentService.generate_or_update_summary(db, selected_incident.id, use_llm=False)
                    db.refresh(selected_incident)

                # Top info bar
                h_col1, h_col2, h_col3, h_col4 = st.columns(4)
                h_col1.metric("Priority", priority_badge(selected_incident.priority))
                h_col2.metric("Score", f"{selected_incident.score:.1f} / 100")
                h_col3.metric("Status", status_badge(selected_incident.status))
                h_col4.metric("Supporting Alerts", selected_incident.alert_count)

                # Status Transition Action Card
                with st.expander("📝 Analyst Triage & Status Transition", expanded=False):
                    c_s1, c_s2 = st.columns([2, 5])
                    with c_s1:
                        new_status_choice = st.selectbox(
                            "Transition To Status",
                            [s.value for s in IncidentStatus if s.value != selected_incident.status],
                            index=0,
                        )
                        analyst_name = st.text_input("Analyst Handle", value="secops_analyst")
                    with c_s2:
                        status_notes = st.text_area("Triage Rational / Notes", placeholder="Reason for status change...")
                        if st.button("Apply Status Transition", type="primary"):
                            IncidentService.update_status(
                                db,
                                incident_id=selected_incident.id,
                                new_status=IncidentStatus(new_status_choice),
                                notes=status_notes,
                                analyst=analyst_name,
                            )
                            st.success(f"Incident updated to {new_status_choice}")
                            st.rerun()

                # Triage Explainability Card
                st.markdown("### 📊 Explainable Prioritization Breakdown")
                st.caption("Deterministic factor-by-factor breakdown explaining exact point contributions.")

                score_breakdown = selected_incident.score_breakdown or []
                if score_breakdown:
                    factor_cols = st.columns(min(len(score_breakdown), 4))
                    for idx, factor in enumerate(score_breakdown):
                        with factor_cols[idx % 4]:
                            st.metric(
                                label=factor.get("factor", "Factor"),
                                value=f"+{factor.get('points', 0):.1f} pts",
                                help=factor.get("reason", ""),
                            )
                            st.caption(f"**Value:** {factor.get('value')} — {factor.get('reason')}")
                else:
                    st.write("No score breakdown recorded.")

                st.divider()

                # Evidence Summary & Fact / Hypothesis Separation
                st.markdown("### 📑 Evidence-Grounded Analysis")
                st.caption("Strict separation between verifiable observed facts and inferred hypotheses.")

                summary_model = (
                    selected_incident.evidence_summaries[0]
                    if selected_incident.evidence_summaries
                    else None
                )

                if summary_model:
                    st.info(f"**Concise Summary:** {summary_model.concise_summary}")

                    tab_facts, tab_hypo, tab_actions, tab_timeline = st.tabs([
                        "🔍 Observed Empirical Facts",
                        "💡 Inferred Tactical Hypotheses",
                        "🛡️ Recommended Containment Actions",
                        "⏱️ Chronological Timeline",
                    ])

                    with tab_facts:
                        st.markdown("**Verifiable facts directly derived from telemetry:**")
                        for fact in summary_model.observed_facts or []:
                            st.markdown(f"- {fact}")

                    with tab_hypo:
                        st.markdown("**Inferred hypotheses and attack objectives (segregated from facts):**")
                        for hypo in summary_model.inferred_hypotheses or []:
                            st.markdown(f"- ⚠️ {hypo}")

                    with tab_actions:
                        st.markdown("**Actionable triage checklist:**")
                        for action in summary_model.recommended_actions or []:
                            st.markdown(f"- [ ] {action}")

                    with tab_timeline:
                        st.markdown("**Ordered chronological event progression:**")
                        for t in summary_model.chronological_timeline or []:
                            t_time = t.get("timestamp", "")
                            t_src = t.get("source", "")
                            t_type = t.get("event_type", "")
                            t_sum = t.get("summary", "")
                            t_aid = t.get("alert_id", "")
                            st.markdown(f"**`{t_time}`** | **{t_src}** | `{t_type}` | Alert ID: `{t_aid}`")
                            st.caption(f"{t_sum} | Entities: {t.get('entities', {})}")
                            st.divider()

                # Supporting Alerts Forensics View
                st.markdown("### 📦 Supporting Alerts & Forensic Raw Payloads")
                alerts_linked = [l.alert for l in selected_incident.alert_links if l.alert]
                for a in alerts_linked:
                    with st.expander(
                        f"Alert `{a.source_event_id}` ({a.source}) - {a.event_type} | Severity: {a.severity} | Conf: {a.confidence:.2f}"
                    ):
                        a_col1, a_col2 = st.columns(2)
                        with a_col1:
                            st.write(f"**Title:** {a.title}")
                            st.write(f"**Host:** {a.host_entity or 'N/A'}")
                            st.write(f"**User:** {a.user_entity or 'N/A'}")
                            st.write(f"**Asset Criticality:** {a.asset_criticality}")
                        with a_col2:
                            st.write(f"**Source IP:** {a.source_ip or 'N/A'}")
                            st.write(f"**Destination IP:** {a.destination_ip or 'N/A'}:{a.destination_port or ''}")
                            st.write(f"**Indicators:** {', '.join(a.indicators or [])}")
                            st.write(f"**Deduplication Hash:** `{a.deduplication_hash[:16]}...`")
                        
                        st.markdown("**Forensic Untampered Raw Payload:**")
                        st.json(a.raw_payload)

                # Status Transition Audit History
                with st.expander("📜 Status History & Audit Log"):
                    if selected_incident.status_history:
                        h_records = [
                            {
                                "Timestamp (UTC)": h.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                                "Old Status": h.old_status,
                                "New Status": h.new_status,
                                "Analyst": h.changed_by,
                                "Notes": h.notes,
                            }
                            for h in selected_incident.status_history
                        ]
                        st.table(pd.DataFrame(h_records))
                    else:
                        st.caption("No history transitions recorded.")

elif menu == "📥 Alert Ingestion Sandbox":
    st.title("Alert Ingestion Sandbox")
    st.caption("Ingest JSON or CSV alerts, validate schemas, identify duplicates, and inspect processing errors.")

    ingest_tab1, ingest_tab2 = st.tabs(["JSON Ingestion", "CSV Batch Upload"])

    with ingest_tab1:
        st.markdown("#### Paste JSON Alert or Batch Array")
        sample_placeholder = json.dumps([
            {
                "source_event_id": f"TEST-{int(datetime.now().timestamp())}",
                "source": "Custom_EDR",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "event_type": "SuspiciousProcess",
                "severity": "HIGH",
                "confidence": 0.85,
                "user": "jdoe",
                "host": "srv-api-01.corp",
                "asset_criticality": "HIGH",
                "indicators": ["malware.exe", "198.51.100.99"],
                "title": "Unsigned binary executed from Temp folder",
                "description": "Suspicious payload executed without valid digital signature.",
            }
        ], indent=2)

        json_text = st.text_area("JSON Input", value=sample_placeholder, height=220)
        if st.button("Process & Ingest JSON", type="primary"):
            try:
                parsed_json = json.loads(json_text)
                alerts, errors = parse_and_normalize_json(parsed_json)
                with get_db_session() as db:
                    saved, dupes = AlertService.save_alerts_batch(db, alerts)
                    created, updated = CorrelationEngine.correlate_batch(db, saved)
                
                st.success(
                    f"Processed {len(alerts) + len(errors)} records: {len(saved)} Accepted, {dupes} Duplicates, {len(errors)} Rejected."
                )
                if created:
                    st.info(f"Created Incident(s): {', '.join(created)}")
                if updated:
                    st.info(f"Updated Incident(s): {', '.join(updated)}")

                if errors:
                    st.error("Validation Errors Encountered:")
                    err_rows = [{"Index": e.item_index, "Errors": "; ".join(e.errors), "Raw Input": str(e.raw_data)} for e in errors]
                    st.table(pd.DataFrame(err_rows))

            except Exception as e:
                st.error(f"Failed to parse JSON: {str(e)}")

    with ingest_tab2:
        st.markdown("#### Upload CSV or Paste CSV Content")
        uploaded_file = st.file_uploader("Upload CSV File", type=["csv"])
        csv_placeholder = "source_event_id,source,event_type,severity,confidence,host,user\nCSV-901,Firewall,PortScan,MEDIUM,0.7,edge-gw,attacker\nCSV-902,Firewall,PortScan,MEDIUM,0.7,edge-gw,attacker"
        raw_csv_text = st.text_area("Or Paste Raw CSV Text", value=csv_placeholder, height=120)

        if st.button("Process & Ingest CSV", type="primary"):
            content = None
            if uploaded_file is not None:
                content = uploaded_file.read()
            elif raw_csv_text.strip():
                content = raw_csv_text.encode("utf-8")

            if content:
                alerts, errors = parse_and_normalize_csv(content)
                with get_db_session() as db:
                    saved, dupes = AlertService.save_alerts_batch(db, alerts)
                    created, updated = CorrelationEngine.correlate_batch(db, saved)
                
                st.success(
                    f"Processed {len(alerts) + len(errors)} CSV rows: {len(saved)} Accepted, {dupes} Duplicates, {len(errors)} Rejected."
                )
                if created:
                    st.info(f"Created Incident(s): {', '.join(created)}")
                if updated:
                    st.info(f"Updated Incident(s): {', '.join(updated)}")

                if errors:
                    st.error("Row Validation Errors Encountered:")
                    err_rows = [{"Row": e.item_index, "Errors": "; ".join(e.errors), "Raw Data": str(e.raw_data)} for e in errors]
                    st.table(pd.DataFrame(err_rows))
            else:
                st.warning("Please upload a CSV file or paste CSV text.")

elif menu == "📋 Telemetry & Raw Alerts":
    st.title("Raw Alert Telemetry")
    st.caption("Forensic audit log of all validated and persisted security alerts.")

    with get_db_session() as db:
        alerts_list = list(db.execute(select(AlertModel).order_by(desc(AlertModel.timestamp))).scalars().all())

    if not alerts_list:
        st.info("No telemetry alerts stored.")
    else:
        df_alerts = pd.DataFrame([
            {
                "Alert ID": a.id[:8] + "...",
                "Source Event ID": a.source_event_id,
                "Source": a.source,
                "Timestamp (UTC)": a.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                "Type": a.event_type,
                "Severity": a.severity,
                "Confidence": a.confidence,
                "Host": a.host_entity or "N/A",
                "User": a.user_entity or "N/A",
                "Indicators": ", ".join(a.indicators or []),
                "Title": a.title,
            }
            for a in alerts_list
        ])
        st.dataframe(df_alerts, use_container_width=True, hide_index=True)

elif menu == "⚙️ Engine Configuration":
    st.title("Engine Configuration & Scoring Parameters")
    st.caption("Inspect active deterministic scoring weights, thresholds, and correlation parameters.")

    cfg_col1, cfg_col2 = st.columns(2)
    with cfg_col1:
        st.markdown("#### Correlation Parameters")
        st.write(f"**Sliding Time Window:** {settings.CORRELATION_WINDOW_MINUTES} minutes")
        st.write(f"**Max Ingestion Batch Size:** {settings.MAX_BATCH_SIZE}")
        st.write(f"**Database URL:** `{settings.DATABASE_URL}`")

        st.markdown("#### Priority Classification Thresholds")
        st.write(f"- **CRITICAL:** Score >= {settings.CRITICAL_THRESHOLD}")
        st.write(f"- **HIGH:** Score >= {settings.HIGH_THRESHOLD}")
        st.write(f"- **MEDIUM:** Score >= {settings.MEDIUM_THRESHOLD}")
        st.write(f"- **LOW:** Score >= {settings.LOW_THRESHOLD}")
        st.write("- **INFORMATIONAL:** Score < 20.0")

    with cfg_col2:
        st.markdown("#### Scoring Factor Weights")
        st.write("**Base Severity Points:**")
        st.json(settings.SEVERITY_POINTS)
        st.write("**Asset Criticality Points:**")
        st.json(settings.ASSET_CRITICALITY_POINTS)
        st.write(f"**Confidence Multiplier Weight:** {settings.CONFIDENCE_WEIGHT}")
        st.write(f"**Multi-Stage Attack Chain Bonus:** +{settings.MULTI_STAGE_BONUS_PER_STAGE} pts per stage (Max: {settings.MAX_MULTI_STAGE_BONUS})")
        st.write(f"**Privileged Account Bonus:** +{settings.SENSITIVE_ACCOUNT_BONUS} pts")
        st.write(f"**Threat Indicator Bonus:** +{settings.INDICATOR_THREAT_BONUS} pts")
