
import sys
from pathlib import Path

import pandas as pd
import streamlit as st


# ==================================================
# 1. PROJECT PATHS AND IMPORTS
# ==================================================

BASE_DIR = Path(__file__).resolve().parent
SRC_DIR = BASE_DIR / "src"

sys.path.append(str(SRC_DIR))

from investigation_engine import (
    load_activity_logs,
    get_employee_activity,
)

from dlp_engine import detect_personal_cloud_uploads

from ueba_engine import (
    detect_after_hours_activity,
    detect_bulk_downloads,
)

from incident_correlation import correlate_incident_events

from risk_scoring import calculate_incident_risk


# ==================================================
# 2. HELPER FUNCTIONS
# ==================================================

def to_dataframe(data):
    """Convert detection output into a DataFrame safely."""

    if isinstance(data, pd.DataFrame):
        return data.copy()

    if data is None:
        return pd.DataFrame()

    return pd.DataFrame(data)


# ==================================================
# 3. PAGE CONFIGURATION
# ==================================================

st.set_page_config(
    page_title="Insider Threat Detection Lab",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ Insider Threat Detection & Digital Investigation Lab")

st.caption(
    "A Python-based investigation dashboard combining "
    "DLP detection, UEBA analytics, incident correlation, "
    "risk scoring, and forensic evidence review."
)

st.divider()


# ==================================================
# 4. CUSTOM STYLING
# ==================================================

st.markdown(
    """
    <style>
    .block-container {
        padding-top: 2rem;
        padding-bottom: 2rem;
    }

    div[data-testid="stMetric"] {
        background-color: rgba(128, 128, 128, 0.08);
        border: 1px solid rgba(128, 128, 128, 0.2);
        padding: 15px;
        border-radius: 10px;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


# ==================================================
# 5. LOAD ACTIVITY DATA
# ==================================================

@st.cache_data
def load_data():
    return load_activity_logs()


try:
    logs = load_data()

except Exception as error:
    st.error(f"Unable to load activity logs: {error}")
    st.stop()


if logs.empty:
    st.warning("No activity records found.")
    st.stop()


# ==================================================
# 6. SIDEBAR - EMPLOYEE SELECTION
# ==================================================

st.sidebar.header("Investigation Controls")

employees = sorted(logs["user_id"].dropna().unique())

# Default to EMP004 if it exists.
default_employee_index = (
    employees.index("EMP004")
    if "EMP004" in employees
    else 0
)

selected_employee = st.sidebar.selectbox(
    "Select Employee",
    employees,
    index=default_employee_index,
)

st.sidebar.caption(
    "Select an employee to review activity and investigation findings."
)


# ==================================================
# 7. EMPLOYEE ACTIVITY
# ==================================================

employee_logs = get_employee_activity(
    logs,
    selected_employee,
)


# ==================================================
# 8. DLP DETECTION
# ==================================================

dlp_alerts = detect_personal_cloud_uploads(employee_logs)

dlp_df = to_dataframe(dlp_alerts)


# ==================================================
# 9. UEBA DETECTION
# ==================================================

after_hours_alerts = detect_after_hours_activity(employee_logs)

after_hours_df = to_dataframe(after_hours_alerts)

bulk_download_alerts = detect_bulk_downloads(employee_logs)

bulk_df = to_dataframe(bulk_download_alerts)


# ==================================================
# 10. INCIDENT CORRELATION
# ==================================================

correlation_result = correlate_incident_events(
    employee_logs,
    selected_employee,
)

correlated_groups = correlation_result.get("incidents", [])


# ==================================================
# 11. RISK SCORING
# ==================================================

incidents = []

for group in correlated_groups:

    risk_assessment = calculate_incident_risk(group)

    incident = group.copy()

    incident["risk_assessment"] = risk_assessment

    incidents.append(incident)


# ==================================================
# 12. INVESTIGATION OVERVIEW
# ==================================================

st.subheader("Investigation Overview")

total_events = len(employee_logs)

total_dlp_alerts = len(dlp_df)

total_after_hours = len(after_hours_df)

total_groups = len(incidents)

high_critical_groups = sum(
    1
    for incident in incidents
    if incident["risk_assessment"]["priority"] in [
        "HIGH",
        "CRITICAL",
    ]
)

col1, col2, col3, col4, col5 = st.columns(5)

col1.metric("Activity Events", total_events)

col2.metric("DLP Alerts", total_dlp_alerts)

col3.metric("After-hours Events", total_after_hours)

col4.metric("Correlated Groups", total_groups)

col5.metric("High / Critical Groups", high_critical_groups)


st.divider()


# ==================================================
# 13. CORRELATED ACTIVITY RISK OVERVIEW
# ==================================================

st.subheader("Correlated Activity Risk Overview")

if incidents:

    risk_data = []

    for index, incident in enumerate(incidents):

        risk = incident["risk_assessment"]

        risk_data.append(
            {
                "Activity Group": f"Incident {index + 1}",
                "Classification": incident["classification"],
                "Risk Score": risk["risk_score"],
                "Priority": risk["priority"],
            }
        )

    risk_df = pd.DataFrame(risk_data)

    st.dataframe(
        risk_df,
        use_container_width=True,
        hide_index=True,
    )

    st.bar_chart(
        risk_df.set_index("Activity Group")["Risk Score"],
        y_label="Risk Score",
    )

else:

    st.info("No correlated activity groups identified.")


st.divider()


# ==================================================
# 14. INVESTIGATION DETAILS
# ==================================================

st.subheader("Investigation Details")

if incidents:

    incident_options = [
        (
            f"Incident {index + 1} - "
            f"{incident['classification']}"
        )
        for index, incident in enumerate(incidents)
    ]

    # Automatically select the highest-risk group.

    highest_risk_index = max(
        range(len(incidents)),
        key=lambda index: incidents[index]["risk_assessment"]["risk_score"],
    )

    selected_incident_index = st.selectbox(
        "Select a correlated activity group",
        range(len(incidents)),
        index=highest_risk_index,
        format_func=lambda index: incident_options[index],
    )

    selected_incident = incidents[selected_incident_index]

    risk_assessment = selected_incident["risk_assessment"]

    risk_score = risk_assessment["risk_score"]

    priority = risk_assessment["priority"]


    # ----------------------------------------------
    # RISK ASSESSMENT
    # ----------------------------------------------

    st.markdown("### Risk Assessment")

    risk_col1, risk_col2, risk_col3 = st.columns(3)

    risk_col1.metric(
        "Risk Score",
        f"{risk_score}/100",
    )

    risk_col2.metric(
        "Priority",
        priority,
    )

    risk_col3.metric(
        "Confidential Files",
        selected_incident["confidential_download_files"],
    )

    st.progress(
        min(max(risk_score / 100, 0.0), 1.0)
    )


    # ----------------------------------------------
    # RISK FACTORS
    # ----------------------------------------------

    st.markdown("### Risk Factors")

    reasons = risk_assessment.get("reasons", [])

    if reasons:

        for reason in reasons:
            st.write(f"• {reason}")

    else:

        st.write("No additional risk factors recorded.")


    # ----------------------------------------------
    # INVESTIGATION EXPLANATION
    # ----------------------------------------------

    st.markdown("### Investigation Explanation")

    st.write(selected_incident["explanation"])


    # ----------------------------------------------
    # EVIDENCE FLAGS
    # ----------------------------------------------

    st.markdown("### Evidence Flags")

    evidence_flags = selected_incident["evidence_flags"]

    for flag, value in evidence_flags.items():

        st.write(
            f"• **{flag.replace('_', ' ').title()}:** {value}"
        )


    # ----------------------------------------------
    # AUTHORIZATION STATUS
    # ----------------------------------------------

    st.markdown("### Authorization Status")

    st.write(
        selected_incident["authorization_status"]
    )

    st.caption(
        "Authorization status must be independently verified "
        "through approved access records and business justification."
    )


    # ----------------------------------------------
    # CORRELATED EVENT TIMELINE
    # ----------------------------------------------

    st.markdown("### Correlated Event Timeline")

    event_details = selected_incident["events"]

    if event_details:

        event_df = pd.DataFrame(event_details)

        if "timestamp_utc" in event_df.columns:

            event_df["timestamp_utc"] = pd.to_datetime(
                event_df["timestamp_utc"],
                utc=True,
                errors="coerce",
            )

            event_df = event_df.sort_values("timestamp_utc")

        st.dataframe(
            event_df,
            use_container_width=True,
            hide_index=True,
        )

    else:

        st.info("No event-level details available.")


    st.caption(
        "Risk scores are prioritisation heuristics for analyst review. "
        "They do not establish malicious intent or prove data exfiltration."
    )

else:

    st.info("No correlated activity groups available for investigation.")


st.divider()


# ==================================================
# 15. EMPLOYEE ACTIVITY TIMELINE
# ==================================================

st.subheader("Employee Activity Timeline")

if not employee_logs.empty:

    timeline_df = employee_logs.copy()

    if "timestamp_utc" in timeline_df.columns:

        timeline_df["timestamp_utc"] = pd.to_datetime(
            timeline_df["timestamp_utc"],
            utc=True,
            errors="coerce",
        )

        timeline_df = timeline_df.sort_values("timestamp_utc")

    st.dataframe(
        timeline_df,
        use_container_width=True,
        hide_index=True,
    )

else:

    st.info("No employee activity records available.")


st.divider()


# ==================================================
# 16. DLP FINDINGS
# ==================================================

st.subheader("Data Loss Prevention (DLP) Findings")

if not dlp_df.empty:

    st.dataframe(
        dlp_df,
        use_container_width=True,
        hide_index=True,
    )

else:

    st.success("No DLP alerts identified for this employee.")


st.divider()


# ==================================================
# 17. UEBA FINDINGS
# ==================================================

st.subheader("User and Entity Behaviour Analytics (UEBA)")


# After-hours activity

st.markdown("### After-hours Activity")

if not after_hours_df.empty:

    st.dataframe(
        after_hours_df,
        use_container_width=True,
        hide_index=True,
    )

else:

    st.info("No after-hours activity alerts identified.")


# Unusual bulk downloads

st.markdown("### Unusual Bulk Downloads")

if not bulk_df.empty:

    st.dataframe(
        bulk_df,
        use_container_width=True,
        hide_index=True,
    )

else:

    st.info("No unusual bulk download alerts identified.")


# ==================================================
# 18. FOOTER
# ==================================================

st.divider()

st.caption(
    """
    Insider Threat Detection & Digital Investigation Lab

    Dataset: Synthetic activity logs.

    This project demonstrates detection logic, behavioural analytics,
    temporal correlation, risk-based prioritisation, and evidence review.

    All findings require analyst validation. Temporal correlation does
    not prove file-level transfer, and matching file hashes do not
    establish transfer direction or user intent.
    """
)
