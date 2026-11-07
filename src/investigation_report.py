
from pathlib import Path
from datetime import datetime, timezone

from dlp_engine import detect_personal_cloud_uploads

from ueba_engine import (
    analyse_activity_hours,
    detect_after_hours_activity,
    detect_bulk_downloads
)

from investigation_engine import (
    load_activity_logs,
    get_employee_activity
)

from forensic_evidence import (
    collect_file_evidence,
    compare_file_hashes
)

from incident_correlation import correlate_incident_events
from risk_scoring import calculate_incident_risk


def generate_investigation_report(employee_id):

    # Locate project directory
    BASE_DIR = Path(__file__).resolve().parent.parent
    OUTPUT_DIR = BASE_DIR / "outputs"
    OUTPUT_DIR.mkdir(exist_ok=True)

    # Load employee activity logs
    logs = load_activity_logs()

    # Run DLP detection
    dlp_alerts = detect_personal_cloud_uploads(logs)

    # Run UEBA detection
    analysed_logs = analyse_activity_hours(logs)

    after_hours_alerts = detect_after_hours_activity(analysed_logs)
    bulk_download_alerts = detect_bulk_downloads(analysed_logs)

    # Filter alerts for the employee under investigation
    employee_dlp = dlp_alerts[
        dlp_alerts["user_id"] == employee_id
    ].copy()

    employee_after_hours = after_hours_alerts[
        after_hours_alerts["user_id"] == employee_id
    ].copy()

    employee_bulk_downloads = bulk_download_alerts[
        bulk_download_alerts["user_id"] == employee_id
    ].copy()

    # Retrieve employee activity timeline
    employee_events = get_employee_activity(logs, employee_id)

    # Correlate related events into investigation groups
    correlation_result = correlate_incident_events(
        logs,
        employee_id
    )

    correlated_incidents = correlation_result["incidents"]

    # Calculate risk priority for each correlated incident
    for incident in correlated_incidents:

        incident["risk_assessment"] = calculate_incident_risk(
            incident
        )

    # Collect independent forensic evidence
    endpoint_folder = BASE_DIR / "data" / "endpoint_evidence"
    cloud_folder = BASE_DIR / "data" / "cloud_evidence"

    endpoint_evidence = collect_file_evidence(
        endpoint_folder,
        "endpoint"
    )

    cloud_evidence = collect_file_evidence(
        cloud_folder,
        "cloud"
    )

    forensic_comparison = compare_file_hashes(
        endpoint_evidence,
        cloud_evidence
    )

    # Calculate investigation indicators
    matching_files = forensic_comparison[
        forensic_comparison["comparison_result"] == "HASH MATCH"
    ]

    # Generate report
    report_time = datetime.now(timezone.utc).isoformat()

    report = []

    report.append("=" * 65)
    report.append("DIGITAL INVESTIGATION REPORT")
    report.append("=" * 65)

    report.append(f"Employee ID: {employee_id}")
    report.append(f"Report generated (UTC): {report_time}")

    # --------------------------------------------------
    # 1. DLP FINDINGS
    # --------------------------------------------------

    report.append("\n1. DLP FINDINGS")
    report.append("-" * 65)
    report.append(f"DLP alerts: {len(employee_dlp)}")

    # --------------------------------------------------
    # 2. UEBA FINDINGS
    # --------------------------------------------------

    report.append("\n2. UEBA FINDINGS")
    report.append("-" * 65)

    report.append(
        f"After-hours events: {len(employee_after_hours)}"
    )

    report.append(
        f"Bulk-download events: {len(employee_bulk_downloads)}"
    )

    # --------------------------------------------------
    # 3. EMPLOYEE ACTIVITY
    # --------------------------------------------------

    report.append("\n3. EMPLOYEE ACTIVITY")
    report.append("-" * 65)

    report.append(
        f"Total recorded events: {len(employee_events)}"
    )

    if not employee_events.empty:

        report.append(
            employee_events[
                [
                    "timestamp_utc",
                    "event_type",
                    "sensitivity",
                    "file_count",
                    "bytes_mb",
                    "destination"
                ]
            ].to_string(index=False)
        )

    else:
        report.append("No employee activity records found.")

    # --------------------------------------------------
    # 4. CORRELATED INCIDENT ANALYSIS
    # --------------------------------------------------

    report.append("\n4. CORRELATED INCIDENT ANALYSIS")
    report.append("-" * 65)

    report.append(
        f"Correlated activity groups: {len(correlated_incidents)}"
    )

    if correlated_incidents:

        for index, incident in enumerate(
            correlated_incidents,
            start=1
        ):

            report.append(f"\nIncident {index}")

            # Incident classification
            report.append(
                f"Classification: {incident['classification']}"
            )

            # Risk assessment
            risk = incident["risk_assessment"]

            report.append(
                f"Risk score: {risk['risk_score']}/100"
            )

            report.append(
                f"Risk priority: {risk['priority']}"
            )

            report.append("Risk factors:")

            if risk["reasons"]:

                for reason in risk["reasons"]:
                    report.append(f"  - {reason}")

            else:
                report.append("  - No elevated risk indicators identified.")

            # Incident details
            report.append(
                f"Events in group: {len(incident['events'])}"
            )

            report.append(
                "Confidential files downloaded: "
                f"{incident['confidential_download_files']}"
            )

            report.append(
                "External transfer observed: "
                f"{incident['evidence_flags']['external_transfer_observed']}"
            )

            report.append(
                f"Explanation: {incident['explanation']}"
            )

            # Evidence flags
            report.append("Evidence flags:")

            for flag, value in incident["evidence_flags"].items():

                report.append(
                    f"  - {flag}: {value}"
                )

            # Related events
            report.append("Related events:")

            for event in incident["events"]:

                report.append(
                    f"  - {event['timestamp_utc']} | "
                    f"{event['event_type']} | "
                    f"{event['destination']}"
                )

    else:
        report.append("No correlated activity groups were identified.")

    # --------------------------------------------------
    # 5. FORENSIC HASH COMPARISON
    # --------------------------------------------------

    report.append("\n5. FORENSIC HASH COMPARISON")
    report.append("-" * 65)

    report.append(
        f"Endpoint files: {len(endpoint_evidence)}"
    )

    report.append(
        f"Cloud files: {len(cloud_evidence)}"
    )

    report.append(
        f"Matching file hashes: {len(matching_files)}"
    )

    # --------------------------------------------------
    # 6. INVESTIGATION LIMITATIONS
    # --------------------------------------------------

    report.append("\n6. INVESTIGATION LIMITATIONS")
    report.append("-" * 65)

    report.append(
        "Matching hashes establish identical file contents, "
        "not transfer direction or employee attribution."
    )

    report.append(
        "Cloud audit logs, endpoint telemetry, authentication "
        "records and authorisation context require further review."
    )

    report.append(
        "HR context must be obtained only through authorised processes."
    )

    report.append(
        "Temporal correlation does not establish file-level transfer linkage."
    )

    report.append(
        "Risk scores prioritise analyst review and do not establish "
        "malicious intent or employee culpability."
    )

    # --------------------------------------------------
    # 7. INVESTIGATION ASSESSMENT
    # --------------------------------------------------

    report.append("\n7. INVESTIGATION ASSESSMENT")
    report.append("-" * 65)

    report.append(
        "Multiple security indicators require further investigation."
    )

    report.append(
        "No conclusion about employee intent or culpability is made."
    )

    # --------------------------------------------------
    # REPORT FOOTER
    # --------------------------------------------------

    report.append("\n" + "=" * 65)
    report.append("END OF REPORT")
    report.append("=" * 65)

    # Save report
    report_text = "\n".join(report)

    report_file = (
        OUTPUT_DIR / f"{employee_id}_investigation_report.txt"
    )

    report_file.write_text(
        report_text,
        encoding="utf-8"
    )

    print(report_text)

    print(
        f"\nReport saved to: {report_file}"
    )


if __name__ == "__main__":

    generate_investigation_report("EMP004")
