
import pandas as pd


def correlate_incident_events(logs, employee_id, window_minutes=60):
    """
    Correlate employee events and identify investigative patterns.

    After-hours activity is evaluated within each correlated group.
    This is an investigation-prioritisation tool, not a determination
    of misconduct or employee intent.
    """

    required_columns = {
        "event_id",
        "timestamp_utc",
        "user_id",
        "device_id",
        "event_type",
    }

    missing_columns = required_columns - set(logs.columns)

    if missing_columns:
        raise ValueError(
            f"Missing required columns: {sorted(missing_columns)}"
        )

    employee_logs = logs[
        logs["user_id"] == employee_id
    ].copy()

    if employee_logs.empty:
        return {
            "employee_id": employee_id,
            "incidents": [],
            "message": "No activity found for this employee."
        }

    employee_logs["timestamp_utc"] = pd.to_datetime(
        employee_logs["timestamp_utc"],
        format="mixed",
        utc=True,
        errors="coerce"
    )

    employee_logs = employee_logs.dropna(
        subset=["timestamp_utc"]
    ).sort_values("timestamp_utc")

    incidents = []

    for device_id, device_logs in employee_logs.groupby(
        "device_id",
        dropna=False
    ):

        device_logs = device_logs.sort_values("timestamp_utc")

        current_group = []
        previous_timestamp = None

        for _, event in device_logs.iterrows():

            current_timestamp = event["timestamp_utc"]

            if previous_timestamp is None:
                current_group = [event]

            else:
                difference = (
                    current_timestamp - previous_timestamp
                ).total_seconds() / 60

                if difference <= window_minutes:
                    current_group.append(event)

                else:
                    if len(current_group) > 1:
                        incidents.append(
                            classify_event_group(
                                employee_id,
                                device_id,
                                current_group
                            )
                        )

                    current_group = [event]

            previous_timestamp = current_timestamp

        if len(current_group) > 1:
            incidents.append(
                classify_event_group(
                    employee_id,
                    device_id,
                    current_group
                )
            )

    return {
        "employee_id": employee_id,
        "incidents": incidents,
        "message": "Correlation completed. Analyst review required."
    }


def classify_event_group(employee_id, device_id, events):

    total_download_files = 0
    confidential_download_files = 0

    personal_cloud_upload = False
    external_email = False
    approved_company_cloud = False
    approved_usb = False

    after_hours_event_count = 0

    event_details = []

    for event in events:

        event_type = str(event["event_type"]).lower()

        destination = str(
            event.get("destination", "")
        ).lower()

        sensitivity = str(
            event.get("sensitivity", "")
        ).lower()

        timestamp = event["timestamp_utc"]

        # Existing UEBA rule:
        # Before 09:00 UTC or at/after 18:00 UTC.
        is_after_hours = (
            timestamp.hour < 9 or timestamp.hour >= 18
        )

        if is_after_hours:
            after_hours_event_count += 1

        if event_type == "file_download":

            file_count = event.get("file_count", 0)

            if pd.notna(file_count):

                total_download_files += int(file_count)

                if sensitivity == "confidential":
                    confidential_download_files += int(file_count)

        elif event_type == "cloud_upload":

            if destination == "personal_cloud":
                personal_cloud_upload = True

            elif destination == "approved_company_cloud":
                approved_company_cloud = True

        elif event_type == "email_send":

            if destination == "external_email":
                external_email = True

        elif event_type == "usb_connected":

            if destination == "approved_usb":
                approved_usb = True

        event_details.append({
            "event_id": event["event_id"],
            "timestamp_utc": timestamp.isoformat(),
            "event_type": event_type,
            "destination": destination,
            "sensitivity": sensitivity,
            "after_hours": is_after_hours,
        })

    unusual_confidential_download = (
        confidential_download_files > 100
    )

    external_transfer_observed = (
        personal_cloud_upload or external_email
    )

    after_hours_activity = after_hours_event_count > 0

    # Classify the correlated activity group

    if confidential_download_files > 0 and external_transfer_observed:

        classification = "POTENTIAL_DATA_EXFILTRATION"

        explanation = (
            "Confidential file downloads and an external destination "
            "event were observed within the correlation window. "
            "File-level linkage and authorisation require verification."
        )

    elif unusual_confidential_download:

        classification = "UNUSUAL_DATA_ACCESS"

        explanation = (
            "More than 100 confidential files were downloaded. "
            "No external transfer was observed in this group. "
            "Review access authorisation and business justification."
        )

    elif confidential_download_files > 0:

        classification = "CONFIDENTIAL_DATA_ACCESS_REVIEW"

        explanation = (
            "Confidential files were downloaded. The volume did not "
            "meet the configured bulk-download threshold. "
            "Review access authorisation and business justification."
        )

    elif external_transfer_observed:

        classification = "EXTERNAL_TRANSFER_REVIEW"

        explanation = (
            "An external destination event was observed. "
            "Determine what data was transferred and whether "
            "the activity was authorised."
        )

    elif approved_usb:

        classification = "USB_ACTIVITY_REVIEW"

        explanation = (
            "An approved USB device connection was recorded. "
            "No file-copy evidence is available in this event."
        )

    else:

        classification = "TEMPORAL_ACTIVITY_GROUP"

        explanation = (
            "Events occurred within the configured time window. "
            "No specific suspicious sequence was established."
        )

    if confidential_download_files > 0:
        authorization_status = "NOT_VERIFIED"
    else:
        authorization_status = "NOT_ASSESSED"

    return {
        "employee_id": employee_id,
        "device_id": device_id,
        "classification": classification,
        "authorization_status": authorization_status,
        "total_download_files": total_download_files,
        "confidential_download_files": confidential_download_files,
        "event_count": len(events),
        "start_time": events[0]["timestamp_utc"].isoformat(),
        "end_time": events[-1]["timestamp_utc"].isoformat(),

        "after_hours_activity": after_hours_activity,
        "after_hours_event_count": after_hours_event_count,

        "evidence_flags": {
            "unusual_confidential_download": unusual_confidential_download,
            "personal_cloud_upload": personal_cloud_upload,
            "external_email": external_email,
            "approved_company_cloud": approved_company_cloud,
            "approved_usb_connection": approved_usb,
            "external_transfer_observed": external_transfer_observed,
            "after_hours_activity": after_hours_activity,
        },

        "explanation": explanation,
        "events": event_details,
        "requires_analyst_review": True,
    }
