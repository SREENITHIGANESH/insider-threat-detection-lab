
import pandas as pd


# ==================================================
# 1. ANALYSE ACTIVITY HOURS
# ==================================================

def analyse_activity_hours(logs):
    """
    Convert UTC timestamps and extract the activity hour.

    Returns a copy of the original DataFrame with an
    additional activity_hour column.
    """

    analysed_logs = logs.copy()

    analysed_logs["timestamp_utc"] = pd.to_datetime(
        analysed_logs["timestamp_utc"],
        utc=True,
        errors="coerce",
    )

    analysed_logs["activity_hour"] = (
        analysed_logs["timestamp_utc"].dt.hour
    )

    return analysed_logs


# ==================================================
# 2. DETECT AFTER-HOURS ACTIVITY
# ==================================================

def detect_after_hours_activity(logs):
    """
    Identify activity occurring outside the illustrative
    UTC working-hour window.

    Working hours: 09:00 to 17:59 UTC.
    After-hours: before 09:00 or from 18:00 onwards.

    These thresholds are illustrative and should be
    replaced with employee-specific schedules in a
    production environment.
    """

    if logs.empty:
        return []

    analysed_logs = analyse_activity_hours(logs)

    after_hours_logs = analysed_logs[
        (analysed_logs["activity_hour"] < 9)
        | (analysed_logs["activity_hour"] >= 18)
    ].copy()

    alerts = []

    for index, (_, event) in enumerate(after_hours_logs.iterrows()):

        alerts.append(
            {
                "alert_id": f"UEBA-AH-{index + 1:03d}",
                "alert_type": "After-hours Activity",
                "severity": "MEDIUM",
                "user_id": event["user_id"],
                "timestamp_utc": event["timestamp_utc"],
                "activity_hour": event["activity_hour"],
                "event_type": event["event_type"],
                "device_id": event["device_id"],
                "description": (
                    f"User {event['user_id']} performed "
                    f"{event['event_type']} at "
                    f"{event['timestamp_utc']} UTC, "
                    "outside the illustrative working-hour window."
                ),
            }
        )

    return alerts


# ==================================================
# 3. DETECT UNUSUAL BULK DOWNLOADS
# ==================================================

def detect_bulk_downloads(logs, threshold=100):
    """
    Identify file download events exceeding the configured
    file-count threshold.

    Default threshold: more than 100 files.

    This is a detection heuristic, not proof of malicious
    activity or unauthorised access.
    """

    if logs.empty:
        return []

    required_columns = [
        "user_id",
        "event_type",
        "file_count",
        "timestamp_utc",
        "device_id",
    ]

    missing_columns = [
        column
        for column in required_columns
        if column not in logs.columns
    ]

    if missing_columns:
        raise ValueError(
            f"Missing required columns: {missing_columns}"
        )

    download_logs = logs[
        (logs["event_type"] == "file_download")
        & (pd.to_numeric(logs["file_count"], errors="coerce") > threshold)
    ].copy()

    alerts = []

    for index, (_, event) in enumerate(download_logs.iterrows()):

        alerts.append(
            {
                "alert_id": f"UEBA-BD-{index + 1:03d}",
                "alert_type": "Unusual Bulk Download",
                "severity": "HIGH",
                "user_id": event["user_id"],
                "timestamp_utc": event["timestamp_utc"],
                "device_id": event["device_id"],
                "file_count": event["file_count"],
                "bytes_mb": event.get("bytes_mb", 0),
                "sensitivity": event.get("sensitivity", "Unknown"),
                "description": (
                    f"User {event['user_id']} downloaded "
                    f"{event['file_count']} files, exceeding "
                    f"the configured threshold of {threshold} files."
                ),
            }
        )

    return alerts
