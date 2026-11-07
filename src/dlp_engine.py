
import pandas as pd


def detect_personal_cloud_uploads(logs):

    # Rule 001: Confidential data uploaded to personal cloud
    cloud_alerts = logs[
        (logs["event_type"] == "cloud_upload") &
        (logs["sensitivity"] == "confidential") &
        (logs["destination"] == "personal_cloud")
    ].copy()

    # Rule 002: Confidential data sent to external email
    email_alerts = logs[
        (logs["event_type"] == "email_send") &
        (logs["sensitivity"] == "confidential") &
        (logs["destination"] == "external_email")
    ].copy()

    # Combine alerts
    alerts = pd.concat(
        [cloud_alerts, email_alerts],
        ignore_index=True
    )

    # Assign alert details
    alerts["alert_id"] = [
        f"DLP-{i:04d}" for i in range(1, len(alerts) + 1)
    ]

    alerts["alert_type"] = "Potential Data Loss"
    alerts["severity"] = "HIGH"

    return alerts


if __name__ == "__main__":

    from pathlib import Path

    BASE_DIR = Path(__file__).resolve().parent.parent
    LOG_FILE = BASE_DIR / "data" / "activity_logs.csv"

    logs = pd.read_csv(LOG_FILE)

    alerts = detect_personal_cloud_uploads(logs)

    print("\n===== DLP DETECTION ENGINE =====")
    print(f"Total DLP alerts: {len(alerts)}")

    if not alerts.empty:

        print("\nDETECTED SECURITY ALERTS:")

        print(
            alerts[
                [
                    "alert_id",
                    "user_id",
                    "event_type",
                    "sensitivity",
                    "bytes_mb",
                    "destination",
                    "severity"
                ]
            ].to_string(index=False)
        )

    else:
        print("No matching DLP alerts found.")

    print("\n===== DLP ANALYSIS COMPLETED =====")
