import pandas as pd
from pathlib import Path

def load_activity_logs():

    # Locate the project root directory
    BASE_DIR = Path(__file__).resolve().parent.parent

    # Define the activity log file path
    LOG_FILE = BASE_DIR / "data" / "activity_logs.csv"

    # Load activity logs
    logs = pd.read_csv(LOG_FILE)

    return logs

def get_employee_activity(logs, employee_id):

    # Filter events belonging to the selected employee
    employee_events = logs[
        logs["user_id"] == employee_id
    ].copy()

    # Convert timestamps into datetime format
    employee_events["timestamp_utc"] = pd.to_datetime(
        employee_events["timestamp_utc"],
        format="mixed",
        utc=True
    )

    # Arrange events chronologically
    employee_events = employee_events.sort_values(
        by="timestamp_utc"
    )

    return employee_events

if __name__ == "__main__":

    # Load employee activity logs
    logs = load_activity_logs()

    # Select employee for investigation
    employee_id = "EMP004"

    # Retrieve employee activity
    employee_events = get_employee_activity(logs, employee_id)

    # Display investigation timeline
    print("\n===== EMPLOYEE INVESTIGATION TIMELINE =====")

    print(f"Employee under investigation: {employee_id}")
    print(f"Total recorded events: {len(employee_events)}")

    print(
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