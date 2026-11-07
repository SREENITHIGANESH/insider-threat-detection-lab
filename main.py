import pandas as pd
from pathlib import Path

# Locate the security log file
BASE_DIR = Path(__file__).resolve().parent
LOG_FILE = BASE_DIR / "data" / "activity_logs.csv"

# Load security events
logs = pd.read_csv(LOG_FILE)

print("\n===== INSIDER THREAT DETECTION PLATFORM =====")

print("\n1. DATASET OVERVIEW")

print(f"Total events: {len(logs)}")
print(f"Unique employees: {logs['user_id'].nunique()}")

print("\n2. EVENT DISTRIBUTION")

print(logs["event_type"].value_counts())

print("\n3. DEPARTMENT ACTIVITY")

print(logs["department"].value_counts())

print("\n4. EXTERNAL CLOUD ACTIVITY")

cloud_events = logs[
    (logs["event_type"] == "cloud_upload") &
    (logs["destination"] == "personal_cloud")
]

print(
    cloud_events[
        ["user_id", "timestamp_utc", "bytes_mb", "destination"]
    ]
)

print("\n===== ANALYSIS COMPLETED =====")