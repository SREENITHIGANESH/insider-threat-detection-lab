
import csv
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Project directory
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)

OUTPUT_FILE = DATA_DIR / "activity_logs.csv"

# Reproducible synthetic data
random.seed(42)

# Employee information
departments = {
    "EMP001": "Finance",
    "EMP002": "HR",
    "EMP003": "IT",
    "EMP004": "Research",
    "EMP005": "Research",
    "EMP006": "Legal",
    "EMP007": "Finance",
    "EMP008": "Research",
    "EMP009": "IT",
    "EMP010": "HR"
}

users = list(departments.keys())

now = datetime.now(timezone.utc)
events = []


# Function to create a security event
def add_event(user_id, timestamp, event_type,
              sensitivity="none",
              file_count=0,
              bytes_mb=0,
              destination="none",
              scenario="normal"):

    events.append({
        "event_id": f"EVT-{len(events)+1:05d}",
        "timestamp_utc": timestamp.isoformat(),
        "user_id": user_id,
        "department": departments[user_id],
        "device_id": f"DEVICE-{user_id}",
        "event_type": event_type,
        "sensitivity": sensitivity,
        "file_count": file_count,
        "bytes_mb": bytes_mb,
        "destination": destination,
        "success": True,
        "scenario_label": scenario
    })


# Generate normal employee activity
event_types = [
    "login",
    "file_access",
    "file_download",
    "usb_connected",
    "cloud_upload",
    "email_send"
]

for _ in range(250):

    user = random.choice(users)

    day_offset = random.randint(0, 6)
    hour = random.randint(9, 17)
    minute = random.randint(0, 59)

    timestamp = (
        now - timedelta(days=day_offset)
    ).replace(
        hour=hour,
        minute=minute,
        second=0,
        microsecond=0
    )

    event_type = random.choice(event_types)

    sensitivity = random.choice([
        "public",
        "internal",
        "confidential"
    ])

    file_count = 0
    bytes_mb = 0
    destination = "none"

    if event_type in ["file_access", "file_download"]:
        file_count = random.randint(1, 5)
        bytes_mb = random.randint(1, 25)

    elif event_type == "usb_connected":
        destination = "approved_usb"

    elif event_type == "cloud_upload":
        destination = "approved_company_cloud"
        bytes_mb = random.randint(1, 20)

    elif event_type == "email_send":
        destination = "internal_email"

    add_event(
        user,
        timestamp,
        event_type,
        sensitivity,
        file_count,
        bytes_mb,
        destination
    )


# Simulate suspicious employee activity
suspect = "EMP004"

incident_time = (
    now - timedelta(days=1)
).replace(
    hour=23,
    minute=45,
    second=0,
    microsecond=0
)

add_event(
    suspect,
    incident_time,
    "login",
    scenario="simulated_suspicious"
)

add_event(
    suspect,
    incident_time + timedelta(minutes=5),
    "file_download",
    sensitivity="confidential",
    file_count=450,
    bytes_mb=1800,
    scenario="simulated_suspicious"
)

add_event(
    suspect,
    incident_time + timedelta(minutes=30),
    "cloud_upload",
    sensitivity="confidential",
    file_count=450,
    bytes_mb=1800,
    destination="personal_cloud",
    scenario="simulated_suspicious"
)

# Simulate confidential data sent to external email

add_event(
    "EMP005",
    now - timedelta(hours=2),
    "email_send",
    sensitivity="confidential",
    file_count=3,
    bytes_mb=25,
    destination="external_email",
    scenario="simulated_suspicious"
)

# Sort events by timestamp
events.sort(key=lambda event: event["timestamp_utc"])


# Save events as CSV
with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as file:

    writer = csv.DictWriter(
        file,
        fieldnames=events[0].keys()
    )

    writer.writeheader()
    writer.writerows(events)


print("Synthetic security logs generated successfully!")
print(f"Total events: {len(events)}")
print(f"Output file: {OUTPUT_FILE}")