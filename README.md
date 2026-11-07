
# Insider Threat Detection & Digital Investigation Lab

A Python-based insider threat detection and digital investigation prototype combining Data Loss Prevention (DLP), User and Entity Behaviour Analytics (UEBA), incident correlation, risk scoring, and forensic evidence analysis.

## Project Overview

This project demonstrates how employee activity logs can be analysed to identify potentially suspicious patterns, correlate related events, prioritise investigations, and support evidence review.

The dashboard is built using Python, Pandas, and Streamlit. It uses synthetic activity logs and locally generated evidence samples.

## Key Features

- **DLP Detection:** Identifies confidential data activity involving external destinations such as personal cloud storage and external email.
- **UEBA Analytics:** Detects activity outside illustrative working hours and unusual bulk downloads.
- **Incident Correlation:** Groups related employee activities by device and time window.
- **Risk Scoring:** Assigns transparent risk scores and investigation priorities based on observed indicators.
- **Digital Investigation:** Displays correlated event timelines, investigation explanations, and evidence flags.
- **Forensic Evidence Analysis:** Uses SHA-256 hashes to compare endpoint and cloud evidence samples.
- **Interactive Dashboard:** Provides an employee-level investigation interface using Streamlit.

## Technology Stack

- Python
- Pandas
- Streamlit
- SHA-256 hashing
- Git and GitHub

## Project Structure

```text
insider-threat-detection-lab/
│
├── data/
│   ├── activity_logs.csv
│   ├── cloud_evidence/
│   └── endpoint_evidence/
│
├── outputs/
│   └── EMP004_investigation_report.txt
│
├── src/
│   ├── dlp_engine.py
│   ├── forensic_evidence.py
│   ├── generate_data.py
│   ├── incident_correlation.py
│   ├── investigation_engine.py
│   ├── investigation_report.py
│   ├── risk_scoring.py
│   └── ueba_engine.py
│
├── dashboard.py
├── main.py
├── requirements.txt
└── README.md
```

## Installation and Setup

### 1. Clone the repository

```bash
git clone https://github.com/SREENITHIGANESH/insider-threat-detection-lab.git
cd insider-threat-detection-lab
```

### 2. Create a virtual environment

```bash
python -m venv .venv
```

### 3. Activate the environment

Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

### 4. Install dependencies

```bash
pip install -r requirements.txt
```

### 5. Launch the dashboard

```bash
streamlit run dashboard.py
```

## Investigation Workflow

1. Load employee activity records.
2. Analyse activity using DLP and UEBA detection rules.
3. Correlate events by employee, device, and time window.
4. Calculate risk scores for correlated activity groups.
5. Review investigation explanations, evidence flags, and event timelines.
6. Compare endpoint and cloud evidence using SHA-256 hashes.

## Example Investigation

The synthetic dataset includes an illustrative employee activity sequence involving:

- After-hours login activity.
- A bulk download of confidential files.
- A subsequent personal cloud upload event.

The correlated activity group is classified as `POTENTIAL_DATA_EXFILTRATION` and assigned a prototype risk score of 70/100 (CRITICAL).

This classification indicates that the activity requires analyst review. It does not establish malicious intent or prove that the downloaded files were transferred to the external destination.

## Important Limitations

- All activity records are synthetic and intended for demonstration.
- Working-hour thresholds are illustrative UTC-based rules.
- Risk scores are heuristic prioritisation values, not validated probabilities.
- Temporal correlation does not establish file-level transfer or causation.
- Matching SHA-256 hashes establish content identity, not transfer direction, timing, or user attribution.
- Authorisation must be independently verified.
- The prototype does not connect to production DLP, EDR, SIEM, HR, or cloud audit systems.

## Purpose

This project was developed to explore practical applications of cybersecurity analytics, insider threat detection, digital investigation workflows, and forensic evidence review.
