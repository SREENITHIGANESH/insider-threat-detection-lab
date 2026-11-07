
def calculate_incident_risk(incident):
    """
    Calculate a transparent risk-priority score for a correlated
    activity group.

    This score prioritises analyst review. It does not establish
    malicious intent or employee culpability.
    """

    score = 0
    reasons = []

    flags = incident["evidence_flags"]

    confidential_files = incident["confidential_download_files"]

    # 1. Confidential data access
    if confidential_files >= 100:

        score += 30
        reasons.append(
            "High-volume confidential data download"
        )

    elif confidential_files > 0:

        score += 15
        reasons.append(
            "Confidential data download observed"
        )

    # 2. External destination
    if flags.get("personal_cloud_upload", False):

        score += 30
        reasons.append(
            "Personal cloud destination observed"
        )

    if flags.get("external_email", False):

        score += 25
        reasons.append(
            "External email destination observed"
        )

    # 3. After-hours activity within this incident group
    after_hours_activity = flags.get(
        "after_hours_activity",
        incident.get("after_hours_activity", False)
    )

    if after_hours_activity:

        score += 10

        reasons.append(
            "After-hours activity observed within this incident group"
        )

    # 4. Evidence limitation
    if (
        flags.get("external_transfer_observed", False)
        and confidential_files > 0
    ):

        reasons.append(
            "External transfer and confidential access are "
            "temporally correlated; file-level linkage is unverified"
        )

    # Cap the score
    score = min(score, 100)

    # Assign priority
    if score >= 70:
        priority = "CRITICAL"

    elif score >= 45:
        priority = "HIGH"

    elif score >= 20:
        priority = "MEDIUM"

    else:
        priority = "LOW"

    return {
        "risk_score": score,
        "priority": priority,
        "reasons": reasons
    }
