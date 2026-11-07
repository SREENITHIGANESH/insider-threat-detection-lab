
import hashlib
from pathlib import Path
import pandas as pd


def calculate_file_hash(file_path):

    # Calculate SHA-256 from actual file contents
    sha256_hash = hashlib.sha256()

    with open(file_path, "rb") as file:
        for chunk in iter(lambda: file.read(4096), b""):
            sha256_hash.update(chunk)

    return sha256_hash.hexdigest()


def collect_file_evidence(folder_path, evidence_source):

    # Collect file metadata and hashes independently
    evidence = []

    for file_path in folder_path.iterdir():

        if file_path.is_file():

            file_hash = calculate_file_hash(file_path)

            evidence.append({
                "file_name": file_path.name,
                "file_path": str(file_path),
                "file_size_bytes": file_path.stat().st_size,
                "sha256": file_hash,
                "evidence_source": evidence_source
            })

    return pd.DataFrame(evidence)


def compare_file_hashes(endpoint_evidence, cloud_evidence):

    # Match files using their actual SHA-256 fingerprints
    comparison = endpoint_evidence.merge(
        cloud_evidence,
        on="sha256",
        how="outer",
        suffixes=("_endpoint", "_cloud"),
        indicator=True
    )

    # Classify comparison results
    comparison["comparison_result"] = comparison["_merge"].map({
        "both": "HASH MATCH",
        "left_only": "ENDPOINT ONLY",
        "right_only": "CLOUD ONLY"
    })

    return comparison


if __name__ == "__main__":

    # Locate project directories
    BASE_DIR = Path(__file__).resolve().parent.parent

    endpoint_folder = BASE_DIR / "data" / "endpoint_evidence"
    cloud_folder = BASE_DIR / "data" / "cloud_evidence"

    # Collect endpoint evidence
    endpoint_evidence = collect_file_evidence(
        endpoint_folder,
        "endpoint"
    )

    # Collect cloud evidence independently
    cloud_evidence = collect_file_evidence(
        cloud_folder,
        "cloud"
    )

    # Display endpoint hashes
    print("\n===== ENDPOINT FORENSIC EVIDENCE =====")

    print(
        endpoint_evidence[
            ["file_name", "file_size_bytes", "sha256"]
        ].to_string(index=False)
    )

    # Display cloud hashes
    print("\n===== CLOUD FORENSIC EVIDENCE =====")

    print(
        cloud_evidence[
            ["file_name", "file_size_bytes", "sha256"]
        ].to_string(index=False)
    )

    # Compare evidence
    comparison = compare_file_hashes(
        endpoint_evidence,
        cloud_evidence
    )

    # Display comparison results
    print("\n===== FORENSIC HASH COMPARISON =====")

    print(
        comparison[
            [
                "file_name_endpoint",
                "file_name_cloud",
                "comparison_result"
            ]
        ].to_string(index=False)
    )

    matching_files = comparison[
        comparison["comparison_result"] == "HASH MATCH"
    ]

    print("\n===== INVESTIGATION SUMMARY =====")
    print(f"Endpoint files: {len(endpoint_evidence)}")
    print(f"Cloud files: {len(cloud_evidence)}")
    print(f"Matching hashes: {len(matching_files)}")

    print("\n===== FORENSIC ANALYSIS COMPLETED =====")
