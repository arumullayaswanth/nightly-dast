#!/usr/bin/env python3
"""
regression-diff.py
Phase 2 — New vs Fixed Findings Comparison

Compares the current summary.json against the most recent prior run
stored in S3 to produce a regression delta:
  - new_findings:   findings in current run not in prior run
  - fixed_findings: findings in prior run not in current run
  - persisting:     findings present in both runs

The delta is injected back into summary.json and used by:
  - generate-pdf.py  (regression section in PDF)
  - slack-notify.sh  (new/fixed counts in Slack)

Usage:
    python3 scripts/regression-diff.py \
        --current  artifacts/final/summary.json \
        --bucket   yash-security \
        --prefix   dast/ \
        --region   us-east-1

Requirements:
    pip install boto3
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone

try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
except ImportError:
    print("[WARN] boto3 not available — skipping regression diff", file=sys.stderr)
    sys.exit(0)


def get_prior_summary(bucket: str, prefix: str, current_timestamp: str, region: str) -> dict | None:
    """Find and download the most recent prior summary.json from S3."""
    try:
        s3 = boto3.client("s3", region_name=region)
        paginator = s3.get_paginator("list_objects_v2")
        pages = paginator.paginate(Bucket=bucket, Prefix=prefix, Delimiter="/")

        timestamps = []
        for page in pages:
            for cp in page.get("CommonPrefixes", []):
                ts = cp["Prefix"].rstrip("/").split("/")[-1]
                if ts != current_timestamp and ts.endswith("Z"):
                    timestamps.append(ts)

        if not timestamps:
            print("[INFO] No prior runs found in S3 — skipping regression diff")
            return None

        # Sort descending and take the most recent
        timestamps.sort(reverse=True)
        prior_ts = timestamps[0]
        prior_key = f"{prefix}{prior_ts}/final/summary.json"

        print(f"[INFO] Comparing against prior run: {prior_ts}")
        response = s3.get_object(Bucket=bucket, Key=prior_key)
        return json.loads(response["Body"].read())

    except ClientError as e:
        print(f"[WARN] Could not fetch prior summary from S3: {e}", file=sys.stderr)
        return None
    except NoCredentialsError:
        print("[WARN] AWS credentials not available — skipping regression diff", file=sys.stderr)
        return None


def finding_key(finding: dict) -> str:
    """Generate a stable key for deduplication across runs."""
    return f"{finding.get('tool', '')}::{finding.get('title', '')}::{finding.get('cwe', '')}"


def diff_findings(current: list, prior: list) -> dict:
    """Compare two finding lists and return new, fixed, and persisting sets."""
    current_keys = {finding_key(f): f for f in current}
    prior_keys   = {finding_key(f): f for f in prior}

    new_keys       = set(current_keys) - set(prior_keys)
    fixed_keys     = set(prior_keys)   - set(current_keys)
    persisting_keys = set(current_keys) & set(prior_keys)

    return {
        "new_findings":       [current_keys[k] for k in new_keys],
        "fixed_findings":     [prior_keys[k]   for k in fixed_keys],
        "persisting_findings": [current_keys[k] for k in persisting_keys],
        "new_count":       len(new_keys),
        "fixed_count":     len(fixed_keys),
        "persisting_count": len(persisting_keys),
    }


def severity_score(findings: list) -> int:
    weights = {"critical": 100, "high": 40, "medium": 10, "low": 3, "info": 1, "unknown": 0}
    return sum(weights.get(f.get("severity", "unknown"), 0) for f in findings)


def main():
    parser = argparse.ArgumentParser(description="Compare current scan against prior S3 run")
    parser.add_argument("--current",  required=True, help="Path to current summary.json")
    parser.add_argument("--bucket",   required=True, help="S3 bucket name")
    parser.add_argument("--prefix",   default="dast/", help="S3 prefix (default: dast/)")
    parser.add_argument("--region",   default="us-east-1")
    args = parser.parse_args()

    if not os.path.isfile(args.current):
        print(f"[ERROR] Current summary not found: {args.current}", file=sys.stderr)
        sys.exit(1)

    with open(args.current) as f:
        current_data = json.load(f)

    current_ts = current_data.get("scan_metadata", {}).get("timestamp", "")
    current_findings = current_data.get("findings", [])

    prior_data = get_prior_summary(args.bucket, args.prefix, current_ts, args.region)

    if prior_data is None:
        # No prior run — mark everything as new
        regression = {
            "prior_timestamp": None,
            "new_findings": current_findings,
            "fixed_findings": [],
            "persisting_findings": [],
            "new_count": len(current_findings),
            "fixed_count": 0,
            "persisting_count": 0,
            "regression_score": 100.0,
            "note": "First run — no prior data to compare against",
        }
    else:
        prior_findings = prior_data.get("findings", [])
        prior_ts = prior_data.get("scan_metadata", {}).get("timestamp", "unknown")

        diff = diff_findings(current_findings, prior_findings)

        # Regression score: 100 = no new findings, decreases with new critical/high
        new_score = severity_score(diff["new_findings"])
        regression_score = max(0.0, round(100 - min(new_score / 10, 100), 1))

        regression = {
            "prior_timestamp": prior_ts,
            **diff,
            "regression_score": regression_score,
        }

        print(f"[INFO] New findings:       {diff['new_count']}")
        print(f"[INFO] Fixed findings:     {diff['fixed_count']}")
        print(f"[INFO] Persisting:         {diff['persisting_count']}")
        print(f"[INFO] Regression score:   {regression_score}/100")

        # Print new critical/high for visibility
        new_critical_high = [
            f for f in diff["new_findings"]
            if f.get("severity") in ("critical", "high")
        ]
        if new_critical_high:
            print(f"\n[WARN] {len(new_critical_high)} NEW critical/high findings:")
            for f in new_critical_high:
                print(f"  - [{f['severity'].upper()}] {f['title']} ({f.get('tool', '?')})")

    # Inject regression data into summary.json
    current_data["regression"] = regression
    current_data["scan_metadata"]["regression_score"] = regression.get("regression_score", 100.0)
    current_data["scan_metadata"]["new_findings_count"] = regression.get("new_count", 0)
    current_data["scan_metadata"]["fixed_findings_count"] = regression.get("fixed_count", 0)

    with open(args.current, "w") as f:
        json.dump(current_data, f, indent=2)

    print(f"[INFO] Regression diff written to {args.current}")


if __name__ == "__main__":
    main()
