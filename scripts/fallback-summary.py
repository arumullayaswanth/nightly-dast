#!/usr/bin/env python3
"""
fallback-summary.py
-------------------
WHY THIS FILE EXISTS:
    During the pipeline, all scan tools (ZAP, Nuclei, ffuf, Katana) run
    with '|| true' so a failed scan does not stop the whole pipeline.
    But if ALL tools fail, normalize-reports.py has nothing to read and
    summary.json never gets created. Without it, generate-pdf.py crashes
    with 'Input file not found' and the pipeline fails.

WHAT THIS SCRIPT DOES:
    Safety net. The workflow checks if summary.json exists after
    normalize-reports.py runs. If missing, this script writes a minimal
    valid summary.json with zero findings so the PDF, S3 upload, and
    Slack steps always have something to work with.

WHEN IT RUNS:
    Only called by the workflow when summary.json is not found:
        if [ ! -f artifacts/final/summary.json ]; then
            python3 scripts/fallback-summary.py ...
        fi

ARGUMENTS (positional):
    1. output path  - where to write summary.json
    2. timestamp    - value of SCAN_TIMESTAMP env var
    3. targets      - comma-separated TARGET_URLS env var
    4. environment  - value of ENVIRONMENT env var
"""

import datetime
import json
import os
import sys

# Read positional arguments injected by the workflow shell step
output = sys.argv[1] if len(sys.argv) > 1 else "artifacts/final/summary.json"
timestamp = sys.argv[2] if len(sys.argv) > 2 else ""
targets_raw = sys.argv[3] if len(sys.argv) > 3 else ""
environment = sys.argv[4] if len(sys.argv) > 4 else "non-production"

# Split comma-separated TARGET_URLS into a clean list
targets = [t.strip() for t in targets_raw.split(",") if t.strip()]

# Build summary using the same schema as normalize-reports.py
# so downstream steps (PDF, Slack) work without any changes
summary = {
    "scan_metadata": {
        "timestamp": timestamp,
        "environment": environment,
        "targets": targets,
        "pipeline": "github-actions-dast-nightly",
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        # Flags in the report that real scan data was not available
        "note": "Fallback summary — normalize-reports.py failed or produced no output",
    },
    # All zero because no findings were parsed from scan tools
    "statistics": {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
        "unknown": 0,
        "total": 0,
    },
    # Empty — no scan data to report
    "findings": [],
}

# Create output directory if it does not exist, then write the file
os.makedirs(os.path.dirname(output), exist_ok=True)
with open(output, "w") as f:
    json.dump(summary, f, indent=2)

print(f"[INFO] Fallback summary.json written to {output}")
