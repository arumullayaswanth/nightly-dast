#!/usr/bin/env bash
# upload-s3.sh — validate artifacts then upload to S3 under dast/<timestamp>/
set -euo pipefail

: "${S3_BUCKET:?S3_BUCKET environment variable is required}"
: "${SCAN_TIMESTAMP:?SCAN_TIMESTAMP environment variable is required}"
: "${AWS_DEFAULT_REGION:=us-east-1}"

S3_PREFIX="dast/${SCAN_TIMESTAMP}"
S3_BASE="s3://${S3_BUCKET}/${S3_PREFIX}"

# ── Pre-upload artifact validation ───────────────────────────────────────────
echo "[INFO] Validating artifacts before upload..."
FAILED=0

if [ ! -f "artifacts/final/summary.json" ]; then
  echo "[ERROR] Missing required artifact: artifacts/final/summary.json"
  FAILED=$((FAILED + 1))
else
  if ! jq empty artifacts/final/summary.json 2>/dev/null; then
    echo "[ERROR] artifacts/final/summary.json is not valid JSON"
    FAILED=$((FAILED + 1))
  else
    echo "[OK] artifacts/final/summary.json ($(wc -c < artifacts/final/summary.json) bytes)"
  fi
fi

if [ ! -f "artifacts/final/summary.pdf" ]; then
  echo "[WARN] artifacts/final/summary.pdf not found — uploading without PDF"
else
  echo "[OK] artifacts/final/summary.pdf ($(wc -c < artifacts/final/summary.pdf) bytes)"
fi

if [ "$FAILED" -gt 0 ]; then
  echo "[ERROR] $FAILED critical artifact(s) missing or invalid. Aborting S3 upload."
  exit 1
fi

# ── Verify AWS credentials ────────────────────────────────────────────────────
echo "[INFO] Verifying AWS credentials..."
if ! aws sts get-caller-identity --output text > /dev/null 2>&1; then
  echo "[ERROR] AWS credentials are not configured or invalid."
  exit 1
fi
echo "[INFO] AWS credentials valid."

# ── Upload to S3 under dast/<timestamp>/ ─────────────────────────────────────
echo "[INFO] Uploading artifacts to ${S3_BASE}"

if [ -d "artifacts/raw" ]; then
  echo "[INFO] Uploading raw reports..."
  aws s3 cp artifacts/raw/ "${S3_BASE}/raw/" \
    --recursive \
    --no-progress \
    --region "$AWS_DEFAULT_REGION"
fi

if [ -d "artifacts/final" ]; then
  echo "[INFO] Uploading final reports..."
  aws s3 cp artifacts/final/ "${S3_BASE}/final/" \
    --recursive \
    --no-progress \
    --region "$AWS_DEFAULT_REGION"
fi

if [ -d "artifacts/logs" ]; then
  echo "[INFO] Uploading logs..."
  aws s3 cp artifacts/logs/ "${S3_BASE}/logs/" \
    --recursive \
    --no-progress \
    --region "$AWS_DEFAULT_REGION"
fi

echo "[INFO] All artifacts uploaded successfully."
echo "[INFO] S3 path: ${S3_BASE}"

# Write S3 path for downstream steps (Slack notification)
echo "${S3_BASE}" > /tmp/s3-artifact-path.txt
