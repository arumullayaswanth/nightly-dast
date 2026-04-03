#!/usr/bin/env bash
# upload-s3.sh — upload all scan artifacts to S3 under a timestamped dast/ path
# uploads all artifacts to S3 under dast/<timestamp>/
set -euo pipefail

: "${S3_BUCKET:?S3_BUCKET environment variable is required}"
: "${SCAN_TIMESTAMP:?SCAN_TIMESTAMP environment variable is required}"
: "${AWS_DEFAULT_REGION:=us-east-1}"

S3_PREFIX="dast/${SCAN_TIMESTAMP}"
S3_BASE="s3://${S3_BUCKET}/${S3_PREFIX}"

echo "[INFO] Uploading artifacts to ${S3_BASE}"

# Verify AWS credentials are available
if ! aws sts get-caller-identity --output text > /dev/null 2>&1; then
  echo "[ERROR] AWS credentials are not configured or invalid."
  exit 1
fi

# Upload raw tool outputs
if [ -d "artifacts/raw" ]; then
  echo "[INFO] Uploading raw reports..."
  aws s3 cp artifacts/raw/ "${S3_BASE}/raw/" \
    --recursive \
    --no-progress \
    --region "$AWS_DEFAULT_REGION"
fi

# Upload final consolidated reports
if [ -d "artifacts/final" ]; then
  echo "[INFO] Uploading final reports..."
  aws s3 cp artifacts/final/ "${S3_BASE}/final/" \
    --recursive \
    --no-progress \
    --region "$AWS_DEFAULT_REGION"
fi

# Upload logs
if [ -d "artifacts/logs" ]; then
  echo "[INFO] Uploading logs..."
  aws s3 cp artifacts/logs/ "${S3_BASE}/logs/" \
    --recursive \
    --no-progress \
    --region "$AWS_DEFAULT_REGION"
fi

echo "[INFO] All artifacts uploaded successfully."
echo "[INFO] S3 path: ${S3_BASE}"

# Write S3 path for downstream steps
echo "${S3_BASE}" > /tmp/s3-artifact-path.txt
