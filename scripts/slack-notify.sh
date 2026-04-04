#!/usr/bin/env bash
# slack-notify.sh — send scan completion notification to Slack
#color-coded Slack notification with findings + S3 link
set -euo pipefail

: "${SLACK_WEBHOOK_URL:?SLACK_WEBHOOK_URL secret is required}"
: "${SCAN_TIMESTAMP:?SCAN_TIMESTAMP is required}"
: "${JOB_STATUS:=unknown}"

ENVIRONMENT="${ENVIRONMENT:-non-production}"
TARGET_URLS="${TARGET_URLS:-unknown}"
S3_BUCKET="${S3_BUCKET:-}"
AWS_DEFAULT_REGION="${AWS_DEFAULT_REGION:-us-east-1}"

# Build S3 URL if bucket is set
S3_PATH=""
if [ -n "$S3_BUCKET" ]; then
  S3_PATH="s3://${S3_BUCKET}/dast/${SCAN_TIMESTAMP}"
fi

# Read findings summary from summary.json if available
CRITICAL=0; HIGH=0; MEDIUM=0; LOW=0; INFO=0; TOTAL=0
if [ -f "artifacts/final/summary.json" ]; then
  CRITICAL=$(jq -r '.statistics.critical // 0' artifacts/final/summary.json)
  HIGH=$(jq -r '.statistics.high // 0' artifacts/final/summary.json)
  MEDIUM=$(jq -r '.statistics.medium // 0' artifacts/final/summary.json)
  LOW=$(jq -r '.statistics.low // 0' artifacts/final/summary.json)
  INFO=$(jq -r '.statistics.info // 0' artifacts/final/summary.json)
  TOTAL=$(jq -r '.statistics.total // 0' artifacts/final/summary.json)
fi

# Choose emoji and color based on job status and findings
if [ "$JOB_STATUS" = "success" ]; then
  if [ "$CRITICAL" -gt 0 ] || [ "$HIGH" -gt 0 ]; then
    COLOR="danger"
    STATUS_EMOJI=":rotating_light:"
    STATUS_TEXT="Completed with critical/high findings"
  else
    COLOR="good"
    STATUS_EMOJI=":white_check_mark:"
    STATUS_TEXT="Completed — no critical/high findings"
  fi
else
  COLOR="warning"
  STATUS_EMOJI=":warning:"
  STATUS_TEXT="Completed with errors (status: ${JOB_STATUS})"
fi

# Format target list
TARGET_LIST=$(echo "$TARGET_URLS" | tr ',' '\n' | sed 's/^/• /' | tr '\n' '\n')

# Build Slack payload
PAYLOAD=$(jq -n \
  --arg color "$COLOR" \
  --arg status_emoji "$STATUS_EMOJI" \
  --arg status_text "$STATUS_TEXT" \
  --arg timestamp "$SCAN_TIMESTAMP" \
  --arg environment "$ENVIRONMENT" \
  --arg targets "$TARGET_LIST" \
  --arg critical "$CRITICAL" \
  --arg high "$HIGH" \
  --arg medium "$MEDIUM" \
  --arg low "$LOW" \
  --arg info "$INFO" \
  --arg total "$TOTAL" \
  --arg s3_path "$S3_PATH" \
  '{
    attachments: [
      {
        color: $color,
        title: ($status_emoji + " DAST Nightly Scan — " + $status_text),
        fields: [
          { title: "Timestamp",    value: $timestamp,    short: true },
          { title: "Environment",  value: $environment,  short: true },
          { title: "Targets",      value: $targets,      short: false },
          { title: "Findings",
            value: ("🔴 Critical: " + $critical + "  🟠 High: " + $high + "  🟡 Medium: " + $medium + "  🟢 Low: " + $low + "  🔵 Info: " + $info + "  📊 Total: " + $total),
            short: false },
          { title: "S3 Artifacts", value: (if $s3_path != "" then $s3_path else "N/A" end), short: false }
        ],
        footer: "DAST Pipeline | GitHub Actions",
        ts: (now | floor)
      }
    ]
  }')

echo "[INFO] Sending Slack notification..."
HTTP_CODE=$(curl -s -o /tmp/slack-response.txt -w "%{http_code}" \
  -X POST \
  -H "Content-Type: application/json" \
  -d "$PAYLOAD" \
  "$SLACK_WEBHOOK_URL")

if [ "$HTTP_CODE" = "200" ]; then
  echo "[INFO] Slack notification sent successfully."
else
  echo "[WARN] Slack notification returned HTTP $HTTP_CODE"
  cat /tmp/slack-response.txt
fi
