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
ZAP_COUNT=0; NUCLEI_COUNT=0; FFUF_COUNT=0; KATANA_COUNT=0; NEWMAN_COUNT=0
POSTURE_SCORE="N/A"; COVERAGE="N/A"; RISK_LEVEL="UNKNOWN"
IS_FALLBACK="false"; AUTH_STATUS="not_run"; ZAP_AUTH_STATUS="not_run"

if [ -f "artifacts/final/summary.json" ]; then
  CRITICAL=$(jq -r '.statistics.critical // 0' artifacts/final/summary.json)
  HIGH=$(jq -r '.statistics.high // 0' artifacts/final/summary.json)
  MEDIUM=$(jq -r '.statistics.medium // 0' artifacts/final/summary.json)
  LOW=$(jq -r '.statistics.low // 0' artifacts/final/summary.json)
  INFO=$(jq -r '.statistics.info // 0' artifacts/final/summary.json)
  TOTAL=$(jq -r '.statistics.total // 0' artifacts/final/summary.json)
  ZAP_COUNT=$(jq -r '[.findings[] | select(.tool=="zap")] | length' artifacts/final/summary.json)
  NUCLEI_COUNT=$(jq -r '[.findings[] | select(.tool=="nuclei")] | length' artifacts/final/summary.json)
  FFUF_COUNT=$(jq -r '[.findings[] | select(.tool=="ffuf")] | length' artifacts/final/summary.json)
  KATANA_COUNT=$(jq -r '[.findings[] | select(.tool=="katana")] | length' artifacts/final/summary.json)
  NEWMAN_COUNT=$(jq -r '[.findings[] | select(.tool=="newman")] | length' artifacts/final/summary.json)
  POSTURE_SCORE=$(jq -r '.posture.posture_score // "N/A"' artifacts/final/summary.json)
  COVERAGE=$(jq -r '.posture.coverage_confidence // "N/A"' artifacts/final/summary.json)
  RISK_LEVEL=$(jq -r '.posture.risk_level // "UNKNOWN"' artifacts/final/summary.json)
  IS_FALLBACK=$(jq -r '.scan_metadata.is_fallback // false' artifacts/final/summary.json)
  AUTH_STATUS=$(jq -r '.scan_metadata.stage_flags.auth_bootstrap // "not_run"' artifacts/final/summary.json)
  ZAP_AUTH_STATUS=$(jq -r '.scan_metadata.stage_flags.zap_auth // "not_run"' artifacts/final/summary.json)
fi

# Build tools summary line
TOOLS_SUMMARY="🔍 ZAP: ${ZAP_COUNT}  |  ☢️ Nuclei: ${NUCLEI_COUNT}  |  🌐 Katana: ${KATANA_COUNT}  |  💥 ffuf: ${FFUF_COUNT}  |  📬 Newman: ${NEWMAN_COUNT}"

# Fallback warning
FALLBACK_NOTE=""
if [ "$IS_FALLBACK" = "true" ]; then
  FALLBACK_NOTE="⚠️ FALLBACK SUMMARY USED — scan tools produced no output"
fi

# Auth coverage status
AUTH_NOTE="Auth Bootstrap: ${AUTH_STATUS} | ZAP Auth Scan: ${ZAP_AUTH_STATUS}"

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
# Build optional fallback warning field
FALLBACK_FIELD=""
if [ "$IS_FALLBACK" = "true" ]; then
  FALLBACK_FIELD=$(jq -n --arg note "$FALLBACK_NOTE" \
    '[{ title: "⚠️ Warning", value: $note, short: false }]')
else
  FALLBACK_FIELD="[]"
fi

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
  --arg tools "$TOOLS_SUMMARY" \
  --arg posture "$POSTURE_SCORE" \
  --arg coverage "$COVERAGE" \
  --arg risk "$RISK_LEVEL" \
  --arg auth_note "$AUTH_NOTE" \
  --arg s3_path "$S3_PATH" \
  --argjson fallback_fields "$FALLBACK_FIELD" \
  '{
    attachments: [
      {
        color: $color,
        title: ($status_emoji + " DAST Nightly Scan — " + $status_text),
        fields: ([
          { title: "Timestamp",          value: $timestamp,   short: true },
          { title: "Environment",        value: $environment, short: true },
          { title: "Posture Score",      value: ($posture + "/100  |  Risk: " + $risk + "  |  Coverage: " + $coverage + "%"), short: false },
          { title: "Scanned URL(s)",     value: $targets,     short: false },
          { title: "Severity Breakdown", value: ("🔴 Critical: " + $critical + "  🟠 High: " + $high + "  🟡 Medium: " + $medium + "  🟢 Low: " + $low + "  🔵 Info: " + $info + "  📊 Total: " + $total), short: false },
          { title: "Tools & Findings",   value: $tools,       short: false },
          { title: "Auth Coverage",      value: $auth_note,   short: false },
          { title: "S3 Artifacts",       value: (if $s3_path != "" then $s3_path else "N/A" end), short: false }
        ] + $fallback_fields),
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
