#!/usr/bin/env bash
# slack-notify.sh — tiered Slack notification with triage intelligence
# Tier Red:    new critical/high, fallback summary, failed auth coverage, OAST callback
# Tier Yellow: stage partial, coverage dropped, new mediums in sensitive workflows
# Tier Green:  no new serious findings, coverage targets met
set -euo pipefail

: "${SLACK_WEBHOOK_URL:?SLACK_WEBHOOK_URL secret is required}"
: "${SCAN_TIMESTAMP:?SCAN_TIMESTAMP is required}"
: "${JOB_STATUS:=unknown}"

ENVIRONMENT="${ENVIRONMENT:-non-production}"
TARGET_URLS="${TARGET_URLS:-unknown}"
S3_BUCKET="${S3_BUCKET:-}"
AWS_DEFAULT_REGION="${AWS_DEFAULT_REGION:-us-east-1}"
SLACK_ONCALL_WEBHOOK="${SLACK_ONCALL_WEBHOOK:-}"   # optional second webhook for red-tier escalation

S3_PATH=""
if [ -n "$S3_BUCKET" ]; then
    S3_PATH="s3://${S3_BUCKET}/dast/${SCAN_TIMESTAMP}"
fi

# ── Read summary.json ─────────────────────────────────────────────────────────
CRITICAL=0; HIGH=0; MEDIUM=0; LOW=0; INFO_COUNT=0; TOTAL=0
ZAP_COUNT=0; NUCLEI_COUNT=0; FFUF_COUNT=0; KATANA_COUNT=0; NEWMAN_COUNT=0
AUTHZ_COUNT=0; RATE_COUNT=0; BL_COUNT=0; RACE_COUNT=0; SURFACE_COUNT=0
UPLOAD_COUNT=0; FRONTEND_COUNT=0
POSTURE_SCORE="N/A"; COVERAGE="N/A"; RISK_LEVEL="UNKNOWN"
IS_FALLBACK="false"
AUTH_STATUS="not_run"; ZAP_AUTH_STATUS="not_run"
AUTHZ_STATUS="not_run"; RATE_STATUS="not_run"; BL_STATUS="not_run"
RACE_STATUS="not_run"; UPLOAD_STATUS="not_run"; FRONTEND_STATUS="not_run"
NEW_FINDINGS="N/A"; FIXED_FINDINGS="N/A"; REGRESSION_SCORE="N/A"
TOP_RISKS=""; FAILED_STAGES=""

if [ -f "artifacts/final/summary.json" ]; then
    CRITICAL=$(jq -r '.statistics.critical // 0' artifacts/final/summary.json)
    HIGH=$(jq -r '.statistics.high // 0' artifacts/final/summary.json)
    MEDIUM=$(jq -r '.statistics.medium // 0' artifacts/final/summary.json)
    LOW=$(jq -r '.statistics.low // 0' artifacts/final/summary.json)
    INFO_COUNT=$(jq -r '.statistics.info // 0' artifacts/final/summary.json)
    TOTAL=$(jq -r '.statistics.total // 0' artifacts/final/summary.json)

    # Per-tool counts
    ZAP_COUNT=$(jq -r '[.findings[] | select(.tool=="zap")] | length' artifacts/final/summary.json)
    NUCLEI_COUNT=$(jq -r '[.findings[] | select(.tool=="nuclei")] | length' artifacts/final/summary.json)
    FFUF_COUNT=$(jq -r '[.findings[] | select(.tool=="ffuf")] | length' artifacts/final/summary.json)
    KATANA_COUNT=$(jq -r '[.findings[] | select(.tool=="katana")] | length' artifacts/final/summary.json)
    NEWMAN_COUNT=$(jq -r '[.findings[] | select(.tool=="newman")] | length' artifacts/final/summary.json)
    AUTHZ_COUNT=$(jq -r '[.findings[] | select(.tool=="authz-matrix")] | length' artifacts/final/summary.json)
    RATE_COUNT=$(jq -r '[.findings[] | select(.tool=="rate-limit-test")] | length' artifacts/final/summary.json)
    BL_COUNT=$(jq -r '[.findings[] | select(.tool=="business-logic")] | length' artifacts/final/summary.json)
    RACE_COUNT=$(jq -r '[.findings[] | select(.tool=="race-condition")] | length' artifacts/final/summary.json)
    SURFACE_COUNT=$(jq -r '[.findings[] | select(.tool=="attack-surface")] | length' artifacts/final/summary.json)
    UPLOAD_COUNT=$(jq -r '[.findings[] | select(.tool=="upload-abuse")] | length' artifacts/final/summary.json)
    FRONTEND_COUNT=$(jq -r '[.findings[] | select(.tool=="frontend-security")] | length' artifacts/final/summary.json)

    # Posture
    POSTURE_SCORE=$(jq -r '.posture.posture_score // "N/A"' artifacts/final/summary.json)
    COVERAGE=$(jq -r '.posture.coverage_confidence // "N/A"' artifacts/final/summary.json)
    RISK_LEVEL=$(jq -r '.posture.risk_level // "UNKNOWN"' artifacts/final/summary.json)

    # Flags
    IS_FALLBACK=$(jq -r '.scan_metadata.is_fallback // false' artifacts/final/summary.json)
    AUTH_STATUS=$(jq -r '.scan_metadata.stage_flags.auth_bootstrap // "not_run"' artifacts/final/summary.json)
    ZAP_AUTH_STATUS=$(jq -r '.scan_metadata.stage_flags.zap_auth // "not_run"' artifacts/final/summary.json)
    AUTHZ_STATUS=$(jq -r '.scan_metadata.stage_flags.authz_matrix // "not_run"' artifacts/final/summary.json)
    RATE_STATUS=$(jq -r '.scan_metadata.stage_flags.rate_limit // "not_run"' artifacts/final/summary.json)
    BL_STATUS=$(jq -r '.scan_metadata.stage_flags.business_logic // "not_run"' artifacts/final/summary.json)
    RACE_STATUS=$(jq -r '.scan_metadata.stage_flags.race_condition // "not_run"' artifacts/final/summary.json)
    UPLOAD_STATUS=$(jq -r '.scan_metadata.stage_flags.upload_abuse // "not_run"' artifacts/final/summary.json)
    FRONTEND_STATUS=$(jq -r '.scan_metadata.stage_flags.frontend_security // "not_run"' artifacts/final/summary.json)

    # Regression
    NEW_FINDINGS=$(jq -r '.scan_metadata.new_findings_count // "N/A"' artifacts/final/summary.json)
    FIXED_FINDINGS=$(jq -r '.scan_metadata.fixed_findings_count // "N/A"' artifacts/final/summary.json)
    REGRESSION_SCORE=$(jq -r '.scan_metadata.regression_score // "N/A"' artifacts/final/summary.json)

    # Top 3 new critical/high risks
    TOP_RISKS=$(jq -r '
        (.regression.new_findings // [])
        | map(select(.severity == "critical" or .severity == "high"))
        | sort_by(.severity)
        | .[0:3]
        | map("• [" + (.severity | ascii_upcase) + "] " + .title + " (" + .tool + ")")
        | join("\n")
    ' artifacts/final/summary.json 2>/dev/null || echo "")

    # Failed stages
    FAILED_STAGES=$(jq -r '
        .scan_metadata.stage_flags
        | to_entries
        | map(select(.value == "failed" or .value == "not_run"))
        | map(.key)
        | join(", ")
    ' artifacts/final/summary.json 2>/dev/null || echo "")
fi

# ── Determine alert tier ──────────────────────────────────────────────────────
TIER="green"
TIER_REASON=""

# Red conditions
if [ "$IS_FALLBACK" = "true" ]; then
    TIER="red"
    TIER_REASON="Fallback summary used — all scan tools produced no output"
elif [ "$JOB_STATUS" != "success" ]; then
    TIER="red"
    TIER_REASON="Pipeline job failed (status: ${JOB_STATUS})"
elif [ "$CRITICAL" -gt 0 ]; then
    TIER="red"
    TIER_REASON="${CRITICAL} new critical finding(s)"
elif [ "$HIGH" -gt 0 ] && [ "$NEW_FINDINGS" != "N/A" ] && [ "$NEW_FINDINGS" -gt 0 ]; then
    TIER="red"
    TIER_REASON="${NEW_FINDINGS} new finding(s) including high severity"
elif [ "$ZAP_AUTH_STATUS" = "failed" ] || [ "$ZAP_AUTH_STATUS" = "not_run" ] && [ "$AUTH_STATUS" = "passed" ]; then
    TIER="red"
    TIER_REASON="Authenticated scan failed despite successful auth bootstrap"
fi

# Yellow conditions (only if not already red)
if [ "$TIER" = "green" ]; then
    if [ "$HIGH" -gt 0 ]; then
        TIER="yellow"
        TIER_REASON="${HIGH} high severity finding(s)"
    elif [ "$MEDIUM" -gt 0 ] && [ "$NEW_FINDINGS" != "N/A" ] && [ "$NEW_FINDINGS" -gt 0 ]; then
        TIER="yellow"
        TIER_REASON="${NEW_FINDINGS} new finding(s) including medium severity"
    elif [ "$AUTHZ_STATUS" = "partial" ] || [ "$RATE_STATUS" = "partial" ] || [ "$BL_STATUS" = "partial" ]; then
        TIER="yellow"
        TIER_REASON="One or more security suites ran with partial coverage"
    elif [ -n "$FAILED_STAGES" ]; then
        TIER="yellow"
        TIER_REASON="Stages not run: ${FAILED_STAGES}"
    fi
fi

# ── Map tier to Slack color and emoji ─────────────────────────────────────────
case "$TIER" in
    red)
        COLOR="danger"
        TIER_EMOJI=":rotating_light:"
        STATUS_TEXT="ACTION REQUIRED — ${TIER_REASON}"
        ;;
    yellow)
        COLOR="warning"
        TIER_EMOJI=":warning:"
        STATUS_TEXT="Review Required — ${TIER_REASON}"
        ;;
    *)
        COLOR="good"
        TIER_EMOJI=":white_check_mark:"
        STATUS_TEXT="Clean — No new critical/high findings"
        ;;
esac

# Override if job failed
if [ "$JOB_STATUS" != "success" ] && [ "$TIER" != "red" ]; then
    COLOR="warning"
    TIER_EMOJI=":warning:"
    STATUS_TEXT="Pipeline error (status: ${JOB_STATUS})"
fi

# ── Format target list ────────────────────────────────────────────────────────
TARGET_LIST=$(echo "$TARGET_URLS" | tr ',' '\n' | sed 's/^/• /' | tr '\n' '\n')

# ── Build tool coverage line ──────────────────────────────────────────────────
TOOLS_LINE="🔍 ZAP:${ZAP_COUNT} | ☢️ Nuclei:${NUCLEI_COUNT} | 🕷️ Katana:${KATANA_COUNT} | 💥 ffuf:${FFUF_COUNT} | 📬 Newman:${NEWMAN_COUNT} | 🔐 AuthZ:${AUTHZ_COUNT} | ⏱️ RateLimit:${RATE_COUNT} | 🧠 BizLogic:${BL_COUNT} | 🔄 Race:${RACE_COUNT} | 🗺️ Surface:${SURFACE_COUNT} | 📎 Upload:${UPLOAD_COUNT} | 🌐 Frontend:${FRONTEND_COUNT}"

# ── Build stage coverage status ───────────────────────────────────────────────
stage_icon() {
    case "$1" in
        passed)  echo "✅" ;;
        partial) echo "⚠️" ;;
        failed)  echo "❌" ;;
        *)       echo "⬜" ;;
    esac
}

STAGE_STATUS="$(stage_icon "$AUTH_STATUS") Auth  $(stage_icon "$ZAP_AUTH_STATUS") ZAP-Auth  $(stage_icon "$AUTHZ_STATUS") AuthZ  $(stage_icon "$RATE_STATUS") RateLimit  $(stage_icon "$BL_STATUS") BizLogic  $(stage_icon "$RACE_STATUS") Race  $(stage_icon "$UPLOAD_STATUS") Upload  $(stage_icon "$FRONTEND_STATUS") Frontend"

# ── Build fallback warning ────────────────────────────────────────────────────
FALLBACK_FIELDS="[]"
if [ "$IS_FALLBACK" = "true" ]; then
    FALLBACK_FIELDS=$(jq -n '[{
        title: "⚠️ FALLBACK SUMMARY USED",
        value: "All scan tools produced no output. Results are not reliable.",
        short: false
    }]')
fi

# ── Build top risks field ─────────────────────────────────────────────────────
TOP_RISKS_FIELDS="[]"
if [ -n "$TOP_RISKS" ]; then
    TOP_RISKS_FIELDS=$(jq -n --arg risks "$TOP_RISKS" '[{
        title: "🆕 Top New Risks",
        value: $risks,
        short: false
    }]')
fi

# ── Build failed stages field ─────────────────────────────────────────────────
FAILED_STAGES_FIELDS="[]"
if [ -n "$FAILED_STAGES" ]; then
    FAILED_STAGES_FIELDS=$(jq -n --arg stages "$FAILED_STAGES" '[{
        title: "❌ Stages Not Run / Failed",
        value: $stages,
        short: false
    }]')
fi

# ── Assemble full Slack payload ───────────────────────────────────────────────
PAYLOAD=$(jq -n \
    --arg color "$COLOR" \
    --arg tier_emoji "$TIER_EMOJI" \
    --arg status_text "$STATUS_TEXT" \
    --arg timestamp "$SCAN_TIMESTAMP" \
    --arg environment "$ENVIRONMENT" \
    --arg targets "$TARGET_LIST" \
    --arg posture "$POSTURE_SCORE" \
    --arg coverage "$COVERAGE" \
    --arg risk "$RISK_LEVEL" \
    --arg critical "$CRITICAL" \
    --arg high "$HIGH" \
    --arg medium "$MEDIUM" \
    --arg low "$LOW" \
    --arg info "$INFO_COUNT" \
    --arg total "$TOTAL" \
    --arg tools "$TOOLS_LINE" \
    --arg stages "$STAGE_STATUS" \
    --arg new_count "$NEW_FINDINGS" \
    --arg fixed_count "$FIXED_FINDINGS" \
    --arg regression "$REGRESSION_SCORE" \
    --arg s3_path "$S3_PATH" \
    --argjson fallback_fields "$FALLBACK_FIELDS" \
    --argjson top_risks_fields "$TOP_RISKS_FIELDS" \
    --argjson failed_stages_fields "$FAILED_STAGES_FIELDS" \
    '{
        attachments: [
            {
                color: $color,
                title: ($tier_emoji + "  DAST Nightly — " + $status_text),
                fields: ([
                    { title: "Timestamp",          value: $timestamp,   short: true },
                    { title: "Environment",        value: $environment, short: true },
                    { title: "Posture Score",      value: ($posture + "/100  |  Risk: " + $risk + "  |  Coverage: " + $coverage + "%"), short: false },
                    { title: "Regression",         value: ("Score: " + $regression + "/100  |  🆕 New: " + $new_count + "  |  ✅ Fixed: " + $fixed_count), short: false },
                    { title: "Scanned URL(s)",     value: $targets,     short: false },
                    { title: "Severity Breakdown", value: ("🔴 Critical: " + $critical + "   🟠 High: " + $high + "   🟡 Medium: " + $medium + "   🟢 Low: " + $low + "   🔵 Info: " + $info + "   📊 Total: " + $total), short: false },
                    { title: "Tool Coverage",      value: $tools,       short: false },
                    { title: "Stage Coverage",     value: $stages,      short: false },
                    { title: "S3 Artifacts",       value: (if $s3_path != "" then $s3_path else "N/A" end), short: false }
                ] + $fallback_fields + $top_risks_fields + $failed_stages_fields),
                footer: "DAST Pipeline | GitHub Actions",
                ts: (now | floor)
            }
        ]
    }')

# ── Send to main security channel ────────────────────────────────────────────
echo "[INFO] Sending Slack notification (tier: ${TIER})..."
HTTP_CODE=$(curl -s -o /tmp/slack-response.txt -w "%{http_code}" \
    -X POST \
    -H "Content-Type: application/json" \
    -d "$PAYLOAD" \
    "$SLACK_WEBHOOK_URL")

if [ "$HTTP_CODE" = "200" ]; then
    echo "[INFO] Slack notification sent (tier: ${TIER})."
else
    echo "[WARN] Slack returned HTTP ${HTTP_CODE}"
    cat /tmp/slack-response.txt
fi

# ── Red-tier escalation to on-call channel ────────────────────────────────────
if [ "$TIER" = "red" ] && [ -n "$SLACK_ONCALL_WEBHOOK" ]; then
    echo "[INFO] Sending red-tier escalation to on-call channel..."

    ONCALL_PAYLOAD=$(jq -n \
        --arg tier_emoji "$TIER_EMOJI" \
        --arg status_text "$STATUS_TEXT" \
        --arg timestamp "$SCAN_TIMESTAMP" \
        --arg environment "$ENVIRONMENT" \
        --arg critical "$CRITICAL" \
        --arg high "$HIGH" \
        --arg s3_path "$S3_PATH" \
        --arg posture "$POSTURE_SCORE" \
        --arg risk "$RISK_LEVEL" \
        --argjson top_risks_fields "$TOP_RISKS_FIELDS" \
        '{
            attachments: [
                {
                    color: "danger",
                    title: ($tier_emoji + " ON-CALL ALERT — DAST: " + $status_text),
                    fields: ([
                        { title: "Timestamp",      value: $timestamp,   short: true },
                        { title: "Environment",    value: $environment, short: true },
                        { title: "Posture",        value: ($posture + "/100 — " + $risk), short: true },
                        { title: "Critical/High",  value: ("🔴 " + $critical + " critical  🟠 " + $high + " high"), short: true },
                        { title: "S3 Artifacts",   value: (if $s3_path != "" then $s3_path else "N/A" end), short: false }
                    ] + $top_risks_fields),
                    footer: "DAST Pipeline — On-Call Escalation",
                    ts: (now | floor)
                }
            ]
        }')

    ONCALL_CODE=$(curl -s -o /tmp/slack-oncall-response.txt -w "%{http_code}" \
        -X POST \
        -H "Content-Type: application/json" \
        -d "$ONCALL_PAYLOAD" \
        "$SLACK_ONCALL_WEBHOOK")

    if [ "$ONCALL_CODE" = "200" ]; then
        echo "[INFO] On-call escalation sent."
    else
        echo "[WARN] On-call webhook returned HTTP ${ONCALL_CODE}"
    fi
fi
