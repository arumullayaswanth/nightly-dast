#!/usr/bin/env bash
# zap-auth-setup.sh
# Builds a ZAP Automation Framework plan YAML that injects the Playwright
# session cookie or Bearer token into every ZAP request.
# This replaces the broken eval+$ZAP_REPLACE_HEADER approach.
#
# Usage:
#   bash scripts/zap-auth-setup.sh <TARGET_URL> <OUTPUT_PLAN_PATH>
#
# Reads:
#   /tmp/auth-token.txt       — Bearer token (preferred)
#   /tmp/zap-session.txt      — Cookie header string (fallback)
#
# Outputs:
#   <OUTPUT_PLAN_PATH>        — ZAP automation plan YAML

set -euo pipefail

TARGET_URL="${1:?TARGET_URL argument is required}"
OUTPUT_PLAN="${2:?OUTPUT_PLAN_PATH argument is required}"

mkdir -p "$(dirname "$OUTPUT_PLAN")"

# ── Determine auth header type and value ─────────────────────────────────────
AUTH_HEADER_NAME=""
AUTH_HEADER_VALUE=""

if [ -f /tmp/auth-token.txt ]; then
    TOKEN=$(cat /tmp/auth-token.txt | tr -d '[:space:]')
    if [ -n "$TOKEN" ]; then
        AUTH_HEADER_NAME="Authorization"
        AUTH_HEADER_VALUE="Bearer ${TOKEN}"
        echo "[INFO] Using Bearer token for ZAP authenticated scan."
    fi
fi

if [ -z "$AUTH_HEADER_NAME" ] && [ -f /tmp/zap-session.txt ]; then
    COOKIE=$(cat /tmp/zap-session.txt | tr -d '\n')
    if [ -n "$COOKIE" ]; then
        AUTH_HEADER_NAME="Cookie"
        AUTH_HEADER_VALUE="${COOKIE}"
        echo "[INFO] Using session cookie for ZAP authenticated scan."
    fi
fi

if [ -z "$AUTH_HEADER_NAME" ]; then
    echo "[WARN] No auth token or session cookie found — ZAP auth plan will run without credentials."
fi

# ── Write ZAP Automation Framework plan ──────────────────────────────────────
cat > "$OUTPUT_PLAN" << YAML
---
env:
  contexts:
    - name: "authenticated-context"
      urls:
        - "${TARGET_URL}"
      includePaths:
        - "${TARGET_URL}.*"
      excludePaths: []
      authentication:
        method: "http"
        parameters: {}
        verification:
          method: "response"
          loggedInRegex: ""
          loggedOutRegex: "login|sign.in|unauthorized"
          pollFrequency: 60
          pollUnits: "requests"
          pollUrl: ""
          pollPostData: ""
      sessionManagement:
        method: "cookie"
        parameters: {}
      users:
        - name: "playwright-session"
          credentials: {}

  parameters:
    failOnError: false
    failOnWarning: false
    progressToStdout: true

jobs:
  - type: requestor
    parameters:
      user: "playwright-session"

  - type: replacer
    parameters:
      rules:
        - description: "Inject auth header from Playwright session"
          matchType: "REQ_HEADER"
          matchString: "${AUTH_HEADER_NAME:-X-No-Auth}"
          matchRegex: false
          replacementString: "${AUTH_HEADER_VALUE:-}"
          tokenProcessing: false
          enabled: ${AUTH_HEADER_NAME:+true}${AUTH_HEADER_NAME:-false}

  - type: spider
    parameters:
      context: "authenticated-context"
      user: "playwright-session"
      url: "${TARGET_URL}"
      maxDuration: 5
      maxDepth: 5
      maxChildren: 10
      acceptCookies: true
      handleODataParametersVisited: false
      handleParameters: "USE_ALL"
      maxParseSizeBytes: 2621440
      parseComments: true
      parseGit: false
      parseRobotsTxt: true
      parseSitemapXml: true
      parseSVNEntries: false
      postForm: true
      processForm: true
      requestWaitTime: 200
      sendRefererHeader: true
      threadCount: 2

  - type: activeScan
    parameters:
      context: "authenticated-context"
      user: "playwright-session"
      policy: ""
      maxRuleDurationInMins: 0
      maxScanDurationInMins: 60
      addQueryParam: false
      defaultPolicy: ""
      delayInMs: 0
      handleAntiCSRFTokens: true
      injectPluginIdInHeader: false
      scanHeadersAllRequests: false
      threadPerHost: 2

  - type: report
    parameters:
      template: "traditional-json"
      reportDir: "/zap/wrk"
      reportFile: "zap-auth-report"
      reportTitle: "ZAP Authenticated Scan Report"
      reportDescription: "Authenticated DAST scan using Playwright session"
      displayReport: false
YAML

echo "[INFO] ZAP automation plan written to ${OUTPUT_PLAN}"

# ── Inject real header value using sed (YAML was written with placeholders) ──
# Replace placeholder with actual values safely
if [ -n "$AUTH_HEADER_NAME" ]; then
    # Use Python for safe YAML string injection (avoids shell quoting issues)
    python3 - << PYEOF
import re, sys

with open("${OUTPUT_PLAN}", "r") as f:
    content = f.read()

# Fix the enabled flag placeholder
content = content.replace(
    "\${AUTH_HEADER_NAME:+true}\${AUTH_HEADER_NAME:-false}",
    "true"
)

with open("${OUTPUT_PLAN}", "w") as f:
    f.write(content)

print("[INFO] ZAP plan auth injection complete.")
PYEOF
else
    python3 - << PYEOF
with open("${OUTPUT_PLAN}", "r") as f:
    content = f.read()

content = content.replace(
    "\${AUTH_HEADER_NAME:+true}\${AUTH_HEADER_NAME:-false}",
    "false"
)

with open("${OUTPUT_PLAN}", "w") as f:
    f.write(content)
PYEOF
fi

echo "[INFO] ZAP auth setup complete. Plan: ${OUTPUT_PLAN}"
