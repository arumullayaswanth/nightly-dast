#!/usr/bin/env bash
# preflight.sh — validate target URLs are reachable before scanning
set -euo pipefail

TIMEOUT="${PREFLIGHT_TIMEOUT:-10}"
FAILED=0

if [ -z "${TARGET_URLS:-}" ]; then
  echo "[ERROR] TARGET_URLS environment variable is not set or empty."
  exit 1
fi

echo "[INFO] Starting pre-flight checks (timeout: ${TIMEOUT}s per target)"

for url in $(echo "$TARGET_URLS" | tr ',' '\n'); do
  url=$(echo "$url" | xargs) # trim whitespace
  if [ -z "$url" ]; then continue; fi

  echo -n "[CHECK] $url ... "
  HTTP_CODE=$(curl -o /dev/null -s -w "%{http_code}" \
    --max-time "$TIMEOUT" \
    --connect-timeout "$TIMEOUT" \
    -L \
    "$url" || echo "000")

  if [ "$HTTP_CODE" = "000" ]; then
    echo "UNREACHABLE (connection failed)"
    FAILED=$((FAILED + 1))
  elif [ "$HTTP_CODE" -ge 500 ]; then
    echo "WARNING (HTTP $HTTP_CODE — server error, proceeding with caution)"
  else
    echo "OK (HTTP $HTTP_CODE)"
  fi
done

if [ "$FAILED" -gt 0 ]; then
  echo "[ERROR] $FAILED target(s) unreachable. Aborting pipeline."
  exit 1
fi

echo "[INFO] All targets passed pre-flight checks."
