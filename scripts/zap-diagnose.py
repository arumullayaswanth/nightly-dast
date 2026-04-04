#!/usr/bin/env python3
"""
zap-diagnose.py
---------------
When ZAP does not produce report files, this script reads the ZAP log,
detects the root cause, and injects a diagnostic finding into summary.json
so the PDF report explains exactly why ZAP scanning failed.

Usage:
    python3 scripts/zap-diagnose.py \
        --zap-log artifacts/logs/zap.log \
        --zap-dir artifacts/raw/zap \
        --summary artifacts/final/summary.json \
        --target https://www.example.com
"""

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone


# ── Known failure patterns in ZAP logs ───────────────────────────────────────

FAILURE_PATTERNS = [
    (
        r"cloudflare|cf-ray|attention required|ddos protection",
        "Cloudflare / WAF Protection",
        "The target is protected by Cloudflare or a Web Application Firewall (WAF). "
        "ZAP's requests were blocked before reaching the application. "
        "ZAP is detected as a scanner and served a challenge/block page instead of real content.",
        "Use a custom User-Agent header, scan from a whitelisted IP, or temporarily disable "
        "WAF rules for the scanner IP during the scan window.",
    ),
    (
        r"total of 0 urls|no urls found|spider found 0",
        "Spider Found 0 URLs",
        "ZAP connected to the target but the spider discovered no pages to scan. "
        "This is common with Single Page Applications (React, Angular, Vue) where "
        "content is loaded dynamically by JavaScript and the standard spider cannot follow it.",
        "Enable the AJAX spider by setting ZAP_AJAX_SPIDER=true in GitHub Actions variables. "
        "The AJAX spider uses a real browser to crawl JavaScript-heavy applications.",
    ),
    (
        r"connection refused|connect.*refused|failed to connect",
        "Connection Refused",
        "ZAP could not establish a TCP connection to the target. "
        "The server actively refused the connection, possibly due to IP-based blocking, "
        "firewall rules, or the server being down.",
        "Verify the target URL is reachable from GitHub Actions runner IPs. "
        "Check if the server has IP allowlisting that blocks cloud provider ranges.",
    ),
    (
        r"ssl.*error|certificate.*error|handshake.*fail|ssl.*exception",
        "SSL / TLS Certificate Error",
        "ZAP encountered an SSL/TLS error when connecting to the target. "
        "This may be caused by a self-signed certificate, expired certificate, "
        "or TLS version mismatch.",
        "Add -z 'api.disablekey=true' to ZAP options, or use the -n flag to ignore SSL errors. "
        "Verify the target certificate is valid.",
    ),
    (
        r"timeout|timed out|socketimeout|read timed out",
        "Connection Timeout",
        "ZAP requests to the target timed out. "
        "The server may be too slow to respond (e.g. Heroku free tier cold start), "
        "or the target is rate-limiting ZAP's requests.",
        "Increase ZAP timeout settings or reduce scan intensity. "
        "For Heroku free tier, send a warm-up request before scanning.",
    ),
    (
        r"403|forbidden|access denied|not authorized",
        "Access Forbidden (HTTP 403)",
        "The target returned HTTP 403 Forbidden for ZAP's requests. "
        "The server is blocking the scanner based on User-Agent, IP address, "
        "or missing authentication headers.",
        "Check if the target requires authentication. "
        "If scanning protected pages, enable AUTH_ENABLED=true and configure login credentials.",
    ),
    (
        r"permission denied.*wrk|permission denied.*zap",
        "File Permission Error",
        "ZAP could not write report files to the output directory due to a permission error. "
        "The ZAP Docker container runs as user 'zap' (uid 1000) which may not have "
        "write access to the mounted volume.",
        "Ensure the output directory has chmod 777 before running the Docker container. "
        "This should be fixed automatically by the pipeline.",
    ),
]

UNKNOWN_REASON = (
    "Unknown / Unrecognised Error",
    "ZAP ran but did not produce report files. The exact cause could not be determined "
    "from the log output. This may be due to an internal ZAP error, an unsupported "
    "target configuration, or a network issue.",
    "Review the full ZAP log at artifacts/logs/zap.log for more details. "
    "Try running the scan manually with: docker run --rm ghcr.io/zaproxy/zaproxy:stable "
    "zap-full-scan.py -t <TARGET_URL> -I",
)


def detect_failure(log_content: str) -> tuple:
    """Match log content against known failure patterns."""
    log_lower = log_content.lower()
    for pattern, title, description, solution in FAILURE_PATTERNS:
        if re.search(pattern, log_lower):
            return title, description, solution
    return UNKNOWN_REASON


def main():
    parser = argparse.ArgumentParser(description="Diagnose ZAP scan failures")
    parser.add_argument("--zap-log", required=True)
    parser.add_argument("--zap-dir", required=True)
    parser.add_argument("--summary", required=True)
    parser.add_argument("--target", default="unknown")
    args = parser.parse_args()

    # Check if ZAP produced any report files
    zap_files = []
    if os.path.isdir(args.zap_dir):
        zap_files = [f for f in os.listdir(args.zap_dir)
                     if f.endswith((".json", ".html", ".xml"))]

    if zap_files:
        print(f"[INFO] ZAP produced {len(zap_files)} report file(s) — no diagnosis needed.")
        return

    print("[INFO] ZAP produced no report files — running diagnosis...")

    # Read ZAP log
    log_content = ""
    if os.path.isfile(args.zap_log):
        with open(args.zap_log) as f:
            log_content = f.read()
        print(f"[INFO] Read {len(log_content)} bytes from {args.zap_log}")
    else:
        print(f"[WARN] ZAP log not found: {args.zap_log}")
        log_content = ""

    # Detect failure reason
    title, description, solution = detect_failure(log_content)
    print(f"[INFO] Detected failure reason: {title}")

    # Extract relevant log lines for evidence
    evidence_lines = []
    for line in log_content.splitlines():
        lower = line.lower()
        if any(kw in lower for kw in [
            "error", "fail", "warn", "exception", "refused",
            "timeout", "forbidden", "blocked", "cloudflare",
            "total of", "spider", "permission"
        ]):
            evidence_lines.append(line.strip())
    evidence = "\n".join(evidence_lines[:20])  # cap at 20 lines

    # Build diagnostic finding
    diagnostic_finding = {
        "id": "zap-diagnostic-failure",
        "tool": "zap",
        "authenticated": False,
        "title": f"ZAP Scan Incomplete — {title}",
        "severity": "info",
        "description": (
            f"{description}\n\n"
            f"Target: {args.target}\n\n"
            f"Evidence from ZAP log:\n{evidence if evidence else 'No relevant log lines found.'}"
        ),
        "solution": solution,
        "references": "https://www.zaproxy.org/docs/docker/full-scan/",
        "affected_urls": [args.target],
        "cwe": "",
        "diagnostic": True,
    }

    # Inject into summary.json
    if not os.path.isfile(args.summary):
        print(f"[WARN] summary.json not found at {args.summary} — skipping injection")
        return

    with open(args.summary) as f:
        summary = json.load(f)

    # Add diagnostic finding
    summary["findings"].insert(0, diagnostic_finding)

    # Add ZAP scan status to metadata
    summary["scan_metadata"]["zap_status"] = {
        "completed": False,
        "reason": title,
        "target": args.target,
        "diagnosed_at": datetime.now(timezone.utc).isoformat(),
    }

    # Update stats — diagnostic is info level
    summary["statistics"]["info"] = summary["statistics"].get("info", 0) + 1
    summary["statistics"]["total"] = summary["statistics"].get("total", 0) + 1

    with open(args.summary, "w") as f:
        json.dump(summary, f, indent=2)

    print(f"[INFO] Diagnostic finding injected into {args.summary}")
    print(f"[INFO] Reason: {title}")


if __name__ == "__main__":
    main()
