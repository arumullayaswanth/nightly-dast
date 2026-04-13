# merges ZAP + Nuclei + ffuf + Katana → summary.json
#!/usr/bin/env python3
"""
normalize-reports.py
Reads raw tool outputs (ZAP, Nuclei, ffuf, Katana) and produces a
consolidated summary.json with a unified finding schema.

Usage:
    python3 normalize-reports.py \
        --zap-report artifacts/raw/zap/zap-report.json \
        --zap-auth-report artifacts/raw/zap/zap-auth-report.json \
        --nuclei-report artifacts/raw/nuclei/nuclei-report.json \
        --ffuf-dir artifacts/raw/ffuf \
        --katana-dir artifacts/raw/katana \
        --output artifacts/final/summary.json \
        --timestamp 20240101T020000Z \
        --targets "https://app.example.com,https://api.example.com" \
        --environment non-production
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path


# ── Severity normalisation ────────────────────────────────────────────────────

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}

def normalise_severity(raw: str) -> str:
    s = (raw or "unknown").lower().strip()
    mapping = {
        # ZAP risk levels (riskdesc field contains e.g. "High (Medium)")
        "high (high)": "high",
        "high (medium)": "high",
        "high (low)": "high",
        "medium (high)": "medium",
        "medium (medium)": "medium",
        "medium (low)": "medium",
        "low (high)": "low",
        "low (medium)": "low",
        "low (low)": "low",
        "informational (high)": "info",
        "informational (medium)": "info",
        "informational (low)": "info",
        "informational (informational)": "info",
        # Plain severity words
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "moderate": "medium",
        "low": "low",
        "informational": "info",
        "info": "info",
        "false positive": "info",
    }
    # Try full match first, then first word match
    if s in mapping:
        return mapping[s]
    first_word = s.split()[0] if s.split() else s
    return mapping.get(first_word, "unknown")


# ── ZAP parser ────────────────────────────────────────────────────────────────

def parse_zap(path: str, auth: bool = False) -> list[dict]:
    if not path or not os.path.isfile(path):
        return []
    try:
        with open(path) as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        print(f"[WARN] Could not parse ZAP report {path}: {e}", file=sys.stderr)
        return []

    findings = []

    # ZAP JSON can have site as a list, a single dict, or nested under "@version"
    sites = data.get("site", data.get("@version", []))
    if isinstance(sites, dict):
        sites = [sites]
    elif not isinstance(sites, list):
        sites = []

    # Also handle flat alerts at top level (some ZAP versions)
    top_alerts = data.get("alerts", [])
    if top_alerts:
        sites = [{"alerts": top_alerts}]

    for site in sites:
        alerts = site.get("alerts", site.get("alert", []))
        if isinstance(alerts, dict):
            alerts = [alerts]
        for alert in alerts:
            severity = normalise_severity(alert.get("riskdesc", alert.get("risk", "")))
            instances = alert.get("instances", alert.get("instance", []))
            if isinstance(instances, dict):
                instances = [instances]
            urls = list({i.get("uri", i.get("url", "")) for i in instances if i.get("uri") or i.get("url")})
            if not urls:
                uri = alert.get("uri", alert.get("url", ""))
                if uri:
                    urls = [uri]
            # Extract CVE from tags if present
            cve = ""
            for tag in alert.get("tags", {}).values() if isinstance(alert.get("tags"), dict) else []:
                if isinstance(tag, str) and tag.startswith("CVE-"):
                    cve = tag
                    break
            findings.append({
                "id": f"zap-{alert.get('pluginid', alert.get('id', 'unknown'))}",
                "tool": "zap",
                "authenticated": auth,
                "title": alert.get("alert", alert.get("name", "Unknown")),
                "severity": severity,
                "description": alert.get("desc", alert.get("description", "")),
                "solution": alert.get("solution", alert.get("remedy", "")),
                "references": alert.get("reference", alert.get("references", "")),
                "affected_urls": urls,
                "cwe": alert.get("cweid", alert.get("cwe", "")),
                "cve": cve,
                "wasc": alert.get("wascid", ""),
                "confidence": alert.get("confidence", ""),
                "count": alert.get("count", len(instances)),
            })
    print(f"[INFO] ZAP parser: {len(findings)} findings from {path}", file=sys.stderr)
    return findings


# ── Nuclei parser ─────────────────────────────────────────────────────────────

def parse_nuclei(path: str) -> list[dict]:
    if not path or not os.path.isfile(path):
        return []
    findings = []
    try:
        with open(path) as f:
            raw = f.read().strip()

        if not raw:
            return []

        # Nuclei can output either a JSON array [...] or JSONL (one object per line)
        if raw.startswith("["):
            # JSON array format (--json-export produces this)
            try:
                items = json.loads(raw)
            except json.JSONDecodeError as e:
                print(f"[WARN] Could not parse Nuclei JSON array {path}: {e}", file=sys.stderr)
                return []
        else:
            # JSONL format — one JSON object per line
            items = []
            for line in raw.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    items.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

        for item in items:
            if not isinstance(item, dict):
                continue
            info = item.get("info", {})
            findings.append({
                "id": f"nuclei-{item.get('template-id', 'unknown')}",
                "tool": "nuclei",
                "authenticated": False,
                "title": info.get("name", item.get("template-id", "Unknown")),
                "severity": normalise_severity(info.get("severity", "")),
                "description": info.get("description", ""),
                "solution": info.get("remediation", ""),
                "references": "; ".join(info.get("reference", [])),
                "affected_urls": [item.get("matched-at", item.get("host", ""))],
                "cwe": "; ".join(
                    c for c in info.get("classification", {}).get("cwe-id", []) if c
                ),
                "tags": ", ".join(info.get("tags", [])),
                "matcher_name": item.get("matcher-name", ""),
                "extracted_results": item.get("extracted-results", []),
            })
    except OSError as e:
        print(f"[WARN] Could not read Nuclei report {path}: {e}", file=sys.stderr)
    return findings


# ── ffuf parser ───────────────────────────────────────────────────────────────

def parse_ffuf_dir(directory: str) -> list[dict]:
    findings = []
    if not directory or not os.path.isdir(directory):
        return findings
    for fname in Path(directory).glob("*.json"):
        try:
            with open(fname) as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError):
            continue
        for result in data.get("results", []):
            findings.append({
                "id": f"ffuf-{result.get('status', 0)}-{result.get('url', '')}",
                "tool": "ffuf",
                "authenticated": False,
                "title": f"Discovered path: {result.get('input', {}).get('FUZZ', result.get('url', ''))}",
                "severity": "info",
                "description": (
                    f"ffuf discovered URL: {result.get('url', '')} "
                    f"(HTTP {result.get('status', '?')}, "
                    f"{result.get('length', '?')} bytes)"
                ),
                "solution": "Review whether this endpoint should be publicly accessible.",
                "references": "",
                "affected_urls": [result.get("url", "")],
                "status_code": result.get("status"),
                "content_length": result.get("length"),
            })
    return findings


# ── Katana parser ─────────────────────────────────────────────────────────────

def parse_katana_dir(directory: str) -> list[dict]:
    """Katana outputs one URL per line; we surface them as info-level discoveries."""
    findings = []
    if not directory or not os.path.isdir(directory):
        return findings
    urls = set()
    for fname in Path(directory).glob("*.txt"):
        try:
            with open(fname) as f:
                for line in f:
                    url = line.strip()
                    if url:
                        urls.add(url)
        except OSError:
            continue
    if urls:
        findings.append({
            "id": "katana-discovery",
            "tool": "katana",
            "authenticated": False,
            "title": f"Katana discovered {len(urls)} endpoints",
            "severity": "info",
            "description": "Endpoint discovery via Katana crawler.",
            "solution": "",
            "references": "",
            "affected_urls": sorted(urls),
        })
    return findings


# ── Generic JSON findings parser (authz-matrix, rate-limit) ──────────────────

def parse_json_findings(path: str, tool_name: str) -> list[dict]:
    """Parse any tool output that has a top-level 'findings' array."""
    if not path or not os.path.isfile(path):
        return []
    try:
        with open(path) as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        print(f"[WARN] Could not parse {tool_name} report {path}: {e}", file=sys.stderr)
        return []
    findings = data.get("findings", [])
    print(f"[INFO] {tool_name} parser: {len(findings)} findings from {path}", file=sys.stderr)
    return findings


# ── Newman parser ─────────────────────────────────────────────────────────────

def parse_newman(path: str) -> list[dict]:
    """Parse Newman JSON report and surface failures as security findings."""
    if not path or not os.path.isfile(path):
        return []
    findings = []
    try:
        with open(path) as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        print(f"[WARN] Could not parse Newman report {path}: {e}", file=sys.stderr)
        return []

    run = data.get("run", {})
    executions = run.get("executions", [])

    for execution in executions:
        item = execution.get("item", {})
        item_name = item.get("name", "Unknown request")
        request = execution.get("request", {})
        url = ""
        if isinstance(request.get("url"), dict):
            url = request["url"].get("raw", "")
        elif isinstance(request.get("url"), str):
            url = request["url"]

        # Surface assertion failures as security findings
        assertions = execution.get("assertions", [])
        for assertion in assertions:
            err = assertion.get("error")
            if err:
                findings.append({
                    "id": f"newman-{item_name}-{assertion.get('assertion', 'unknown')}",
                    "tool": "newman",
                    "authenticated": True,
                    "title": f"API assertion failed: {assertion.get('assertion', 'unknown')}",
                    "severity": "medium",
                    "description": (
                        f"Newman assertion failed in request '{item_name}'. "
                        f"Error: {err.get('message', str(err))}. "
                        f"This may indicate a security control is missing or broken."
                    ),
                    "solution": "Review the API response and ensure security assertions pass.",
                    "references": "",
                    "affected_urls": [url] if url else [],
                    "cwe": "",
                    "cve": "",
                })

        # Surface HTTP errors (5xx) as findings
        response = execution.get("response", {})
        status_code = response.get("code", 0)
        if status_code and status_code >= 500:
            findings.append({
                "id": f"newman-5xx-{item_name}",
                "tool": "newman",
                "authenticated": True,
                "title": f"API returned HTTP {status_code}: {item_name}",
                "severity": "high",
                "description": (
                    f"Request '{item_name}' returned HTTP {status_code}. "
                    f"Server errors may indicate unhandled exceptions or security misconfigurations."
                ),
                "solution": "Investigate server-side error handling and exception disclosure.",
                "references": "",
                "affected_urls": [url] if url else [],
                "cwe": "CWE-209",
                "cve": "",
            })

    print(f"[INFO] Newman parser: {len(findings)} findings from {path}", file=sys.stderr)
    return findings

def build_stats(findings: list[dict]) -> dict:
    stats = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "unknown": 0, "total": 0}
    for f in findings:
        sev = f.get("severity", "unknown")
        stats[sev] = stats.get(sev, 0) + 1
        stats["total"] += 1
    return stats


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Normalize DAST tool outputs into summary.json")
    parser.add_argument("--zap-report", default="")
    parser.add_argument("--zap-auth-report", default="")
    parser.add_argument("--nuclei-report", default="")
    parser.add_argument("--ffuf-dir", default="")
    parser.add_argument("--katana-dir", default="")
    parser.add_argument("--newman-report", default="")
    parser.add_argument("--authz-report", default="")
    parser.add_argument("--rate-limit-report", default="")
    parser.add_argument("--bl-report", default="")
    parser.add_argument("--race-report", default="")
    parser.add_argument("--surface-report", default="")
    parser.add_argument("--oast-report", default="")
    parser.add_argument("--upload-report", default="")
    parser.add_argument("--frontend-report", default="")
    parser.add_argument("--output", required=True)
    parser.add_argument("--timestamp", default=datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"))
    parser.add_argument("--targets", default="")
    parser.add_argument("--environment", default="non-production")
    parser.add_argument("--auth-enabled", default="false")
    args = parser.parse_args()

    print("[INFO] Parsing ZAP unauthenticated report...")
    zap_findings = parse_zap(args.zap_report, auth=False)
    print(f"       {len(zap_findings)} findings")

    print("[INFO] Parsing ZAP authenticated report...")
    zap_auth_findings = parse_zap(args.zap_auth_report, auth=True)
    print(f"       {len(zap_auth_findings)} findings")

    print("[INFO] Parsing Nuclei report...")
    nuclei_findings = parse_nuclei(args.nuclei_report)
    print(f"       {len(nuclei_findings)} findings")

    print("[INFO] Parsing ffuf results...")
    ffuf_findings = parse_ffuf_dir(args.ffuf_dir)
    print(f"       {len(ffuf_findings)} findings")

    print("[INFO] Parsing Katana results...")
    katana_findings = parse_katana_dir(args.katana_dir)
    print(f"       {len(katana_findings)} findings")

    print("[INFO] Parsing Newman report...")
    newman_findings = parse_newman(args.newman_report)
    print(f"       {len(newman_findings)} findings")

    print("[INFO] Parsing authz-matrix results...")
    authz_findings = parse_json_findings(args.authz_report, "authz-matrix")
    print(f"       {len(authz_findings)} findings")

    print("[INFO] Parsing rate-limit results...")
    rate_findings = parse_json_findings(args.rate_limit_report, "rate-limit-test")
    print(f"       {len(rate_findings)} findings")

    print("[INFO] Parsing business-logic results...")
    bl_findings = parse_json_findings(args.bl_report, "business-logic")
    print(f"       {len(bl_findings)} findings")

    print("[INFO] Parsing race-condition results...")
    race_findings = parse_json_findings(args.race_report, "race-condition")
    print(f"       {len(race_findings)} findings")

    print("[INFO] Parsing attack-surface results...")
    surface_findings = parse_json_findings(args.surface_report, "attack-surface")
    print(f"       {len(surface_findings)} findings")

    print("[INFO] Parsing OAST results...")
    oast_findings = parse_nuclei(args.oast_report)  # same JSONL format as nuclei
    # re-tag as oast tool
    for f in oast_findings:
        f["tool"] = "oast"
    print(f"       {len(oast_findings)} findings")

    print("[INFO] Parsing upload-abuse results...")
    upload_findings = parse_json_findings(args.upload_report, "upload-abuse")
    print(f"       {len(upload_findings)} findings")

    print("[INFO] Parsing frontend-security results...")
    frontend_findings = parse_json_findings(args.frontend_report, "frontend-security")
    print(f"       {len(frontend_findings)} findings")

    all_findings = (zap_findings + zap_auth_findings + nuclei_findings +
                    ffuf_findings + katana_findings + newman_findings +
                    authz_findings + rate_findings + bl_findings +
                    race_findings + surface_findings + oast_findings +
                    upload_findings + frontend_findings)

    # Sort by severity
    all_findings.sort(key=lambda x: SEVERITY_ORDER.get(x.get("severity", "unknown"), 5))

    stats = build_stats(all_findings)
    targets = [t.strip() for t in args.targets.split(",") if t.strip()]
    auth_enabled = args.auth_enabled.lower() == "true"

    # Stage execution flags — track which tools ran with real output
    stage_flags = {
        "zap_unauth":     "passed" if zap_findings else ("partial" if os.path.isfile(args.zap_report) else "not_run"),
        "zap_auth":       ("passed" if zap_auth_findings else ("partial" if os.path.isfile(args.zap_auth_report) else ("not_run" if not auth_enabled else "failed"))),
        "nuclei":         "passed" if nuclei_findings else ("partial" if os.path.isfile(args.nuclei_report) else "not_run"),
        "katana":         "passed" if katana_findings else "not_run",
        "ffuf":           "passed" if ffuf_findings else "not_run",
        "newman":         "passed" if newman_findings else ("partial" if os.path.isfile(args.newman_report) else "not_run"),
        "auth_bootstrap": "passed" if auth_enabled else "not_run",
        "authz_matrix":   "passed" if authz_findings else ("partial" if os.path.isfile(args.authz_report) else "not_run"),
        "rate_limit":     "passed" if rate_findings else ("partial" if os.path.isfile(args.rate_limit_report) else "not_run"),
        "business_logic": "passed" if bl_findings else ("partial" if os.path.isfile(args.bl_report) else "not_run"),
        "race_condition":  "passed" if race_findings else ("partial" if os.path.isfile(args.race_report) else "not_run"),
        "attack_surface":  "passed" if surface_findings else ("partial" if os.path.isfile(args.surface_report) else "not_run"),
        "oast":            "passed" if oast_findings else ("partial" if os.path.isfile(args.oast_report) else "not_run"),
        "upload_abuse":    "passed" if upload_findings else ("partial" if os.path.isfile(args.upload_report) else "not_run"),
        "frontend_security": "passed" if frontend_findings else ("partial" if os.path.isfile(args.frontend_report) else "not_run"),
    }

    summary = {
        "scan_metadata": {
            "timestamp": args.timestamp,
            "environment": args.environment,
            "targets": targets,
            "pipeline": "github-actions-dast-nightly",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "auth_enabled": auth_enabled,
            "is_fallback": False,
            "stage_flags": stage_flags,
        },
        "statistics": stats,
        "findings": all_findings,
    }

    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "w") as f:
        json.dump(summary, f, indent=2)

    print(f"\n[INFO] summary.json written to {args.output}")
    print(f"[INFO] Total findings: {stats['total']} "
          f"(critical={stats['critical']}, high={stats['high']}, "
          f"medium={stats['medium']}, low={stats['low']}, info={stats['info']})")
    print(f"[INFO] Stage flags: {stage_flags}")


if __name__ == "__main__":
    main()
