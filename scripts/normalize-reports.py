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
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "moderate": "medium",
        "low": "low",
        "informational": "info",
        "info": "info",
        "false positive": "info",
    }
    return mapping.get(s, "unknown")


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
    sites = data.get("site", [])
    if isinstance(sites, dict):
        sites = [sites]

    for site in sites:
        for alert in site.get("alerts", []):
            severity = normalise_severity(alert.get("riskdesc", ""))
            instances = alert.get("instances", [])
            urls = list({i.get("uri", "") for i in instances if i.get("uri")})
            findings.append({
                "id": f"zap-{alert.get('pluginid', 'unknown')}",
                "tool": "zap",
                "authenticated": auth,
                "title": alert.get("alert", "Unknown"),
                "severity": severity,
                "description": alert.get("desc", ""),
                "solution": alert.get("solution", ""),
                "references": alert.get("reference", ""),
                "affected_urls": urls,
                "cwe": alert.get("cweid", ""),
                "wasc": alert.get("wascid", ""),
                "confidence": alert.get("confidence", ""),
                "count": alert.get("count", len(instances)),
            })
    return findings


# ── Nuclei parser ─────────────────────────────────────────────────────────────

def parse_nuclei(path: str) -> list[dict]:
    if not path or not os.path.isfile(path):
        return []
    findings = []
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    item = json.loads(line)
                except json.JSONDecodeError:
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


# ── Summary stats ─────────────────────────────────────────────────────────────

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
    parser.add_argument("--output", required=True)
    parser.add_argument("--timestamp", default=datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"))
    parser.add_argument("--targets", default="")
    parser.add_argument("--environment", default="non-production")
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

    all_findings = zap_findings + zap_auth_findings + nuclei_findings + ffuf_findings + katana_findings

    # Sort by severity
    all_findings.sort(key=lambda x: SEVERITY_ORDER.get(x.get("severity", "unknown"), 5))

    stats = build_stats(all_findings)
    targets = [t.strip() for t in args.targets.split(",") if t.strip()]

    summary = {
        "scan_metadata": {
            "timestamp": args.timestamp,
            "environment": args.environment,
            "targets": targets,
            "pipeline": "github-actions-dast-nightly",
            "generated_at": datetime.now(timezone.utc).isoformat(),
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


if __name__ == "__main__":
    main()
