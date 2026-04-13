#!/usr/bin/env python3
"""
attack-surface.py
Phase 3 — Attack Surface Inventory

Builds a comprehensive attack surface map by aggregating:
  - Katana crawl results (discovered URLs)
  - ffuf forced browsing results (discovered paths)
  - ZAP scan results (scanned URLs and parameters)
  - JS endpoint extraction (from Katana output)
  - Parameter discovery (from ZAP instances)

Produces attack-surface.json with:
  - All discovered routes
  - Authenticated vs unauthenticated routes
  - API operations
  - Parameters found
  - Forms discovered
  - High-risk routes (admin, debug, upload, etc.)
  - Coverage metrics

Usage:
    python3 scripts/attack-surface.py \
        --katana-dir  artifacts/raw/katana \
        --ffuf-dir    artifacts/raw/ffuf \
        --zap-report  artifacts/raw/zap/zap-report.json \
        --output      artifacts/raw/attack-surface/attack-surface.json \
        --target      https://www.example.com
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path
from urllib.parse import urlparse, parse_qs


# High-risk path patterns
HIGH_RISK_PATTERNS = [
    (r"/admin",          "admin panel"),
    (r"/debug",          "debug endpoint"),
    (r"/actuator",       "Spring actuator"),
    (r"/graphql",        "GraphQL endpoint"),
    (r"/api/internal",   "internal API"),
    (r"/upload",         "file upload"),
    (r"/backup",         "backup file"),
    (r"\.env",           "environment file"),
    (r"\.git",           "git repository"),
    (r"/swagger",        "API documentation"),
    (r"/openapi",        "OpenAPI spec"),
    (r"/metrics",        "metrics endpoint"),
    (r"/health",         "health check"),
    (r"/console",        "admin console"),
    (r"/shell",          "shell access"),
    (r"/phpmyadmin",     "phpMyAdmin"),
    (r"/wp-admin",       "WordPress admin"),
    (r"/reset",          "password reset"),
    (r"/token",          "token endpoint"),
]

# API operation patterns
API_PATTERNS = [
    r"/api/",
    r"/v\d+/",
    r"/rest/",
    r"/graphql",
    r"/gql",
]


def is_api_endpoint(path: str) -> bool:
    return any(re.search(p, path, re.IGNORECASE) for p in API_PATTERNS)


def get_high_risk_labels(path: str) -> list:
    labels = []
    for pattern, label in HIGH_RISK_PATTERNS:
        if re.search(pattern, path, re.IGNORECASE):
            labels.append(label)
    return labels


def extract_parameters(url_str: str) -> list:
    try:
        parsed = urlparse(url_str)
        params = list(parse_qs(parsed.query).keys())
        return params
    except Exception:
        return []


def load_katana(directory: str) -> set:
    urls = set()
    if not directory or not os.path.isdir(directory):
        return urls
    for fname in Path(directory).glob("*.txt"):
        try:
            with open(fname) as f:
                for line in f:
                    u = line.strip()
                    if u.startswith("http"):
                        urls.add(u)
        except OSError:
            pass
    return urls


def load_ffuf(directory: str) -> set:
    urls = set()
    if not directory or not os.path.isdir(directory):
        return urls
    for fname in Path(directory).glob("*.json"):
        try:
            with open(fname) as f:
                data = json.load(f)
            for result in data.get("results", []):
                u = result.get("url", "")
                if u:
                    urls.add(u)
        except (json.JSONDecodeError, OSError):
            pass
    return urls


def load_zap(report_path: str) -> tuple[set, list]:
    """Returns (urls, forms_with_params)"""
    urls = set()
    forms = []
    if not report_path or not os.path.isfile(report_path):
        return urls, forms
    try:
        with open(report_path) as f:
            data = json.load(f)
        sites = data.get("site", [])
        if isinstance(sites, dict):
            sites = [sites]
        for site in sites:
            for alert in site.get("alerts", []):
                for instance in alert.get("instances", []):
                    u = instance.get("uri", "")
                    if u:
                        urls.add(u)
                    param = instance.get("param", "")
                    if param and u:
                        forms.append({"url": u, "param": param})
    except (json.JSONDecodeError, OSError):
        pass
    return urls, forms


def categorise_routes(all_urls: set, target: str) -> dict:
    routes = {
        "all": [],
        "api": [],
        "high_risk": [],
        "parameters": {},
        "unique_paths": set(),
    }

    for u in all_urls:
        try:
            parsed = urlparse(u)
            path = parsed.path
        except Exception:
            continue

        if path in routes["unique_paths"]:
            continue
        routes["unique_paths"].add(path)

        entry = {
            "url": u,
            "path": path,
            "is_api": is_api_endpoint(path),
            "high_risk_labels": get_high_risk_labels(path),
            "parameters": extract_parameters(u),
        }

        routes["all"].append(entry)

        if entry["is_api"]:
            routes["api"].append(entry)

        if entry["high_risk_labels"]:
            routes["high_risk"].append(entry)

        if entry["parameters"]:
            for p in entry["parameters"]:
                if p not in routes["parameters"]:
                    routes["parameters"][p] = []
                routes["parameters"][p].append(u)

    return routes


def main():
    parser = argparse.ArgumentParser(description="Build attack surface inventory")
    parser.add_argument("--katana-dir",  default="")
    parser.add_argument("--ffuf-dir",    default="")
    parser.add_argument("--zap-report",  default="")
    parser.add_argument("--output",      required=True)
    parser.add_argument("--target",      default="")
    args = parser.parse_args()

    print("[INFO] Building attack surface inventory...")

    katana_urls = load_katana(args.katana_dir)
    print(f"[INFO] Katana URLs: {len(katana_urls)}")

    ffuf_urls = load_ffuf(args.ffuf_dir)
    print(f"[INFO] ffuf URLs: {len(ffuf_urls)}")

    zap_urls, zap_forms = load_zap(args.zap_report)
    print(f"[INFO] ZAP URLs: {len(zap_urls)}, forms: {len(zap_forms)}")

    all_urls = katana_urls | ffuf_urls | zap_urls
    print(f"[INFO] Total unique URLs: {len(all_urls)}")

    routes = categorise_routes(all_urls, args.target)

    # Build findings for high-risk routes
    findings = []
    for entry in routes["high_risk"]:
        for label in entry["high_risk_labels"]:
            findings.append({
                "id": f"surface-{label.replace(' ', '-')}-{entry['path'].replace('/', '-')}",
                "tool": "attack-surface",
                "authenticated": False,
                "title": f"High-Risk Endpoint Discovered: {label}",
                "severity": "medium" if "admin" in label or "debug" in label or "shell" in label else "low",
                "description": f"High-risk endpoint '{entry['path']}' ({label}) was discovered during surface mapping.",
                "solution": f"Verify this endpoint is intentionally exposed. Restrict access if not required publicly.",
                "references": "OWASP Testing Guide — Information Gathering",
                "affected_urls": [entry["url"]],
                "cwe": "CWE-200",
                "cve": "",
            })

    output = {
        "scan_type": "attack-surface",
        "target": args.target,
        "timestamp": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
        "summary": {
            "total_urls": len(all_urls),
            "unique_paths": len(routes["unique_paths"]),
            "api_endpoints": len(routes["api"]),
            "high_risk_endpoints": len(routes["high_risk"]),
            "parameters_discovered": len(routes["parameters"]),
            "forms_discovered": len(zap_forms),
        },
        "sources": {
            "katana": len(katana_urls),
            "ffuf": len(ffuf_urls),
            "zap": len(zap_urls),
        },
        "high_risk_routes": routes["high_risk"],
        "api_routes": routes["api"],
        "all_routes": routes["all"][:500],  # cap at 500 for JSON size
        "parameters": routes["parameters"],
        "forms": zap_forms[:100],
        "findings": findings,
    }

    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "w") as f:
        json.dump(output, f, indent=2)

    print(f"[INFO] Attack surface: {len(all_urls)} URLs, {len(routes['high_risk'])} high-risk, {len(routes['api'])} API endpoints")
    print(f"[INFO] Findings: {len(findings)}")
    print(f"[INFO] Output: {args.output}")


if __name__ == "__main__":
    main()
