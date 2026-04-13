#!/usr/bin/env python3
"""
arjun-merge.py
Merges Arjun parameter discovery results into the existing attack-surface.json.

Arjun discovers hidden/undocumented GET and POST parameters on endpoints.
This script reads all Arjun JSON output files and injects the discovered
parameters into the attack-surface.json parameters map.

Usage:
    python3 scripts/arjun-merge.py \
        --arjun-dir artifacts/raw/arjun \
        --surface   artifacts/raw/attack-surface/attack-surface.json
"""

import argparse
import json
import os
import sys
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description="Merge Arjun results into attack-surface.json")
    parser.add_argument("--arjun-dir", required=True)
    parser.add_argument("--surface",   required=True)
    args = parser.parse_args()

    if not os.path.isdir(args.arjun_dir):
        print(f"[INFO] Arjun dir not found: {args.arjun_dir} — skipping merge")
        sys.exit(0)

    if not os.path.isfile(args.surface):
        print(f"[WARN] attack-surface.json not found: {args.surface} — skipping merge")
        sys.exit(0)

    # Load existing attack surface
    with open(args.surface) as f:
        surface = json.load(f)

    arjun_params = {}
    total_params = 0

    # Read all Arjun output files
    for fname in Path(args.arjun_dir).glob("*.json"):
        try:
            with open(fname) as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            print(f"[WARN] Could not read {fname}: {e}")
            continue

        # Arjun output format: { "url": [...params...] } or list of {url, params}
        if isinstance(data, dict):
            for endpoint_url, params in data.items():
                if isinstance(params, list):
                    arjun_params[endpoint_url] = params
                    total_params += len(params)
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    ep = item.get("url", item.get("endpoint", ""))
                    params = item.get("params", item.get("parameters", []))
                    if ep and params:
                        arjun_params[ep] = params
                        total_params += len(params)

    if not arjun_params:
        print("[INFO] No Arjun parameters found — nothing to merge")
        sys.exit(0)

    print(f"[INFO] Arjun discovered {total_params} parameters across {len(arjun_params)} endpoints")

    # Merge into surface parameters map
    existing_params = surface.get("parameters", {})
    for endpoint_url, params in arjun_params.items():
        for param in params:
            if param not in existing_params:
                existing_params[param] = []
            if endpoint_url not in existing_params[param]:
                existing_params[param].append(endpoint_url)

    surface["parameters"] = existing_params
    surface["sources"]["arjun"] = total_params
    surface["summary"]["parameters_discovered"] = len(existing_params)

    # Add Arjun-discovered endpoints as findings if they expose sensitive params
    sensitive_params = {
        "debug", "test", "admin", "internal", "token", "key", "secret",
        "password", "passwd", "pass", "auth", "api_key", "apikey",
        "access_token", "redirect", "url", "next", "return", "callback",
        "file", "path", "dir", "cmd", "exec", "shell", "query", "sql",
    }

    arjun_findings = surface.get("findings", [])
    for endpoint_url, params in arjun_params.items():
        sensitive_found = [p for p in params if p.lower() in sensitive_params]
        if sensitive_found:
            arjun_findings.append({
                "id": f"arjun-sensitive-params-{endpoint_url.replace('/', '-').replace(':', '')}",
                "tool": "attack-surface",
                "authenticated": False,
                "title": f"Sensitive Parameters Discovered: {', '.join(sensitive_found[:3])}",
                "severity": "medium",
                "description": (
                    f"Arjun discovered sensitive parameter(s) on {endpoint_url}: "
                    f"{', '.join(sensitive_found)}. These may be undocumented or hidden inputs."
                ),
                "solution": "Review all discovered parameters. Remove debug/internal parameters from production. Validate and sanitize all inputs.",
                "references": "OWASP Testing Guide — OTG-INPVAL-001",
                "affected_urls": [endpoint_url],
                "cwe": "CWE-200",
                "cve": "",
            })

    surface["findings"] = arjun_findings

    with open(args.surface, "w") as f:
        json.dump(surface, f, indent=2)

    print(f"[INFO] Merged {total_params} Arjun parameters into {args.surface}")
    print(f"[INFO] Total parameters in surface map: {len(existing_params)}")


if __name__ == "__main__":
    main()
