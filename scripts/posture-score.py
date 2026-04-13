#!/usr/bin/env python3
"""
posture-score.py
----------------
Calculates a security posture score (0-100) and coverage confidence (0-100)
from summary.json and injects them back into the file.

Formula:
  40% weighted findings score
  25% coverage confidence (which stages ran with real output)
  20% critical control execution
  15% regression trend (placeholder — 100 on first run)

Usage:
    python3 scripts/posture-score.py --summary artifacts/final/summary.json
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone


# ── Severity weights ──────────────────────────────────────────────────────────
SEVERITY_WEIGHTS = {
    "critical": 100,
    "high": 40,
    "medium": 10,
    "low": 3,
    "info": 1,
    "unknown": 0,
}

# ── Stage definitions ─────────────────────────────────────────────────────────
# Each stage: (flag_key, weight, is_critical_control)
STAGES = [
    ("zap_unauth",    1.0, True),
    ("zap_auth",      1.0, True),
    ("nuclei",        1.0, True),
    ("katana",        0.5, False),
    ("ffuf",          0.5, False),
    ("newman",        0.5, True),
    ("auth_bootstrap",1.0, True),
]


def findings_score(stats: dict) -> float:
    """Lower is better — invert to 0-100 where 100 = no findings."""
    raw = sum(
        stats.get(sev, 0) * weight
        for sev, weight in SEVERITY_WEIGHTS.items()
    )
    # Cap at 1000 raw points = score 0, 0 raw = score 100
    capped = min(raw, 1000)
    return round(100 - (capped / 1000 * 100), 1)


def coverage_score(stage_flags: dict) -> float:
    """Score based on how many stages ran with real output."""
    if not stage_flags:
        return 0.0
    total_weight = sum(w for _, w, _ in STAGES)
    earned = 0.0
    for key, weight, _ in STAGES:
        status = stage_flags.get(key, "not_run")
        if status == "passed":
            earned += weight
        elif status == "partial":
            earned += weight * 0.5
    return round((earned / total_weight) * 100, 1)


def critical_control_score(stage_flags: dict) -> float:
    """Score based on critical controls only."""
    critical_stages = [(k, w) for k, w, is_crit in STAGES if is_crit]
    if not critical_stages:
        return 0.0
    total = sum(w for _, w in critical_stages)
    earned = sum(
        w for k, w in critical_stages
        if stage_flags.get(k) in ("passed", "partial")
    )
    return round((earned / total) * 100, 1)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--summary", required=True)
    args = parser.parse_args()

    if not os.path.isfile(args.summary):
        print(f"[ERROR] summary.json not found: {args.summary}", file=sys.stderr)
        sys.exit(1)

    with open(args.summary) as f:
        data = json.load(f)

    stats = data.get("statistics", {})
    stage_flags = data.get("scan_metadata", {}).get("stage_flags", {})
    is_fallback = data.get("scan_metadata", {}).get("is_fallback", False)

    # Calculate component scores
    f_score = findings_score(stats)
    cov_score = coverage_score(stage_flags)
    ctrl_score = critical_control_score(stage_flags)
    regression_score = 100.0  # placeholder — 100 on first run, will compare to prior

    # Weighted posture score
    posture = round(
        (f_score * 0.40) +
        (cov_score * 0.25) +
        (ctrl_score * 0.20) +
        (regression_score * 0.15),
        1
    )

    # Coverage confidence — penalise fallback
    coverage_confidence = cov_score
    if is_fallback:
        coverage_confidence = round(coverage_confidence * 0.3, 1)

    # Risk level
    if posture >= 80:
        risk_level = "LOW"
    elif posture >= 60:
        risk_level = "MEDIUM"
    elif posture >= 40:
        risk_level = "HIGH"
    else:
        risk_level = "CRITICAL"

    posture_data = {
        "posture_score": posture,
        "coverage_confidence": coverage_confidence,
        "risk_level": risk_level,
        "components": {
            "findings_score": f_score,
            "coverage_score": cov_score,
            "critical_control_score": ctrl_score,
            "regression_score": regression_score,
        },
        "is_fallback": is_fallback,
        "calculated_at": datetime.now(timezone.utc).isoformat(),
    }

    data["posture"] = posture_data
    data["scan_metadata"]["posture_score"] = posture
    data["scan_metadata"]["coverage_confidence"] = coverage_confidence
    data["scan_metadata"]["risk_level"] = risk_level

    with open(args.summary, "w") as f:
        json.dump(data, f, indent=2)

    print(f"[INFO] Posture score: {posture}/100 ({risk_level})")
    print(f"[INFO] Coverage confidence: {coverage_confidence}/100")
    print(f"[INFO] Findings score: {f_score} | Coverage: {cov_score} | Controls: {ctrl_score}")


if __name__ == "__main__":
    main()
