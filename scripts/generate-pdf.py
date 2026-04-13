#  renders summary.json → summary.pdf
#!/usr/bin/env python3
"""
generate-pdf.py
Reads summary.json and produces a human-readable summary.pdf report
using Jinja2 for HTML templating and WeasyPrint for PDF rendering.

Usage:
    python3 generate-pdf.py \
        --input artifacts/final/summary.json \
        --output artifacts/final/summary.pdf
"""

import argparse
import json
import os
import sys
from datetime import datetime

try:
    from jinja2 import Environment, BaseLoader
    from weasyprint import HTML
except ImportError:
    print("[ERROR] Missing dependencies. Run: pip install jinja2 weasyprint", file=sys.stderr)
    sys.exit(1)

# ── HTML template ─────────────────────────────────────────────────────────────

REPORT_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>DAST Security Scan Report — {{ meta.timestamp }}</title>
<style>
  body { font-family: Arial, sans-serif; font-size: 11px; color: #222; margin: 40px; }
  h1 { color: #c0392b; border-bottom: 2px solid #c0392b; padding-bottom: 6px; }
  h2 { color: #2c3e50; margin-top: 30px; }
  h3 { color: #34495e; margin-top: 20px; font-size: 12px; }
  table { width: 100%; border-collapse: collapse; margin-top: 10px; }
  th { background: #2c3e50; color: #fff; padding: 6px 8px; text-align: left; font-size: 10px; }
  td { padding: 5px 8px; border-bottom: 1px solid #ddd; vertical-align: top; font-size: 10px; }
  tr:nth-child(even) { background: #f9f9f9; }
  .badge { display: inline-block; padding: 2px 6px; border-radius: 3px; font-weight: bold;
           font-size: 9px; text-transform: uppercase; }
  .critical { background: #c0392b; color: #fff; }
  .high     { background: #e67e22; color: #fff; }
  .medium   { background: #f1c40f; color: #333; }
  .low      { background: #27ae60; color: #fff; }
  .info     { background: #2980b9; color: #fff; }
  .unknown  { background: #95a5a6; color: #fff; }
  .stat-box { display: inline-block; width: 80px; text-align: center; padding: 8px;
              margin: 4px; border-radius: 5px; }
  .stat-num { font-size: 22px; font-weight: bold; }
  .stat-lbl { font-size: 9px; text-transform: uppercase; }
  .meta-table td { border: none; padding: 3px 8px; }
  .finding-block { border: 1px solid #ddd; border-radius: 4px; padding: 10px;
                   margin-bottom: 12px; page-break-inside: avoid; }
  .url-list { font-family: monospace; font-size: 9px; color: #555; }
  .desc-cell { max-width: 200px; word-wrap: break-word; }
  .section-divider { border: none; border-top: 1px solid #eee; margin: 20px 0; }
  .tool-table td { font-size: 11px; padding: 5px 10px; }
  @page { margin: 1.5cm; size: A4 landscape; }
</style>
</head>
<body>

<h1>DAST Security Scan Report</h1>

<table class="meta-table">
  <tr><td><strong>Timestamp:</strong></td><td>{{ meta.timestamp }}</td></tr>
  <tr><td><strong>Environment:</strong></td><td>{{ meta.environment }}</td></tr>
  <tr><td><strong>Targets:</strong></td><td>{{ meta.targets | join(", ") }}</td></tr>
  <tr><td><strong>Pipeline:</strong></td><td>{{ meta.pipeline }}</td></tr>
  <tr><td><strong>Generated:</strong></td><td>{{ meta.generated_at }}</td></tr>
</table>

<h2>Executive Summary</h2>

{% if meta.zap_status and not meta.zap_status.completed %}
<div style="background:#fff3cd; border:1px solid #ffc107; border-radius:4px; padding:12px; margin:10px 0;">
  <strong>⚠️ ZAP Scan Incomplete</strong><br>
  <strong>Reason:</strong> {{ meta.zap_status.reason }}<br>
  <strong>Target:</strong> {{ meta.zap_status.target }}<br>
  <em>See the diagnostic finding below for details and recommended fix.</em>
</div>
{% endif %}

<div>
  <div class="stat-box critical"><div class="stat-num">{{ stats.critical }}</div><div class="stat-lbl">Critical</div></div>
  <div class="stat-box high"><div class="stat-num">{{ stats.high }}</div><div class="stat-lbl">High</div></div>
  <div class="stat-box medium"><div class="stat-num">{{ stats.medium }}</div><div class="stat-lbl">Medium</div></div>
  <div class="stat-box low"><div class="stat-num">{{ stats.low }}</div><div class="stat-lbl">Low</div></div>
  <div class="stat-box info"><div class="stat-num">{{ stats.info }}</div><div class="stat-lbl">Info</div></div>
</div>
<p><strong>Total findings: {{ stats.total }}</strong></p>

{% if posture %}
<table class="meta-table" style="margin-top:10px;">
  <tr>
    <td><strong>Posture Score:</strong></td>
    <td><strong style="font-size:16px;">{{ posture.posture_score }}/100</strong></td>
    <td><strong>Risk Level:</strong></td>
    <td><strong>{{ posture.risk_level }}</strong></td>
    <td><strong>Coverage Confidence:</strong></td>
    <td>{{ posture.coverage_confidence }}%</td>
  </tr>
</table>
{% endif %}

{% if meta.stage_flags %}
<h2>Stage Execution Status</h2>
<table class="tool-table">
  <thead><tr><th>Stage</th><th>Status</th></tr></thead>
  <tbody>
  {% for stage, status in meta.stage_flags.items() %}
    <tr>
      <td>{{ stage }}</td>
      <td style="color: {% if status == 'passed' %}green{% elif status == 'partial' %}orange{% elif status == 'not_run' %}grey{% else %}red{% endif %}">
        {{ status }}
      </td>
    </tr>
  {% endfor %}
  </tbody>
</table>
{% endif %}

<h2>Tools Summary</h2>
<table class="tool-table">
  <thead>
    <tr><th>Tool</th><th>Findings</th><th>Status</th><th>Scanned URL(s)</th></tr>
  </thead>
  <tbody>
  {% for tool, count in tool_counts.items() %}
    <tr>
      <td>{{ tool }}</td>
      <td><strong>{{ count }}</strong></td>
      <td>{% if count > 0 %}✅ Findings detected{% else %}✔ No findings detected{% endif %}</td>
      <td class="url-list">{{ meta.targets | join(", ") }}</td>
    </tr>
  {% endfor %}
  </tbody>
</table>

{% if critical_and_high %}
<h2>Critical &amp; High Severity Findings</h2>
{% for f in critical_and_high %}
<div class="finding-block">
  <h3>
    <span class="badge {{ f.severity }}">{{ f.severity }}</span>
    &nbsp;{{ f.title }}
    <small style="color:#888; font-weight:normal;">[{{ f.tool }}{% if f.authenticated %} / authenticated{% endif %}]</small>
  </h3>
  {% if f.description %}<p><strong>Description:</strong> {{ f.description }}</p>{% endif %}
  {% if f.solution %}<p><strong>Remediation:</strong> {{ f.solution }}</p>{% endif %}
  {% if f.cwe %}<p><strong>CWE:</strong> {{ f.cwe }}</p>{% endif %}
  {% if f.get('cve') %}<p><strong>CVE:</strong> {{ f.cve }}</p>{% endif %}
  {% if f.references %}<p><strong>References:</strong> {{ f.references }}</p>{% endif %}
  {% if f.affected_urls %}
  <p><strong>Affected URLs:</strong></p>
  <div class="url-list">
    {% for url in f.affected_urls[:10] %}{{ url }}<br>{% endfor %}
    {% if f.affected_urls | length > 10 %}<em>... and {{ f.affected_urls | length - 10 }} more</em>{% endif %}
  </div>
  {% endif %}
</div>
{% endfor %}
{% endif %}

<hr class="section-divider">

<h2>All Findings</h2>
<table>
  <thead>
    <tr>
      <th>Severity</th>
      <th>Title</th>
      <th>Tool</th>
      <th>Auth</th>
      <th>Affected URLs (sample)</th>
      <th>CWE</th>
      <th>CVE</th>
      <th>Description</th>
      <th>Remediation</th>
    </tr>
  </thead>
  <tbody>
  {% for f in findings %}
    <tr>
      <td><span class="badge {{ f.severity }}">{{ f.severity }}</span></td>
      <td>{{ f.title }}</td>
      <td>{{ f.tool }}</td>
      <td>{{ "Yes" if f.authenticated else "No" }}</td>
      <td class="url-list">
        {% for url in f.affected_urls[:3] %}{{ url }}<br>{% endfor %}
        {% if f.affected_urls | length > 3 %}+{{ f.affected_urls | length - 3 }} more{% endif %}
      </td>
      <td>{{ f.cwe or "—" }}</td>
      <td>{{ f.get("cve", "—") }}</td>
      <td class="desc-cell">{{ (f.description or "—")[:200] }}{% if (f.description or "") | length > 200 %}...{% endif %}</td>
      <td class="desc-cell">{{ (f.solution or "—")[:200] }}{% if (f.solution or "") | length > 200 %}...{% endif %}</td>
    </tr>
  {% endfor %}
  </tbody>
</table>

<hr class="section-divider">
<p style="color:#aaa; font-size:9px; text-align:center;">
  Generated by DAST Nightly Pipeline &mdash; {{ meta.generated_at }} &mdash;
  For approved non-production targets only.
</p>

</body>
</html>
"""


def main():
    parser = argparse.ArgumentParser(description="Generate PDF report from summary.json")
    parser.add_argument("--input", required=True, help="Path to summary.json")
    parser.add_argument("--output", required=True, help="Path for output summary.pdf")
    args = parser.parse_args()

    if not os.path.isfile(args.input):
        print(f"[ERROR] Input file not found: {args.input}", file=sys.stderr)
        sys.exit(1)

    with open(args.input) as f:
        data = json.load(f)

    meta = data.get("scan_metadata", {})
    stats = data.get("statistics", {})
    findings = data.get("findings", [])
    posture = data.get("posture", {})

    critical_and_high = [f for f in findings if f.get("severity") in ("critical", "high")]

    # Always show all pipeline tools, even if they found 0 findings
    ALL_TOOLS = {
        "zap":              "OWASP ZAP (DAST Scanner)",
        "nuclei":           "Nuclei (Security Regression)",
        "katana":           "Katana (Endpoint Discovery)",
        "ffuf":             "ffuf (Forced Browsing)",
        "newman":           "Newman (API Workflow)",
        "authz-matrix":     "AuthZ Matrix (Access Control)",
        "rate-limit-test":  "Rate Limit Testing",
        "business-logic":   "Business Logic Testing",
        "race-condition":   "Race Condition Testing",
        "attack-surface":   "Attack Surface Inventory",
        "upload-abuse":     "File Upload Abuse Testing",
        "frontend-security":"Frontend / Browser Security",
    }
    tool_counts = {label: 0 for label in ALL_TOOLS.values()}
    for f in findings:
        tool = f.get("tool", "unknown")
        label = ALL_TOOLS.get(tool, tool)
        tool_counts[label] = tool_counts.get(label, 0) + 1

    env = Environment(loader=BaseLoader())
    template = env.from_string(REPORT_TEMPLATE)
    html_content = template.render(
        meta=meta,
        stats=stats,
        findings=findings,
        critical_and_high=critical_and_high,
        tool_counts=tool_counts,
        posture=posture,
    )

    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    HTML(string=html_content).write_pdf(args.output)
    print(f"[INFO] PDF report written to {args.output}")


if __name__ == "__main__":
    main()
