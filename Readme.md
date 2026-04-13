# Nightly DAST / Pentest Regression Pipeline

A fully automated, CI/CD-driven security testing pipeline built on GitHub Actions. Runs nightly against approved non-production targets, produces consolidated machine-readable and human-readable reports, uploads all artifacts to AWS S3, and sends a Slack notification on completion.

> **Scope:** Approved non-production environments only. This pipeline supports continuous pentest regression and does not replace manual testing for business logic, complex authorization, or chained attack scenarios.

---

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Pipeline Flow](#pipeline-flow)
- [Project Structure](#project-structure)
- [Tools Used](#tools-used)
- [Quick Start](#quick-start)
- [Configuration Reference](#configuration-reference)
- [Artifact Structure](#artifact-structure)
- [Report Samples](#report-samples)
- [Authenticated Scan Setup](#authenticated-scan-setup)
- [Customization](#customization)
- [Troubleshooting](#troubleshooting)
- [Security Notes](#security-notes)

---

## Architecture Overview

```
GitHub Actions (nightly cron)
        │
        ▼
┌───────────────────────────────────────────────────────┐
│                   DAST Pipeline Job                   │
│                                                       │
│  1.  Pre-flight        → curl reachability checks     │
│  2.  Auth Bootstrap    → Playwright login (optional)  │
│  3.  Discovery         → Katana crawl + ffuf fuzz     │
│  4.  Newman            → API workflow setup           │
│  5.  ZAP Scan          → Unauthenticated full scan    │
│  6.  ZAP Auth Scan     → Real authenticated scan ✅   │
│  7.  ZAP Diagnosis     → Root-cause if ZAP fails      │
│  8.  Nuclei Scan       → Supplemental regression      │
│  9.  AuthZ Matrix      → anonymous/user/admin checks  │
│  10. Rate Limit Suite  → 429/throttle/lockout tests   │
│  11. Business Logic    → abuse-case test suite        │
│  12. Race Conditions   → concurrency/parallel tests   │
│  13. Attack Surface    → route/param inventory        │
│  14. Upload Abuse      → file upload security suite   │
│  15. Frontend Security → browser/JS security suite    │
│  16. Normalize         → Unified summary.json         │
│  17. Posture Score     → 0-100 security posture       │
│  18. Regression Diff   → new vs fixed findings        │
│  19. PDF Report        → summary.pdf                  │
│  20. S3 Upload         → dast/<timestamp>/            │
│  21. Slack Notify      → Tiered Red/Yellow/Green      │
└───────────────────────────────────────────────────────┘
        │                          │
        ▼                          ▼
   AWS S3 Bucket             Slack Channel(s)
   dast/<timestamp>/         #security-alerts + on-call
```

---

## Pipeline Flow

| Step | Tool | Purpose |
|---|---|---|
| Pre-flight | `curl` | Validates all target URLs are reachable before wasting scan time |
| Auth Bootstrap | Playwright (Chromium) | Headless browser login — exports session cookies and Bearer tokens |
| Endpoint Discovery | Katana | Crawls targets up to configurable depth, discovers all reachable endpoints |
| Forced Browsing | ffuf | Fuzzes common paths against a wordlist to find hidden/unlinked endpoints |
| API Workflow | Newman/Postman | Runs Postman collections for API auth setup and workflow testing |
| DAST Scan | OWASP ZAP | Full active scan — XSS, SQLi, SSRF, security headers, session issues |
| Authenticated DAST | OWASP ZAP (Automation Framework) | Real authenticated scan using ZAP AF plan with injected Playwright session |
| ZAP Diagnosis | Python | Detects and explains ZAP failure root cause when no reports are produced |
| Regression Checks | Nuclei | Template-based checks for CVEs, misconfigs, exposed panels, CORS, CSRF |
| AuthZ Matrix | Node.js | Tests anonymous/user/admin access across all endpoints — IDOR/BOLA/BFLA |
| Rate Limit Suite | Node.js | Tests login throttling, reset abuse, signup throttling, 429/Retry-After |
| Business Logic | Node.js | Duplicate submit, negative values, mass assignment, workflow skipping |
| Race Conditions | Node.js | Parallel request concurrency testing for double-submit and state races |
| Attack Surface | Python | Aggregates Katana/ffuf/ZAP into route inventory with high-risk tagging |
| Upload Abuse | Node.js | Extension mismatch, null byte, oversized, SVG XSS, path traversal, access control |
| Frontend Security | Playwright | Storage leaks, cookie flags, CSP depth, clickjacking, source maps, JS secrets |
| Normalization | Python | Merges all raw outputs into a single unified `summary.json` |
| Posture Score | Python | 4-dimension security posture score (0-100) with coverage confidence |
| Regression Diff | Python | Compares against prior S3 run — new vs fixed findings |
| PDF Generation | WeasyPrint | Renders a styled HTML report to `summary.pdf` |
| S3 Upload | AWS CLI | Uploads all raw reports, final reports, and logs under a timestamped S3 path |
| Slack Notification | Webhook | Tiered Red/Yellow/Green with top-3 risks, failed stages, on-call escalation |

---

## Project Structure

```
.
├── .github/
│   └── workflows/
│       └── dast-nightly.yml        # Main GitHub Actions workflow
├── configs/
│   ├── zap-config.yaml             # OWASP ZAP rule configuration
│   ├── nuclei-tags.txt             # Nuclei tag reference (documentation)
│   └── ffuf-wordlist-small.txt     # Wordlist for forced browsing
├── scripts/
│   ├── preflight.sh                # Target reachability validation
│   ├── auth-bootstrap.js           # Playwright authenticated login
│   ├── zap-auth-setup.sh           # ZAP Automation Framework plan builder (real auth injection)
│   ├── authz-matrix.js             # Phase 2 — authorization matrix testing
│   ├── rate-limit-test.js          # Phase 2 — rate limiting & anti-automation
│   ├── regression-diff.py          # Phase 2 — new vs fixed findings comparison
│   ├── posture-score.py            # Phase 2 — security posture score (0-100)
│   ├── business-logic-test.js      # Phase 3 — business logic abuse cases
│   ├── race-condition-test.js      # Phase 3 — concurrency & race condition tests
│   ├── attack-surface.py           # Phase 3 — attack surface inventory
│   ├── upload-abuse.js             # Phase 4 — file upload abuse testing
│   ├── frontend-security.js        # Phase 4 — browser/JS security suite
│   ├── normalize-reports.py        # Raw output → unified summary.json
│   ├── generate-pdf.py             # summary.json → summary.pdf
│   ├── fallback-summary.py         # Safety net if all tools fail
│   ├── zap-diagnose.py             # ZAP failure root-cause diagnosis
│   ├── upload-s3.sh                # S3 artifact upload
│   └── slack-notify.sh             # Tiered Slack notification (Red/Yellow/Green)
└── docs/
    └── env-vars.md                 # Full environment variable reference
```

---

## Tools Used

| Tool | Version | Purpose |
|---|---|---|
| [OWASP ZAP](https://www.zaproxy.org/) | `stable` (Docker) | Main DAST scanning engine (unauth + real authenticated via AF plan) |
| [Playwright](https://playwright.dev/) | Latest | Auth bootstrap + frontend/browser security suite |
| [Nuclei](https://github.com/projectdiscovery/nuclei) | Latest | Supplemental template-based security regression |
| [Katana](https://github.com/projectdiscovery/katana) | Latest | Endpoint and route discovery / crawling |
| [ffuf](https://github.com/ffuf/ffuf) | Latest | Forced browsing and path fuzzing |
| [Newman](https://github.com/postmanlabs/newman) | Latest | Postman collection runner for API workflows |
| [WeasyPrint](https://weasyprint.org/) | Latest | HTML-to-PDF report rendering |
| AWS CLI | v2 | S3 artifact upload |
| jq | System | JSON processing in shell scripts |

All tools are **open-source** and require no paid licenses.

---

## Quick Start

### 1. Fork / clone this repository

```bash
git clone https://github.com/your-org/dast-pipeline.git
cd dast-pipeline
```

### 2. Set GitHub Actions Secrets

Go to **Settings → Secrets and variables → Actions → Secrets** and add:

| Secret | Value |
|---|---|
| `AWS_ACCESS_KEY_ID` | Your AWS IAM access key |
| `AWS_SECRET_ACCESS_KEY` | Your AWS IAM secret key |
| `SLACK_WEBHOOK_URL` | Your Slack Incoming Webhook URL |

### 3. Set GitHub Actions Variables

Go to **Settings → Secrets and variables → Actions → Variables** and add:

| Variable | Example Value |
|---|---|
| `TARGET_URLS` | `https://staging.example.com,https://api-staging.example.com` |
| `S3_BUCKET` | `my-security-artifacts` |

### 4. Run the pipeline

The pipeline runs automatically every night at **02:00 UTC**.

To trigger manually: **Actions → Nightly DAST / Pentest Regression → Run workflow**

---

## Configuration Reference

See [`docs/env-vars.md`](docs/env-vars.md) for the full reference. Key variables:

### Required

| Name | Type | Description |
|---|---|---|
| `TARGET_URLS` | Variable | Comma-separated list of target URLs |
| `S3_BUCKET` | Variable | S3 bucket for artifact storage |
| `AWS_ACCESS_KEY_ID` | Secret | AWS credentials |
| `AWS_SECRET_ACCESS_KEY` | Secret | AWS credentials |
| `SLACK_WEBHOOK_URL` | Secret | Slack notification endpoint |

### Scan Tuning

| Name | Default | Description |
|---|---|---|
| `NUCLEI_TAGS` | `cve,ssrf,xss,sqli,rce,misconfig,exposure,headers,session` | Nuclei template tags |
| `NUCLEI_SEVERITY` | `medium,high,critical` | Minimum severity to report |
| `KATANA_DEPTH` | `3` | Crawler depth |
| `FFUF_RATE` | `50` | Requests/sec for ffuf |
| `PREFLIGHT_TIMEOUT` | `10` | Seconds per target reachability check |

### Authenticated Scans

| Name | Default | Description |
|---|---|---|
| `AUTH_ENABLED` | `false` | Set `true` to enable auth flow |
| `AUTH_URL` | — | Login page URL |
| `AUTH_USERNAME` *(secret)* | — | Login username |
| `AUTH_PASSWORD` *(secret)* | — | Login password |
| `AUTH_USERNAME_SELECTOR` | `#username` | CSS selector for username field |
| `AUTH_PASSWORD_SELECTOR` | `#password` | CSS selector for password field |
| `AUTH_SUBMIT_SELECTOR` | `[type=submit]` | CSS selector for submit button |
| `SESSION_COOKIE_NAME` | `session` | Session cookie name to validate |

---

## Artifact Structure

Every scan run produces a timestamped folder in S3:

```
s3://<S3_BUCKET>/dast/<YYYYMMDDTHHMMSSZ>/
├── raw/
│   ├── zap/
│   │   ├── zap-report.json          # ZAP unauthenticated (machine-readable)
│   │   ├── zap-report.html          # ZAP unauthenticated (human-readable)
│   │   ├── zap-report.xml           # ZAP unauthenticated (XML)
│   │   ├── zap-auth-report.json     # ZAP authenticated (if AUTH_ENABLED)
│   │   └── zap-auth-report.html     # ZAP authenticated (if AUTH_ENABLED)
│   ├── nuclei/
│   │   ├── nuclei-report.json       # Nuclei findings (JSONL)
│   │   └── nuclei-report.txt        # Nuclei findings (plain text)
│   ├── katana/
│   │   └── <target>.txt             # Discovered endpoints per target
│   ├── ffuf/
│   │   └── <target>.json            # ffuf results per target
│   └── newman/
│       └── newman-report.json       # Newman API run (if configured)
├── final/
│   ├── summary.json                 # Consolidated unified findings report
│   └── summary.pdf                  # Human-readable PDF summary
└── logs/
    ├── preflight.log
    ├── auth-bootstrap.log
    ├── katana.log
    ├── ffuf.log
    ├── zap.log
    ├── zap-auth.log
    ├── nuclei.log
    ├── normalize.log
    ├── pdf-gen.log
    ├── s3-upload.log
    └── slack.log
```

Artifacts are also retained in GitHub Actions for **30 days** under the run's artifact tab.

---

## Report Samples

### summary.json schema

```json
{
  "scan_metadata": {
    "timestamp": "20240315T020012Z",
    "environment": "non-production",
    "targets": ["https://staging.example.com"],
    "pipeline": "github-actions-dast-nightly",
    "generated_at": "2024-03-15T02:14:33+00:00"
  },
  "statistics": {
    "critical": 0,
    "high": 2,
    "medium": 7,
    "low": 12,
    "info": 34,
    "unknown": 0,
    "total": 55
  },
  "findings": [
    {
      "id": "zap-10038",
      "tool": "zap",
      "authenticated": false,
      "title": "Content Security Policy (CSP) Header Not Set",
      "severity": "medium",
      "description": "...",
      "solution": "...",
      "affected_urls": ["https://staging.example.com/"],
      "cwe": "693"
    }
  ]
}
```

### Slack Notification

```
🔴  DAST Nightly Scan — Completed with critical/high findings

Timestamp:    20240315T020012Z     Environment: non-production
Targets:      • https://staging.example.com
Findings:     🔴 Critical: 0  🟠 High: 2  🟡 Medium: 7  🟢 Low: 12  📊 Total: 55
S3 Artifacts: s3://my-security-artifacts/dast/20240315T020012Z
```

---

## Authenticated Scan Setup

When `AUTH_ENABLED=true`, the pipeline:

1. Launches a headless Chromium browser via Playwright
2. Navigates to `AUTH_URL`
3. Fills in credentials using the configured CSS selectors
4. Waits for post-login navigation
5. Extracts session cookies → `/tmp/zap-session.txt`
6. Extracts Bearer token from response body or `localStorage` → `/tmp/auth-token.txt`
7. Passes the session to ZAP for the authenticated scan

**For non-standard login flows** (MFA, OAuth, custom JS), edit `scripts/auth-bootstrap.js` directly — it's plain Playwright and fully customizable.

---

## Customization

**Change scan schedule:**
Edit the cron in `.github/workflows/dast-nightly.yml`:
```yaml
- cron: "0 2 * * *"   # currently 02:00 UTC daily
```

**Add more Nuclei templates:**
Update the `NUCLEI_TAGS` variable or pass a custom templates directory by modifying the Nuclei step in the workflow.

**Use a larger ffuf wordlist:**
Set `FFUF_WORDLIST` to point to a larger wordlist file committed to the repo, or reference a URL. [SecLists](https://github.com/danielmiessler/SecLists) is a good source.

**Scan multiple targets with ZAP:**
Currently ZAP scans the first URL in `TARGET_URLS`. To scan all targets, duplicate the ZAP steps in the workflow with a loop (same pattern as the Katana/ffuf steps).

**Add ZAP authentication scripts:**
Place a ZAP `.js` or `.zst` auth script in `configs/` and reference it via `ZAP_AUTH_SCRIPT`.

---

## Troubleshooting

| Symptom | Check |
|---|---|
| Pipeline fails at pre-flight | Target URL is unreachable from GitHub Actions runners. Check firewall/allowlist rules. |
| Auth bootstrap fails | Inspect `artifacts/logs/auth-bootstrap.log`. Verify CSS selectors match the login form. |
| ZAP produces empty report | Check `artifacts/logs/zap.log`. ZAP may have timed out or the target blocked the scanner. |
| Nuclei finds nothing | Verify `NUCLEI_TAGS` and `NUCLEI_SEVERITY` are not too restrictive. Check `nuclei.log`. |
| S3 upload fails | Verify IAM permissions. The key needs `s3:PutObject` on `arn:aws:s3:::BUCKET/dast/*`. |
| Slack notification not received | Verify `SLACK_WEBHOOK_URL` is set as a secret (not a variable). Check `slack.log`. |
| PDF generation fails | WeasyPrint requires system fonts. Check `pdf-gen.log` for missing font warnings. |

All logs are available in:
- GitHub Actions run → step output (real-time)
- `artifacts/logs/` folder in the uploaded artifact
- `s3://<bucket>/dast/<timestamp>/logs/` after upload

---

## Security Notes

- All credentials are passed via GitHub Actions **Secrets** — never committed to the repository
- The pipeline targets **approved non-production environments only**
- Rate limiting is applied to all scanning tools (`FFUF_RATE`, `NUCLEI_RATE`) to avoid disrupting target services
- ZAP is configured via `configs/zap-config.yaml` to suppress noisy low-value rules
- The minimum required IAM policy for S3 upload is scoped to `dast/*` only:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:PutObject", "s3:PutObjectAcl"],
      "Resource": "arn:aws:s3:::YOUR-BUCKET-NAME/dast/*"
    }
  ]
}
```

---

## Acceptance Criteria Checklist

- [x] Pipeline runs nightly from GitHub Actions without manual intervention
- [x] Target URLs are sourced from GitHub Actions environment variables
- [x] Authenticated flows supported via Playwright session bootstrap
- [x] Authenticated ZAP scan uses real session injection via ZAP Automation Framework
- [x] Newman findings normalized into summary.json and counted in Slack
- [x] Authorization matrix tests anonymous/user/admin access (IDOR/BOLA/BFLA)
- [x] Rate limiting suite tests login throttling, reset abuse, 429/Retry-After
- [x] Business logic suite tests duplicate submit, negative values, mass assignment, workflow skipping
- [x] Race condition suite tests parallel request concurrency
- [x] Attack surface inventory aggregates all discovered routes with high-risk tagging
- [x] File upload abuse suite tests extension mismatch, null byte, SVG XSS, path traversal, access control
- [x] Frontend security suite tests storage leaks, cookie flags, CSP depth, source maps, JS secrets
- [x] Consolidated `summary.json` generated from all tool outputs (all phases)
- [x] Security posture score (0-100) with coverage confidence calculated
- [x] Regression diff compares new vs fixed findings against prior S3 run
- [x] `summary.pdf` generated from consolidated JSON with all phases
- [x] Reports uploaded to AWS S3 under `dast/` prefix with timestamp
- [x] Slack notification tiered Red/Yellow/Green with top-3 risks, failed stages, on-call escalation
- [x] Hard fail if fallback summary is used (no silent zero-finding success)
- [x] Workflow logs and artifacts sufficient for troubleshooting failed runs
- [x] Solution is open-source-first — no paid scanners required

---

*Built with OWASP ZAP · Nuclei · Katana · ffuf · Playwright · Newman · WeasyPrint · AWS CLI*
