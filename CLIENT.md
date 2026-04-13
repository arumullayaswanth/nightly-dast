# DAST Pentest Pipeline — Client Handover Document

**Project:** Nightly DAST / Pentest Regression Pipeline
**Delivered by:** Yaswanth Reddy
**Repository:** https://github.com/arumullayaswanth/nightly-dast

---

## What Was Built

A fully automated, continuous security testing pipeline that runs every night on GitHub Actions. It scans your non-production application using 15+ security tools across 4 phases, produces a consolidated PDF report, uploads everything to AWS S3, and sends a color-coded Slack notification with findings.

No paid tools. No manual effort after setup. Runs at 02:00 UTC every night automatically.

---

## How It Works — Simple View

```
Every night at 2:00 AM (UTC)
         │
         ▼
  GitHub Actions starts
         │
         ├── Checks your app is reachable
         ├── Logs in to your app (if AUTH_ENABLED=true)
         ├── Discovers all routes and endpoints
         ├── Runs 15 security test suites
         ├── Combines all results into one report
         ├── Generates a PDF
         ├── Uploads everything to S3
         └── Sends Slack notification
                    │
          ┌─────────┴──────────┐
          ▼                    ▼
    #security-alerts      #on-call (only if
    (every run)            critical findings)
```

---

## The 4 Phases — What Each One Tests

### Phase 1 — Core DAST (Web Scanning)

| What runs | What it finds |
|---|---|
| **Preflight check** | Confirms your app is reachable before wasting scan time |
| **Auth Bootstrap** (Playwright) | Logs in to your app using a real browser, extracts session cookies and tokens |
| **Katana crawler** | Discovers every page, route, and endpoint by crawling your app |
| **ffuf forced browsing** | Finds hidden/unlinked paths by guessing common names |
| **OWASP ZAP (unauthenticated)** | Full active scan — XSS, SQLi, SSRF, missing headers, session issues |
| **OWASP ZAP (authenticated)** | Same full scan but logged in as a real user — finds issues only visible after login |
| **Nuclei** | Template-based checks for known CVEs, misconfigurations, exposed panels, CORS, CSRF |
| **Newman/Postman** | Runs your API test collection and flags assertion failures as security findings |

### Phase 2 — Authorization & Regression

| What runs | What it finds |
|---|---|
| **Authorization Matrix** | Tests every endpoint as anonymous, user, and admin — finds privilege escalation and missing access controls |
| **Cross-user IDOR tests** | User A tries to access User B's data — finds Broken Object Level Authorization (BOLA/IDOR) |
| **Rate Limit Suite** | Sends rapid bursts to login, reset, signup, and API endpoints — checks if your app throttles abuse |
| **Regression Diff** | Compares this run against the previous one — shows exactly what's new and what's been fixed |
| **Posture Score** | Calculates a 0–100 security score based on findings + coverage + controls + regression trend |

### Phase 3 — Business Logic & Surface

| What runs | What it finds |
|---|---|
| **Business Logic Tests** | Duplicate submissions, negative values, mass assignment, workflow skipping |
| **Race Condition Tests** | Sends parallel requests simultaneously — finds double-spend, double-submit, and state corruption bugs |
| **Attack Surface Inventory** | Maps every discovered route, API endpoint, parameter, form, and high-risk path |
| **Arjun Parameter Discovery** | Finds hidden GET/POST parameters that aren't visible in the UI |
| **OAST / Blind Callbacks** | Detects blind SSRF and blind XSS using out-of-band callback detection (interactsh) |

### Phase 4 — Upload & Browser Security

| What runs | What it finds |
|---|---|
| **File Upload Abuse** | Extension mismatch, null byte injection, oversized files, SVG XSS, path traversal, access control on uploaded files |
| **Frontend Security** | localStorage/sessionStorage token leaks, insecure cookies, CSP weaknesses, clickjacking, mixed content, exposed source maps, hardcoded secrets in JS bundles, internal URLs in JS |

---

## What You Get After Every Run

### 1. summary.json
Machine-readable file with every finding from every tool. Includes severity, description, remediation, affected URLs, CWE, and CVE where applicable.

```json
{
  "scan_metadata": {
    "timestamp": "20260414T020012Z",
    "environment": "staging",
    "targets": ["https://staging.acmecorp.com"],
    "posture_score": 74.5,
    "risk_level": "MEDIUM",
    "coverage_confidence": 85.0
  },
  "statistics": {
    "critical": 0,
    "high": 2,
    "medium": 7,
    "low": 12,
    "info": 34,
    "total": 55
  },
  "findings": [ ... ]
}
```

### 2. summary.pdf
Human-readable PDF report with:
- Executive summary with severity breakdown
- Security posture score and risk level
- Stage execution status (which tools ran)
- All critical and high findings with full details
- Complete findings table for all severities
- Remediation guidance for each finding

### 3. S3 Artifacts
Everything uploaded to your S3 bucket under `dast/<timestamp>/`:
```
dast/20260414T020012Z/
  raw/          ← raw output from every tool
  final/        ← summary.json + summary.pdf
  logs/         ← per-tool logs for troubleshooting
```

### 4. Slack Notification

**Green** — no new critical/high findings, all coverage targets met
**Yellow** — high severity findings, partial coverage, new mediums
**Red** — new critical/high findings, pipeline failure, auth coverage failed

Red alerts also fire to your on-call channel with the top 3 new risks.

---

## Security Posture Score — How It's Calculated

The pipeline calculates a **0–100 posture score** after every run using 4 dimensions:

| Dimension | Weight | What it measures |
|---|---|---|
| Finding severity score | 40% | Weighted count of findings (Critical=100pts, High=40, Medium=10, Low=3, Info=1) |
| Coverage confidence | 25% | How many of the 14 security stages actually ran and produced results |
| Critical control execution | 20% | Did the most important stages run — ZAP auth, authz matrix, rate limit, upload, frontend |
| Regression trend | 15% | Are new findings appearing or are things getting better over time |

**Risk levels:**
- 80–100 → LOW risk
- 60–79 → MEDIUM risk
- 40–59 → HIGH risk
- 0–39 → CRITICAL risk

---

## All Files in the Repository

```
nightly-dast/
│
├── .github/workflows/
│   └── dast-nightly.yml          ← The main pipeline (GitHub Actions)
│
├── scripts/
│   ├── preflight.sh              ← Checks targets are reachable
│   ├── auth-bootstrap.js         ← Playwright login, exports cookies/tokens
│   ├── zap-auth-setup.sh         ← Builds ZAP Automation Framework plan for real auth injection
│   ├── authz-matrix.js           ← Authorization matrix + cross-user IDOR tests
│   ├── rate-limit-test.js        ← Rate limiting and anti-automation tests
│   ├── business-logic-test.js    ← Business logic abuse cases
│   ├── race-condition-test.js    ← Concurrency and race condition tests
│   ├── attack-surface.py         ← Attack surface inventory builder
│   ├── arjun-merge.py            ← Merges Arjun parameter discovery into surface map
│   ├── upload-abuse.js           ← File upload security tests
│   ├── frontend-security.js      ← Browser/JS security tests via Playwright
│   ├── normalize-reports.py      ← Merges all tool outputs into summary.json
│   ├── posture-score.py          ← Calculates security posture score
│   ├── regression-diff.py        ← Compares current run vs prior S3 run
│   ├── generate-pdf.py           ← Renders summary.pdf from summary.json
│   ├── fallback-summary.py       ← Safety net if all tools fail
│   ├── zap-diagnose.py           ← Explains why ZAP failed when it produces no output
│   ├── upload-s3.sh              ← Uploads all artifacts to S3
│   └── slack-notify.sh           ← Sends tiered Slack notification
│
├── configs/
│   ├── zap-config.yaml           ← ZAP rule configuration
│   ├── ffuf-wordlist-small.txt   ← Wordlist for forced browsing
│   └── nuclei-tags.txt           ← Nuclei template tag reference
│
├── docs/
│   └── env-vars.md               ← Complete variable and secret reference
│
├── Readme.md                     ← Project overview
├── DEPLOYMENT.md                 ← Setup guide
└── CLIENT.md                     ← This file
```

---

## Tools Used (All Open Source, No Paid Licenses)

| Tool | Purpose |
|---|---|
| **OWASP ZAP** | Main DAST scanner — active web vulnerability scanning |
| **Nuclei** | Template-based security checks, CVEs, misconfigs, OAST |
| **Playwright** | Headless browser — login automation and frontend security checks |
| **Katana** | Web crawler — discovers all routes and endpoints |
| **ffuf** | Forced browsing — finds hidden paths |
| **Arjun** | Parameter discovery — finds hidden GET/POST parameters |
| **Newman** | Postman collection runner — API security workflow testing |
| **WeasyPrint** | PDF generation from HTML report |
| **AWS CLI** | S3 artifact upload |
| **jq** | JSON processing in shell scripts |

---

## Setup — What You Need to Do Once

### Step 1 — AWS S3 Bucket

Create a private S3 bucket to store scan artifacts:

```
Bucket name: your-security-artifacts
Region:      us-east-1 (or your preferred region)
Access:      Block all public access ON
```

Create an IAM user `dast-pipeline-bot` with this policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:PutObject", "s3:PutObjectAcl", "s3:GetObject", "s3:ListBucket"],
      "Resource": [
        "arn:aws:s3:::your-security-artifacts",
        "arn:aws:s3:::your-security-artifacts/dast/*"
      ]
    },
    {
      "Effect": "Allow",
      "Action": "sts:GetCallerIdentity",
      "Resource": "*"
    }
  ]
}
```

Save the **Access Key ID** and **Secret Access Key**.

### Step 2 — Slack Webhook

1. Go to https://api.slack.com/apps → Create New App → From scratch
2. Name: `DAST Pipeline` → select your workspace
3. Incoming Webhooks → Activate → Add New Webhook → select `#security-alerts`
4. Copy the webhook URL

Optionally create a second webhook for `#on-call` for red-tier escalation.

### Step 3 — GitHub Secrets

Go to your repo → **Settings → Secrets and variables → Actions → Secrets tab**

| Secret | Value |
|---|---|
| `AWS_ACCESS_KEY_ID` | From Step 1 |
| `AWS_SECRET_ACCESS_KEY` | From Step 1 |
| `SLACK_WEBHOOK_URL` | From Step 2 |
| `AUTH_USERNAME` | Your test account email (if app requires login) |
| `AUTH_PASSWORD` | Your test account password (if app requires login) |
| `USER_TOKEN` | Bearer token for a standard user (for authz/IDOR tests) |
| `ADMIN_TOKEN` | Bearer token for an admin user (for privilege escalation tests) |
| `USER_B_TOKEN` | Bearer token for a second user (for cross-user IDOR tests) |
| `SLACK_ONCALL_WEBHOOK` | On-call Slack webhook (optional) |

### Step 4 — GitHub Variables

Go to **Settings → Secrets and variables → Actions → Variables tab**

| Variable | Value |
|---|---|
| `TARGET_URLS` | `https://your-staging-app.com` |
| `S3_BUCKET` | `your-security-artifacts` |
| `ENVIRONMENT` | `staging` |
| `AWS_REGION` | `us-east-1` |
| `AUTH_ENABLED` | `true` (if your app requires login) |
| `AUTH_URL` | `https://your-staging-app.com/login` |
| `AUTH_USERNAME_SELECTOR` | CSS selector for username field e.g. `#email` |
| `AUTH_PASSWORD_SELECTOR` | CSS selector for password field e.g. `#password` |
| `AUTH_SUBMIT_SELECTOR` | CSS selector for submit button e.g. `button[type=submit]` |
| `SESSION_COOKIE_NAME` | Name of session cookie e.g. `connect.sid` |

### Step 5 — Trigger First Run

1. Go to your repo → **Actions** tab
2. Click **Nightly DAST / Pentest Regression**
3. Click **Run workflow → Run workflow**
4. Watch it run — takes 30–90 minutes depending on app size
5. Check Slack for the notification
6. Download the PDF from the Actions artifacts or S3

After this, it runs automatically every night at 02:00 UTC.

---

## How to Read the Slack Notification

```
🔴 DAST Nightly — ACTION REQUIRED — 2 new critical/high findings

Timestamp:       20260414T020012Z    Environment: staging
Posture Score:   61/100  |  Risk: MEDIUM  |  Coverage: 85%
Regression:      Score: 78/100  |  New: 3  |  Fixed: 1

Scanned URL(s):  • https://staging.acmecorp.com

Severity:  🔴 Critical: 0  🟠 High: 2  🟡 Medium: 7  🟢 Low: 12  Total: 55

Tools:  ZAP:18 | Nuclei:5 | Katana:1 | ffuf:12 | Newman:2 |
        AuthZ:3 | RateLimit:2 | BizLogic:4 | Race:1 | Upload:3 | Frontend:4

Stages: ✅ Auth  ✅ ZAP-Auth  ✅ AuthZ  ✅ RateLimit  ✅ BizLogic
        ✅ Race  ✅ Upload  ✅ Frontend

Top New Risks:
• [HIGH] SQL Injection in /api/search (zap)
• [HIGH] No rate limiting on /api/auth/login (rate-limit-test)
• [MEDIUM] localStorage stores auth token (frontend-security)

S3: s3://acmecorp-security-artifacts/dast/20260414T020012Z
```

**Green** = nothing new to worry about, pipeline ran clean
**Yellow** = review needed, some findings or partial coverage
**Red** = action required, check the top new risks immediately

---

## How to Read the PDF Report

The PDF has these sections in order:

1. **Header** — timestamp, environment, targets, pipeline name
2. **Executive Summary** — severity counts, posture score, risk level, coverage confidence
3. **Stage Execution Status** — table showing which of the 14 stages ran (green = passed, orange = partial, grey = not run)
4. **Tools Summary** — how many findings each tool produced
5. **Critical & High Findings** — full detail on the most important issues with remediation steps
6. **All Findings Table** — every finding from every tool with severity, tool, CWE, description, and remediation

---

## How to Customize the Pipeline

**Change scan schedule** — edit `.github/workflows/dast-nightly.yml`:
```yaml
- cron: "0 2 * * *"   # currently 02:00 UTC — change to your preferred time
```

**Add more endpoints to test** — set these variables:
```
AUTHZ_ENDPOINTS    = /api/users,/api/admin,/api/orders,/api/payments
BL_API_ENDPOINTS   = /api/orders,/api/checkout,/api/cart
RACE_ENDPOINTS     = /api/orders,/api/redeem,/api/transfer
```

**Scan multiple targets** — comma-separate in `TARGET_URLS`:
```
TARGET_URLS = https://staging.acmecorp.com,https://api-staging.acmecorp.com
```
Katana, ffuf, Nuclei, and Arjun run against all targets. ZAP runs against the first target.

**Enable AJAX spider for React/Angular/Vue apps**:
```
ZAP_AJAX_SPIDER = true
```

**Tune Nuclei severity**:
```
NUCLEI_SEVERITY = low,medium,high,critical   ← include low findings too
```

---

## Troubleshooting Common Issues

| Symptom | Where to look | Fix |
|---|---|---|
| Pipeline fails at preflight | `logs/preflight.log` | Target URL unreachable from GitHub Actions — check firewall/allowlist |
| Auth bootstrap fails | `logs/auth-bootstrap.log` | Wrong CSS selectors or credentials — inspect login page |
| ZAP produces no report | `logs/zap.log` + `logs/zap-diagnose.log` | Diagnosis is auto-injected into the PDF — read the ZAP diagnostic finding |
| Nuclei finds nothing | `logs/nuclei.log` | Tags or severity filter too restrictive — widen `NUCLEI_TAGS` or `NUCLEI_SEVERITY` |
| S3 upload fails | `logs/s3-upload.log` | IAM policy missing `s3:PutObject` — check the policy in Step 1 |
| Slack not received | `logs/slack.log` | Webhook URL set as Variable not Secret — move it to Secrets |
| PDF blank or missing | `logs/pdf-gen.log` | WeasyPrint font issue — check log for missing font warnings |
| Fallback summary used | `logs/normalize.log` | All scan tools failed — check individual tool logs |
| Regression diff skipped | `logs/regression-diff.log` | First run has no prior data — normal, will work from second run onwards |

---

## Disabling the Pipeline

To pause nightly scans without deleting anything:

1. Go to **Actions → Nightly DAST / Pentest Regression**
2. Click the **...** menu (top right)
3. Click **Disable workflow**

Re-enable the same way when ready to resume.

---

## Summary of Everything Delivered

| Phase | Feature | Status |
|---|---|---|
| Phase 1 | Preflight reachability check | ✅ Done |
| Phase 1 | Playwright auth bootstrap (cookies + tokens) | ✅ Done |
| Phase 1 | Katana endpoint crawling | ✅ Done |
| Phase 1 | ffuf forced browsing | ✅ Done |
| Phase 1 | ZAP unauthenticated full scan | ✅ Done |
| Phase 1 | ZAP authenticated scan (real session injection via AF plan) | ✅ Done |
| Phase 1 | ZAP failure diagnosis (auto root-cause in PDF) | ✅ Done |
| Phase 1 | Nuclei template scan | ✅ Done |
| Phase 1 | Newman API workflow + normalized into report | ✅ Done |
| Phase 1 | Hard fail if fallback summary used | ✅ Done |
| Phase 1 | Stage execution flags in summary.json | ✅ Done |
| Phase 2 | Authorization matrix (anonymous / user / admin) | ✅ Done |
| Phase 2 | Cross-user IDOR / BOLA tests (User A vs User B) | ✅ Done |
| Phase 2 | Rate limit suite (login, reset, signup, API burst, 429 checks) | ✅ Done |
| Phase 2 | Regression diff (new vs fixed vs prior S3 run) | ✅ Done |
| Phase 2 | Security posture score 0–100 (4 dimensions) | ✅ Done |
| Phase 2 | Coverage confidence 0–100 | ✅ Done |
| Phase 3 | Business logic tests (duplicate submit, negative values, mass assignment, workflow skipping) | ✅ Done |
| Phase 3 | Race condition / concurrency tests | ✅ Done |
| Phase 3 | Attack surface inventory (routes, API, high-risk, params, forms) | ✅ Done |
| Phase 3 | Arjun parameter discovery | ✅ Done |
| Phase 3 | OAST / interactsh blind SSRF and blind XSS detection | ✅ Done |
| Phase 4 | File upload abuse suite (9 tests) | ✅ Done |
| Phase 4 | Frontend / browser security suite (9 Playwright tests) | ✅ Done |
| Phase 4 | Slack tiered routing Red / Yellow / Green | ✅ Done |
| Phase 4 | Top-3 new risks in Slack | ✅ Done |
| Phase 4 | Failed stage list in Slack | ✅ Done |
| Phase 4 | On-call escalation (SLACK_ONCALL_WEBHOOK) | ✅ Done |
| Reporting | Consolidated summary.json (all tools, all phases) | ✅ Done |
| Reporting | PDF report with posture score, stage status, all findings | ✅ Done |
| Reporting | S3 upload with timestamped folder structure | ✅ Done |
| Docs | Complete env-vars.md with examples for every variable | ✅ Done |
| Docs | Deployment guide | ✅ Done |
| Docs | This client handover document | ✅ Done |

**Total scripts delivered: 19**
**Total pipeline stages: 21**
**Total security test cases: 60+**
**Tools integrated: 10**
**All open source. No paid licenses required.**
