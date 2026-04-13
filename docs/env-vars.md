# Environment Variables & Secrets Reference

All configuration is passed via GitHub Actions **Variables** (`vars.*`) and **Secrets** (`secrets.*`).
Set these under **Settings → Secrets and variables → Actions** in your repository.

---

## Required Secrets

| Secret | Description |
|---|---|
| `AWS_ACCESS_KEY_ID` | AWS IAM access key with `s3:PutObject` on the target bucket |
| `AWS_SECRET_ACCESS_KEY` | Corresponding AWS secret key |
| `SLACK_WEBHOOK_URL` | Slack Incoming Webhook URL |

## Required Variables

| Variable | Description | Example |
|---|---|---|
| `TARGET_URLS` | Comma-separated approved non-production target URLs | `https://staging.example.com,https://api-staging.example.com` |
| `S3_BUCKET` | S3 bucket name for artifact storage | `my-security-artifacts` |

---

## Optional — General

| Variable | Default | Description |
|---|---|---|
| `ENVIRONMENT` | `non-production` | Environment label used in reports and Slack notifications |
| `AWS_REGION` | `us-east-1` | AWS region for S3 uploads |
| `PREFLIGHT_TIMEOUT` | `10` | Seconds to wait per target during reachability check |


---

## Optional — Auth Bootstrap (Playwright)

| Variable / Secret | Default | Description |
|---|---|---|
| `AUTH_ENABLED` | `false` | Set to `true` to enable authenticated scan flow |
| `AUTH_URL` | — | Login page URL |
| `AUTH_USERNAME` *(secret)* | — | Login username or email |
| `AUTH_PASSWORD` *(secret)* | — | Login password |
| `AUTH_USERNAME_SELECTOR` | `#username` | CSS selector for the username input field |
| `AUTH_PASSWORD_SELECTOR` | `#password` | CSS selector for the password input field |
| `AUTH_SUBMIT_SELECTOR` | `[type=submit]` | CSS selector for the login submit button |
| `SESSION_COOKIE_NAME` | `session` | Name of the session cookie to validate post-login |

---

## Optional — Discovery

| Variable | Default | Description |
|---|---|---|
| `KATANA_DEPTH` | `3` | Crawl depth for Katana endpoint discovery |
| `FFUF_WORDLIST` | `configs/ffuf-wordlist-small.txt` | Path to wordlist for ffuf forced browsing |
| `FFUF_RATE` | `50` | Requests per second limit for ffuf |

---

## Optional — Nuclei

| Variable | Default | Description |
|---|---|---|
| `NUCLEI_TAGS` | `cve,ssrf,xss,sqli,rce,misconfig,exposure,headers,session` | Comma-separated Nuclei template tags to run |
| `NUCLEI_SEVERITY` | `medium,high,critical` | Minimum severity filter for Nuclei findings |
| `NUCLEI_RATE` | `50` | Requests per second limit for Nuclei |

---

## Optional — ZAP

| Variable | Default | Description |
|---|---|---|
| `ZAP_AJAX_SPIDER` | `false` | Enable ZAP AJAX spider (slower, better JS coverage) |

---

## Optional — Newman / Postman

| Variable | Default | Description |
|---|---|---|
| `NEWMAN_COLLECTION` | — | Path or URL to a Postman collection JSON file |
| `NEWMAN_ENV_FILE` | — | Path to a Postman environment file |
| `API_TOKEN` *(secret)* | — | Bearer token injected into Newman runs |

---

## Artifact Structure in S3

```
s3://<S3_BUCKET>/dast/<TIMESTAMP>/
  raw/
    zap/
      zap-report.json
      zap-report.html
      zap-report.xml
      zap-auth-report.json      # only if AUTH_ENABLED=true
      zap-auth-report.html
    nuclei/
      nuclei-report.json
      nuclei-report.txt
    katana/
      <target>.txt
    ffuf/
      <target>.json
    newman/
      newman-report.json        # only if NEWMAN_COLLECTION is set
  final/
    summary.json
    summary.pdf
  logs/
    preflight.log
    auth-bootstrap.log
    katana.log
    ffuf.log
    zap.log
    zap-auth.log
    nuclei.log
    normalize.log
    pdf-gen.log
    s3-upload.log
    slack.log
```

---

## Minimum IAM Policy for S3 Upload

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:PutObject", "s3:PutObjectAcl"],
      "Resource": "arn:aws:s3:::my-security-artifacts/dast/*"
    }
  ]
}
```

---

## Phase 2 — Authorization Matrix

| Variable / Secret | Default | Description |
|---|---|---|
| `USER_TOKEN` *(secret)* | — | Bearer token for standard authenticated user role |
| `ADMIN_TOKEN` *(secret)* | — | Bearer token for admin/privileged user role |
| `AUTHZ_ENDPOINTS` | see script | Comma-separated endpoint paths to test (e.g. `/api/users,/api/admin`) |

The authz matrix tests each endpoint against three roles: anonymous, user, and admin. It detects:
- Unauthenticated access to protected endpoints (IDOR/BOLA)
- Privilege escalation (user accessing admin endpoints)
- Missing access controls

---

## Phase 2 — Rate Limit Testing

| Variable | Default | Description |
|---|---|---|
| `RATE_BURST_COUNT` | `20` | Number of rapid requests to send per test |
| `LOGIN_PATH` | `/api/auth/login` | Login endpoint path to test for throttling |
| `RESET_PATH` | `/api/auth/reset` | Password reset endpoint path |
| `SIGNUP_PATH` | `/api/auth/register` | Signup/registration endpoint path |
| `API_TEST_PATH` | `/api/users` | API endpoint to burst test |

The rate limit suite sends rapid bursts to each endpoint and checks for:
- HTTP 429 responses
- `Retry-After` header presence
- `X-RateLimit-*` header presence

---

## Phase 2 — Regression Diff

No additional variables required. The regression diff step uses the existing `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `S3_BUCKET`, and `AWS_REGION` to fetch the prior run from S3 automatically.

The IAM policy must include `s3:ListBucket` and `s3:GetObject` in addition to `s3:PutObject`:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:PutObject",
        "s3:PutObjectAcl",
        "s3:GetObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::my-security-artifacts",
        "arn:aws:s3:::my-security-artifacts/dast/*"
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

---

## Updated Artifact Structure in S3 (Phase 1 + Phase 2)

```
s3://<S3_BUCKET>/dast/<TIMESTAMP>/
  raw/
    zap/
      zap-report.json
      zap-report.html
      zap-report.xml
      zap-auth-report.json      # only if AUTH_ENABLED=true
      zap-auth-report.html
    nuclei/
      nuclei-report.json
      nuclei-report.txt
    katana/
      <target>.txt
    ffuf/
      <target>.json
    newman/
      newman-report.json        # only if NEWMAN_COLLECTION is set
    authz/
      authz-matrix.json         # Phase 2 — authorization matrix results
    rate-limit/
      rate-limit-results.json   # Phase 2 — rate limit test results
  final/
    summary.json                # consolidated findings (all tools)
    summary.pdf                 # human-readable PDF report
  logs/
    preflight.log
    auth-bootstrap.log
    katana.log
    ffuf.log
    zap.log
    zap-auth.log
    nuclei.log
    authz-matrix.log            # Phase 2
    rate-limit.log              # Phase 2
    regression-diff.log         # Phase 2
    normalize.log
    posture.log
    pdf-gen.log
    s3-upload.log
    slack.log
```

---

## Phase 3 — Business Logic Testing

| Variable / Secret | Default | Description |
|---|---|---|
| `BL_API_ENDPOINTS` | `/api/orders,/api/checkout,/api/payment,/api/users/profile,/api/cart` | Comma-separated API paths to test for business logic flaws |
| `USER_TOKEN` *(secret)* | — | Bearer token for authenticated business logic tests (same as Phase 2) |

Tests performed:
- Duplicate submission (idempotency check)
- Negative value abuse (negative quantities/amounts)
- Mass assignment (privileged field injection)
- Workflow skipping (accessing later steps without completing prior ones)

---

## Phase 3 — Race Condition Testing

| Variable | Default | Description |
|---|---|---|
| `RACE_CONCURRENCY` | `10` | Number of parallel requests per race condition test |
| `RACE_ENDPOINTS` | `/api/orders,/api/checkout,/api/redeem,/api/vote,/api/like` | Comma-separated endpoints to test for race conditions |

---

## Phase 3 — Attack Surface Inventory

No additional variables required. The attack surface script automatically reads from:
- `artifacts/raw/katana/` — Katana crawl results
- `artifacts/raw/ffuf/` — ffuf forced browsing results
- `artifacts/raw/zap/zap-report.json` — ZAP scan results

Produces `artifacts/raw/attack-surface/attack-surface.json` with:
- All discovered routes
- API endpoints
- High-risk routes (admin, debug, upload, etc.)
- Parameters discovered
- Forms discovered

---

## Updated Artifact Structure in S3 (Phase 1 + Phase 2 + Phase 3)

```
s3://<S3_BUCKET>/dast/<TIMESTAMP>/
  raw/
    zap/                          zap-report.json/html/xml
    nuclei/                       nuclei-report.json/txt
    katana/                       <target>.txt
    ffuf/                         <target>.json
    newman/                       newman-report.json
    authz/                        authz-matrix.json         (Phase 2)
    rate-limit/                   rate-limit-results.json   (Phase 2)
    business-logic/               bl-results.json           (Phase 3)
    race-condition/               race-results.json         (Phase 3)
    attack-surface/               attack-surface.json       (Phase 3)
  final/
    summary.json
    summary.pdf
  logs/
    preflight.log
    katana.log / ffuf.log / zap.log / nuclei.log
    authz-matrix.log              (Phase 2)
    rate-limit.log                (Phase 2)
    regression-diff.log           (Phase 2)
    business-logic.log            (Phase 3)
    race-condition.log            (Phase 3)
    attack-surface.log            (Phase 3)
    normalize.log / posture.log / pdf-gen.log
    s3-upload.log / slack.log
```
