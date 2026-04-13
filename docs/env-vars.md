# Environment Variables & Secrets — Complete Reference

All configuration is passed via GitHub Actions **Secrets** (`secrets.*`) and **Variables** (`vars.*`).

- **Secrets** → Settings → Secrets and variables → Actions → **Secrets tab**
- **Variables** → Settings → Secrets and variables → Actions → **Variables tab**

Secrets are encrypted and never visible after saving. Variables are plain text and visible.

---

## Quick-Start Checklist

Minimum required to run the pipeline end-to-end:

```
Secrets (3 required):
  [x] AWS_ACCESS_KEY_ID
  [x] AWS_SECRET_ACCESS_KEY
  [x] SLACK_WEBHOOK_URL

Variables (2 required):
  [x] TARGET_URLS
  [x] S3_BUCKET
```

Everything else is optional and has a safe default.

---

## SECRETS

### Required Secrets

| Secret Name | Required | Example Value | Description |
|---|---|---|---|
| `AWS_ACCESS_KEY_ID` | ✅ Required | `AKIA-YOUR-ACCESS-KEY-ID` | AWS IAM access key ID for S3 artifact upload |
| `AWS_SECRET_ACCESS_KEY` | ✅ Required | `your-aws-secret-access-key-here` | AWS IAM secret access key (pair with above) |
| `SLACK_WEBHOOK_URL` | ✅ Required | `https://hooks.slack.com/services/<WORKSPACE_ID>/<CHANNEL_ID>/<TOKEN>` | Slack Incoming Webhook URL for scan notifications |

### Optional — Authenticated Scans

| Secret Name | Required | Example Value | Description |
|---|---|---|---|
| `AUTH_USERNAME` | Optional | `testuser@acmecorp.com` | Login username or email for Playwright auth bootstrap. Required when `AUTH_ENABLED=true` |
| `AUTH_PASSWORD` | Optional | `TestP@ssw0rd!2024` | Login password for Playwright auth bootstrap. Required when `AUTH_ENABLED=true` |

### Optional — Authorization & IDOR Testing

| Secret Name | Required | Example Value | Description |
|---|---|---|---|
| `USER_TOKEN` | Optional | `your-user-bearer-token` | Bearer token for a standard authenticated user. Used by authz-matrix, business-logic, race-condition, and upload-abuse tests |
| `ADMIN_TOKEN` | Optional | `your-admin-bearer-token` | Bearer token for an admin/privileged user. Used by authz-matrix to test privilege escalation |
| `USER_B_TOKEN` | Optional | `your-second-user-bearer-token` | Bearer token for a **second** standard user account. Used for cross-user IDOR/BOLA tests (User A vs User B object access) |

### Optional — API Workflow (Newman)

| Secret Name | Required | Example Value | Description |
|---|---|---|---|
| `API_TOKEN` | Optional | `your-api-bearer-token` | Bearer token injected into Newman/Postman API workflow runs |

### Optional — Slack On-Call Escalation

| Secret Name | Required | Example Value | Description |
|---|---|---|---|
| `SLACK_ONCALL_WEBHOOK` | Optional | `https://hooks.slack.com/services/<WORKSPACE_ID>/<CHANNEL_ID>/<TOKEN>` | Second Slack webhook for red-tier on-call escalation. When set, critical findings trigger a separate alert to your on-call channel in addition to the main security channel |

---

## VARIABLES

### Required Variables

| Variable Name | Required | Example Value | Description |
|---|---|---|---|
| `TARGET_URLS` | ✅ Required | `https://staging.acmecorp.com,https://api-staging.acmecorp.com` | Comma-separated list of approved **non-production** target URLs to scan. All tools run against these URLs |
| `S3_BUCKET` | ✅ Required | `acmecorp-security-artifacts` | S3 bucket name where all scan artifacts, reports, and logs are uploaded |

### Optional — General Pipeline

| Variable Name | Required | Default | Example Value | Description |
|---|---|---|---|---|
| `ENVIRONMENT` | Optional | `non-production` | `staging` | Environment label shown in reports and Slack notifications |
| `AWS_REGION` | Optional | `us-east-1` | `ap-south-1` | AWS region where your S3 bucket lives |
| `PREFLIGHT_TIMEOUT` | Optional | `10` | `15` | Seconds to wait per target URL during reachability check before marking it unreachable |

### Optional — Authenticated Scan Setup (Playwright)

| Variable Name | Required | Default | Example Value | Description |
|---|---|---|---|---|
| `AUTH_ENABLED` | Optional | `false` | `true` | Set to `true` to enable the full authenticated scan flow (Playwright login + authenticated ZAP scan) |
| `AUTH_URL` | If AUTH_ENABLED=true | — | `https://staging.acmecorp.com/login` | Full URL of the login page Playwright will navigate to |
| `AUTH_USERNAME_SELECTOR` | Optional | `#username` | `#email` | CSS selector for the username/email input field on the login page |
| `AUTH_PASSWORD_SELECTOR` | Optional | `#password` | `input[name="password"]` | CSS selector for the password input field on the login page |
| `AUTH_SUBMIT_SELECTOR` | Optional | `[type=submit]` | `button.login-btn` | CSS selector for the login submit button |
| `SESSION_COOKIE_NAME` | Optional | `session` | `connect.sid` | Name of the session cookie your app sets after successful login. Used to validate auth bootstrap succeeded |

> **How to find CSS selectors:** Open your login page in Chrome → right-click the field → Inspect → note the `id` or `name` attribute → use `#id` or `[name=value]` format.

### Optional — Endpoint Discovery

| Variable Name | Required | Default | Example Value | Description |
|---|---|---|---|---|
| `KATANA_DEPTH` | Optional | `3` | `5` | How deep Katana crawls from the target URL. Higher = more coverage, slower scan |
| `FFUF_WORDLIST` | Optional | `configs/ffuf-wordlist-small.txt` | `configs/ffuf-wordlist-small.txt` | Path to the wordlist file used for forced browsing. Commit a larger wordlist to use it |
| `FFUF_RATE` | Optional | `50` | `30` | Requests per second limit for ffuf forced browsing. Lower to avoid rate-limiting on the target |

### Optional — Nuclei Scan

| Variable Name | Required | Default | Example Value | Description |
|---|---|---|---|---|
| `NUCLEI_TAGS` | Optional | `cve,ssrf,xss,sqli,rce,misconfig,exposure,headers,session` | `cve,ssrf,xss,sqli,rce,misconfig,exposure,headers,session,oast` | Comma-separated Nuclei template tags to run. Controls which vulnerability categories are checked |
| `NUCLEI_SEVERITY` | Optional | `medium,high,critical` | `low,medium,high,critical` | Minimum severity filter. Findings below this level are not reported |
| `NUCLEI_RATE` | Optional | `50` | `25` | Requests per second limit for Nuclei. Lower to be gentler on the target |

### Optional — OAST / Blind Callback Testing

| Variable Name | Required | Default | Example Value | Description |
|---|---|---|---|---|
| `INTERACTSH_SERVER` | Optional | *(Nuclei default public server)* | `https://oast.acmecorp.internal` | Custom interactsh server URL for blind SSRF/XSS out-of-band callbacks. Leave blank to use Nuclei's built-in public interactsh server |

### Optional — ZAP Scan

| Variable Name | Required | Default | Example Value | Description |
|---|---|---|---|---|
| `ZAP_AJAX_SPIDER` | Optional | `false` | `true` | Enable ZAP AJAX spider. Slower but provides much better coverage for React/Angular/Vue single-page applications |

### Optional — Newman / Postman API Workflow

| Variable Name | Required | Default | Example Value | Description |
|---|---|---|---|---|
| `NEWMAN_COLLECTION` | Optional | *(not set)* | `configs/api-security-tests.postman_collection.json` | Path or URL to a Postman collection JSON file. When set, Newman runs the collection as part of the pipeline |
| `NEWMAN_ENV_FILE` | Optional | *(not set)* | `configs/staging.postman_environment.json` | Path to a Postman environment file to inject variables into the Newman run |

### Optional — Authorization Matrix Testing

| Variable Name | Required | Default | Example Value | Description |
|---|---|---|---|---|
| `AUTHZ_ENDPOINTS` | Optional | *(built-in defaults)* | `/api/users,/api/admin,/api/orders,/api/reports` | Comma-separated endpoint paths to test in the authorization matrix. If not set, uses a built-in list of common API paths |

> **Built-in default endpoints tested:** `/api/users`, `/api/users/1`, `/api/users/2`, `/api/admin`, `/api/admin/users`, `/api/profile`, `/api/settings`, `/api/reports`, `/dashboard`, `/admin`

### Optional — Rate Limit Testing

| Variable Name | Required | Default | Example Value | Description |
|---|---|---|---|---|
| `RATE_BURST_COUNT` | Optional | `20` | `30` | Number of rapid requests sent per burst test. Higher = more aggressive test |
| `LOGIN_PATH` | Optional | `/api/auth/login` | `/api/v1/auth/signin` | Login endpoint path to test for brute-force throttling |
| `RESET_PATH` | Optional | `/api/auth/reset` | `/api/v1/auth/forgot-password` | Password reset endpoint path to test for abuse throttling |
| `SIGNUP_PATH` | Optional | `/api/auth/register` | `/api/v1/auth/signup` | Signup/registration endpoint path to test for account creation throttling |
| `API_TEST_PATH` | Optional | `/api/users` | `/api/v1/products` | General API endpoint to burst test for rate limiting |

### Optional — Business Logic Testing

| Variable Name | Required | Default | Example Value | Description |
|---|---|---|---|---|
| `BL_API_ENDPOINTS` | Optional | `/api/orders,/api/checkout,/api/payment,/api/users/profile,/api/cart` | `/api/orders,/api/checkout,/api/payment,/api/cart,/api/coupons` | Comma-separated API paths to test for business logic flaws (duplicate submit, negative values, mass assignment, workflow skipping) |

### Optional — Race Condition Testing

| Variable Name | Required | Default | Example Value | Description |
|---|---|---|---|---|
| `RACE_CONCURRENCY` | Optional | `10` | `15` | Number of parallel requests fired simultaneously per race condition test |
| `RACE_ENDPOINTS` | Optional | `/api/orders,/api/checkout,/api/redeem,/api/vote,/api/like` | `/api/orders,/api/redeem,/api/checkout,/api/transfer` | Comma-separated endpoints to test for race conditions and double-submit vulnerabilities |

### Optional — File Upload Abuse Testing

| Variable Name | Required | Default | Example Value | Description |
|---|---|---|---|---|
| `UPLOAD_PATH` | Optional | `/api/upload` | `/api/v1/files/upload` | Upload endpoint path to test for file upload vulnerabilities |
| `UPLOAD_FIELD` | Optional | `file` | `attachment` | Multipart form field name used for the file in the upload request |
| `RETRIEVE_PATH` | Optional | `/uploads` | `/static/uploads` | URL path prefix where uploaded files are served. Used to test whether uploaded files are publicly accessible without authentication |

### Optional — Slack Tiered Routing

| Variable Name | Required | Default | Example Value | Description |
|---|---|---|---|---|
| *(no extra variables needed)* | — | — | — | Slack routing is controlled by the `SLACK_WEBHOOK_URL` secret (all tiers) and `SLACK_ONCALL_WEBHOOK` secret (red tier only) |

---

## IAM Policy for S3

### Minimum policy (upload only)

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:PutObject", "s3:PutObjectAcl"],
      "Resource": "arn:aws:s3:::acmecorp-security-artifacts/dast/*"
    }
  ]
}
```

### Recommended policy (upload + regression diff)

The regression diff step needs to read prior scan results from S3 to compare new vs fixed findings.

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
        "arn:aws:s3:::acmecorp-security-artifacts",
        "arn:aws:s3:::acmecorp-security-artifacts/dast/*"
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

## Slack Alert Tiers

| Tier | Color | Condition | Channels |
|---|---|---|---|
| 🔴 Red | Danger | New critical/high findings, fallback summary used, pipeline failure, auth coverage failed | Main security channel + on-call channel (`SLACK_ONCALL_WEBHOOK`) |
| 🟡 Yellow | Warning | High severity findings, new mediums, partial stage coverage, stages not run | Main security channel only |
| 🟢 Green | Good | No new critical/high findings, all coverage targets met | Main security channel only |

Red-tier message includes: top-3 new risks, failed stage list, posture score, on-call escalation.

---

## Complete S3 Artifact Structure

```
s3://<S3_BUCKET>/dast/<YYYYMMDDTHHMMSSZ>/
  raw/
    zap/
      zap-report.json               # ZAP unauthenticated scan (machine-readable)
      zap-report.html               # ZAP unauthenticated scan (human-readable)
      zap-report.xml                # ZAP unauthenticated scan (XML)
      zap-auth-report.json          # ZAP authenticated scan (only if AUTH_ENABLED=true)
      zap-auth-report.html          # ZAP authenticated scan (only if AUTH_ENABLED=true)
    nuclei/
      nuclei-report.json            # Nuclei findings (JSONL)
      nuclei-report.txt             # Nuclei findings (plain text)
    oast/
      oast-report.json              # OAST/interactsh blind callback findings
      oast-report.txt               # OAST plain text
    katana/
      <target-safe-name>.txt        # Discovered endpoints per target
    ffuf/
      <target-safe-name>.json       # ffuf forced browsing results per target
    arjun/
      <target-safe-name>.json       # Arjun parameter discovery results
    newman/
      newman-report.json            # Newman API run (only if NEWMAN_COLLECTION is set)
    authz/
      authz-matrix.json             # Authorization matrix + IDOR test results
    rate-limit/
      rate-limit-results.json       # Rate limiting test results
    business-logic/
      bl-results.json               # Business logic abuse test results
    race-condition/
      race-results.json             # Race condition test results
    attack-surface/
      attack-surface.json           # Aggregated attack surface inventory
    upload-abuse/
      upload-results.json           # File upload abuse test results
    frontend/
      frontend-results.json         # Frontend/browser security test results
  final/
    summary.json                    # Consolidated unified findings (all tools, all phases)
    summary.pdf                     # Human-readable PDF report
  logs/
    preflight.log
    auth-bootstrap.log
    zap-auth-setup.log
    katana.log
    ffuf.log
    arjun.log
    zap.log
    zap-auth.log
    nuclei.log
    oast.log
    authz-matrix.log
    rate-limit.log
    regression-diff.log
    business-logic.log
    race-condition.log
    attack-surface.log
    upload-abuse.log
    frontend-security.log
    normalize.log
    posture.log
    pdf-gen.log
    s3-upload.log
    slack.log
```

---

## Full Example — All Variables Set

Below is a realistic example of every variable and secret configured for a staging environment.

### Secrets

| Secret | Example Value |
|---|---|
| `AWS_ACCESS_KEY_ID` | `AKIA-YOUR-ACCESS-KEY-ID` |
| `AWS_SECRET_ACCESS_KEY` | `your-aws-secret-access-key-here` |
| `SLACK_WEBHOOK_URL` | `https://hooks.slack.com/services/<WORKSPACE_ID>/<CHANNEL_ID>/<TOKEN>` |
| `SLACK_ONCALL_WEBHOOK` | `https://hooks.slack.com/services/<WORKSPACE_ID>/<CHANNEL_ID>/<TOKEN>` |
| `AUTH_USERNAME` | `testuser@acmecorp.com` |
| `AUTH_PASSWORD` | `TestP@ssw0rd!2024` |
| `USER_TOKEN` | `your-user-bearer-token` |
| `ADMIN_TOKEN` | `your-admin-bearer-token` |
| `USER_B_TOKEN` | `your-second-user-bearer-token` |
| `API_TOKEN` | `your-api-bearer-token` |

### Variables

| Variable | Example Value |
|---|---|
| `TARGET_URLS` | `https://staging.acmecorp.com,https://api-staging.acmecorp.com` |
| `S3_BUCKET` | `acmecorp-security-artifacts` |
| `ENVIRONMENT` | `staging` |
| `AWS_REGION` | `us-east-1` |
| `PREFLIGHT_TIMEOUT` | `10` |
| `AUTH_ENABLED` | `true` |
| `AUTH_URL` | `https://staging.acmecorp.com/login` |
| `AUTH_USERNAME_SELECTOR` | `#email` |
| `AUTH_PASSWORD_SELECTOR` | `input[name="password"]` |
| `AUTH_SUBMIT_SELECTOR` | `button[type=submit]` |
| `SESSION_COOKIE_NAME` | `connect.sid` |
| `KATANA_DEPTH` | `3` |
| `FFUF_RATE` | `30` |
| `NUCLEI_TAGS` | `cve,ssrf,xss,sqli,rce,misconfig,exposure,headers,session` |
| `NUCLEI_SEVERITY` | `medium,high,critical` |
| `NUCLEI_RATE` | `50` |
| `ZAP_AJAX_SPIDER` | `false` |
| `AUTHZ_ENDPOINTS` | `/api/users,/api/admin,/api/orders,/api/reports,/api/settings` |
| `RATE_BURST_COUNT` | `20` |
| `LOGIN_PATH` | `/api/auth/login` |
| `RESET_PATH` | `/api/auth/reset` |
| `SIGNUP_PATH` | `/api/auth/register` |
| `API_TEST_PATH` | `/api/users` |
| `BL_API_ENDPOINTS` | `/api/orders,/api/checkout,/api/payment,/api/cart` |
| `RACE_CONCURRENCY` | `10` |
| `RACE_ENDPOINTS` | `/api/orders,/api/checkout,/api/redeem` |
| `UPLOAD_PATH` | `/api/upload` |
| `UPLOAD_FIELD` | `file` |
| `RETRIEVE_PATH` | `/uploads` |
