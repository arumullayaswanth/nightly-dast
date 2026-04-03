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
