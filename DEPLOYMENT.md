# Deployment Guide — Nightly DAST / Pentest Regression Pipeline

End-to-end setup guide to get the pipeline running from zero to first successful nightly scan.

---

## Prerequisites

Before you start, make sure you have:

- A GitHub repository (this project pushed to it)
- An AWS account with S3 access
- A Slack workspace where you can create an Incoming Webhook
- A non-production target URL you are authorized to scan

---

## Step 1 — Push the Project to GitHub

If you haven't already:

```bash
git init
git remote add origin https://github.com/YOUR-ORG/YOUR-REPO.git
git add .
git commit -m "feat: add nightly DAST pipeline"
git push -u origin main
```

GitHub Actions will automatically detect `.github/workflows/dast-nightly.yml`.

---

## Step 2 — Create the S3 Bucket

### 2a. Create the bucket

Go to **AWS Console → S3 → Create bucket**

- Bucket name: `your-security-artifacts` (choose your own name)
- Region: pick your preferred region (e.g. `us-east-1`)
- Block all public access: **ON** (keep it private)
- Versioning: optional
- Click **Create bucket**

Or via AWS CLI:

```bash
aws s3api create-bucket \
  --bucket your-security-artifacts \
  --region us-east-1
```

### 2b. Create an IAM user for the pipeline

Go to **AWS Console → IAM → Users → Create user**

- Username: `dast-pipeline-bot`
- Access type: **Programmatic access**

Attach this inline policy (scoped to your bucket only):

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

- Click **Create user**
- Download or copy the **Access Key ID** and **Secret Access Key** — you will need these in Step 4

---

## Step 3 — Create the Slack Webhook

1. Go to [https://api.slack.com/apps](https://api.slack.com/apps)
2. Click **Create New App → From scratch**
3. Name it `DAST Pipeline`, select your workspace, click **Create App**
4. In the left sidebar click **Incoming Webhooks**
5. Toggle **Activate Incoming Webhooks** to ON
6. Click **Add New Webhook to Workspace**
7. Select the channel where you want scan notifications (e.g. `#security-alerts`)
8. Click **Allow**
9. Copy the **Webhook URL** — it will be in the format:
   `https://hooks.slack.com/services/<WORKSPACE_ID>/<CHANNEL_ID>/<TOKEN>`

---

## Step 4 — Configure GitHub Actions Secrets

Go to your GitHub repository:
**Settings → Secrets and variables → Actions → Secrets tab → New repository secret**

Add these three secrets:

| Secret Name | Value |
|---|---|
| `AWS_ACCESS_KEY_ID` | The access key ID from Step 2b |
| `AWS_SECRET_ACCESS_KEY` | The secret access key from Step 2b |
| `SLACK_WEBHOOK_URL` | The webhook URL from Step 3 |

> Secrets are encrypted and never visible after saving. They are injected into the runner at runtime only.

---

## Step 5 — Configure GitHub Actions Variables

Go to your GitHub repository:
**Settings → Secrets and variables → Actions → Variables tab → New repository variable**

Add these required variables:

| Variable Name | Value |
|---|---|
| `TARGET_URLS` | `https://your-staging-app.example.com` |
| `S3_BUCKET` | `your-security-artifacts` |

For multiple targets use a comma-separated list:
```
https://staging.example.com,https://api-staging.example.com
```

### Optional variables to add now

| Variable Name | Recommended Value |
|---|---|
| `ENVIRONMENT` | `staging` |
| `AWS_REGION` | `us-east-1` |
| `NUCLEI_SEVERITY` | `medium,high,critical` |
| `KATANA_DEPTH` | `3` |
| `FFUF_RATE` | `30` |

---

## Step 6 — (Optional) Enable Authenticated Scans

Skip this step if your target does not require login.

Add these additional secrets:

| Secret Name | Value |
|---|---|
| `AUTH_USERNAME` | Your test account username or email |
| `AUTH_PASSWORD` | Your test account password |

Add these variables:

| Variable Name | Value |
|---|---|
| `AUTH_ENABLED` | `true` |
| `AUTH_URL` | `https://your-staging-app.example.com/login` |
| `AUTH_USERNAME_SELECTOR` | CSS selector for the username input (e.g. `#email`) |
| `AUTH_PASSWORD_SELECTOR` | CSS selector for the password input (e.g. `#password`) |
| `AUTH_SUBMIT_SELECTOR` | CSS selector for the submit button (e.g. `button[type=submit]`) |
| `SESSION_COOKIE_NAME` | Name of the session cookie your app sets after login |

To find the correct CSS selectors:
1. Open your login page in Chrome
2. Right-click the username field → **Inspect**
3. Note the `id` or `name` attribute — use `#id` or `[name=value]` format

---

## Step 7 — Trigger a Manual Test Run

Before waiting for the nightly schedule, trigger a manual run to verify everything works:

1. Go to your repository on GitHub
2. Click the **Actions** tab
3. In the left sidebar click **Nightly DAST / Pentest Regression**
4. Click **Run workflow → Run workflow**

Watch the run in real time by clicking into it.

---

## Step 8 — Verify Each Stage

As the run progresses, verify each stage passes:

### Pre-flight check
```
[INFO] Starting pre-flight checks (timeout: 10s per target)
[CHECK] https://staging.example.com ... OK (HTTP 200)
[INFO] All targets passed pre-flight checks.
```
If this fails: the target is unreachable from GitHub Actions. Check firewall rules or allowlist GitHub's IP ranges.

### Auth bootstrap (if enabled)
```
[INFO] Launching browser for auth bootstrap
[INFO] Login page loaded.
[INFO] Post-login URL: https://staging.example.com/dashboard
[INFO] Session cookie "session" found.
[INFO] Auth bootstrap complete.
```
If this fails: check your CSS selectors and credentials. Inspect `auth-bootstrap.log` in the artifacts.

### ZAP scan
```
Total of X alerts were raised.
```
ZAP will always exit with a non-zero code if it finds alerts — the workflow uses `|| true` so this won't fail the pipeline.

### Nuclei scan
```
[INF] Templates loaded: XXXX
[nuclei] finding 1: ...
```

### Report generation
```
[INFO] summary.json written to artifacts/final/summary.json
[INFO] Total findings: 42 (critical=0, high=2, medium=8, low=15, info=17)
[INFO] PDF report written to artifacts/final/summary.pdf
```

### S3 upload
```
[INFO] Uploading artifacts to s3://your-security-artifacts/dast/20240315T020012Z
[INFO] All artifacts uploaded successfully.
```

### Slack notification
Check your Slack channel — you should see a color-coded message with findings summary and S3 path.

---

## Step 9 — Download and Review Artifacts

After the run completes:

1. Click into the completed Actions run
2. Scroll to the bottom — **Artifacts** section
3. Download `dast-artifacts-<timestamp>.zip`
4. Extract and open:
   - `final/summary.pdf` — human-readable PDF report
   - `final/summary.json` — machine-readable findings
   - `raw/zap/zap-report.html` — full ZAP HTML report
   - `logs/*.log` — per-tool logs for troubleshooting

Or retrieve directly from S3:

```bash
aws s3 cp s3://your-security-artifacts/dast/20240315T020012Z/ ./scan-results/ --recursive
```

---

## Step 10 — Verify Nightly Schedule

The pipeline is scheduled to run at **02:00 UTC every night** via:

```yaml
- cron: "0 2 * * *"
```

To change the time, edit `.github/workflows/dast-nightly.yml` and update the cron expression.

> Note: GitHub Actions scheduled workflows may run up to 15 minutes late during high-load periods.

You can verify the schedule is active by going to:
**Actions → Nightly DAST / Pentest Regression** — you will see the next scheduled run time.

---

## Deployment Checklist

Use this checklist to confirm everything is in place before going live:

```
Infrastructure
  [ ] S3 bucket created
  [ ] IAM user created with scoped policy
  [ ] AWS access key and secret key saved

GitHub Configuration
  [ ] Repository has the pipeline code pushed to main
  [ ] Secret: AWS_ACCESS_KEY_ID set
  [ ] Secret: AWS_SECRET_ACCESS_KEY set
  [ ] Secret: SLACK_WEBHOOK_URL set
  [ ] Variable: TARGET_URLS set (approved non-production only)
  [ ] Variable: S3_BUCKET set

Optional (Authenticated Scans)
  [ ] Secret: AUTH_USERNAME set
  [ ] Secret: AUTH_PASSWORD set
  [ ] Variable: AUTH_ENABLED = true
  [ ] Variable: AUTH_URL set
  [ ] Variable: AUTH_USERNAME_SELECTOR set
  [ ] Variable: AUTH_PASSWORD_SELECTOR set
  [ ] Variable: AUTH_SUBMIT_SELECTOR set
  [ ] Variable: SESSION_COOKIE_NAME set

Validation
  [ ] Manual run triggered and completed successfully
  [ ] summary.pdf downloaded and reviewed
  [ ] summary.json contains findings data
  [ ] S3 bucket contains dast/<timestamp>/ folder
  [ ] Slack notification received in correct channel
  [ ] Nightly schedule confirmed active
```

---

## Updating the Pipeline

To update the pipeline after deployment:

```bash
# Edit any file locally
git add .
git commit -m "fix: update nuclei tags"
git push origin main
```

Changes take effect on the next run (nightly or manual trigger).

---

## Disabling the Pipeline

To temporarily disable the nightly schedule without deleting anything:

1. Go to **Actions → Nightly DAST / Pentest Regression**
2. Click the **...** menu (top right)
3. Click **Disable workflow**

Re-enable the same way when ready to resume.

---

## Common Issues at First Deployment

| Issue | Fix |
|---|---|
| `TARGET_URLS` not set error | Add the variable in Actions → Variables |
| `S3_BUCKET` required error | Add the variable in Actions → Variables |
| AWS credentials invalid | Re-check the IAM access key — secrets cannot be read back after saving, recreate if unsure |
| ZAP Docker pull fails | Transient GitHub Actions network issue — re-run the workflow |
| Slack message not received | Confirm the webhook URL is set as a **Secret** not a Variable, and the channel still exists |
| PDF blank or missing | WeasyPrint font issue — check `pdf-gen.log` in artifacts |
| Pre-flight fails on valid URL | GitHub Actions IP may be blocked — allowlist [GitHub's IP ranges](https://api.github.com/meta) on your target |
