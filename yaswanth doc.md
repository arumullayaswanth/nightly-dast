`DEPLOYMENT.md` is ready. Here's what it covers end to end:

- Step 1 — Push project to GitHub
- Step 2 — Create S3 bucket + IAM user with scoped policy (JSON included)
- Step 3 — Create Slack Incoming Webhook (with exact UI steps)
- Step 4 — Set GitHub Actions Secrets (AWS keys + Slack)
- Step 5 — Set GitHub Actions Variables (targets, bucket, region, etc.)
- Step 6 — Optional authenticated scan setup (how to find CSS selectors)
- Step 7 — Trigger a manual test run
- Step 8 — Verify each pipeline stage with expected log output
- Step 9 — Download and review artifacts from GitHub or S3
- Step 10 — Confirm nightly schedule is active
- Full deployment checklist (copy-paste ready)
- How to update and disable the pipeline
- Common first-deployment issues with fixes

Your full deliverable is now:
- `Readme.md` — project overview for the client
- `DEPLOYMENT.md` — end-to-end setup guide
- `docs/env-vars.md` — full variable reference
- All 11 implementation files