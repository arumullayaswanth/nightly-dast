/**
 * rate-limit-test.js
 * Phase 2 — Rate Limiting & Anti-Automation Testing
 *
 * Tests the application's own abuse controls using k6-style burst logic
 * implemented in Node.js (no k6 binary required — uses native http).
 *
 * Tests:
 *   1. Login throttling     — rapid repeated login attempts
 *   2. Password reset abuse — repeated reset requests for same email
 *   3. OTP/verify abuse     — repeated OTP submission attempts
 *   4. Signup throttling    — rapid account creation attempts
 *   5. API burst            — rapid API endpoint hammering
 *   6. 429 header check     — validates Retry-After header presence
 *
 * Required env vars:
 *   TARGET_URL              — base URL
 *   RATE_BURST_COUNT        — requests per burst (default: 20)
 *   RATE_LIMIT_OUTPUT       — output JSON path
 *
 * Optional env vars:
 *   LOGIN_PATH              — login endpoint (default: /api/auth/login)
 *   RESET_PATH              — password reset endpoint (default: /api/auth/reset)
 *   SIGNUP_PATH             — signup endpoint (default: /api/auth/register)
 *   API_TEST_PATH           — API endpoint to burst (default: /api/users)
 */

const https = require("https");
const http = require("http");
const fs = require("fs");
const path = require("path");
const url = require("url");

const TARGET_URL = process.env.TARGET_URL || "";
const BURST_COUNT = parseInt(process.env.RATE_BURST_COUNT || "20", 10);
const OUTPUT = process.env.RATE_LIMIT_OUTPUT || "artifacts/raw/rate-limit/rate-limit-results.json";

const LOGIN_PATH = process.env.LOGIN_PATH || "/api/auth/login";
const RESET_PATH = process.env.RESET_PATH || "/api/auth/reset";
const SIGNUP_PATH = process.env.SIGNUP_PATH || "/api/auth/register";
const API_PATH = process.env.API_TEST_PATH || "/api/users";

// Send a single POST request and return status + headers
function postRequest(targetUrl, endpointPath, body) {
    return new Promise((resolve) => {
        const fullUrl = `${targetUrl}${endpointPath}`;
        const parsed = url.parse(fullUrl);
        const bodyStr = JSON.stringify(body);

        const options = {
            hostname: parsed.hostname,
            port: parsed.port || (parsed.protocol === "https:" ? 443 : 80),
            path: parsed.path,
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "Content-Length": Buffer.byteLength(bodyStr),
                "User-Agent": "DAST-RateLimit/1.0",
            },
            timeout: 10000,
            rejectUnauthorized: false,
        };

        const proto = parsed.protocol === "https:" ? https : http;
        const req = proto.request(options, (res) => {
            resolve({
                status: res.statusCode,
                retryAfter: res.headers["retry-after"] || null,
                xRateLimit: res.headers["x-ratelimit-limit"] || null,
                xRateRemaining: res.headers["x-ratelimit-remaining"] || null,
            });
            res.resume();
        });

        req.on("error", () => resolve({ status: 0, retryAfter: null }));
        req.on("timeout", () => { req.destroy(); resolve({ status: 0, retryAfter: null }); });
        req.write(bodyStr);
        req.end();
    });
}

// Send a GET request
function getRequest(targetUrl, endpointPath) {
    return new Promise((resolve) => {
        const fullUrl = `${targetUrl}${endpointPath}`;
        const parsed = url.parse(fullUrl);
        const options = {
            hostname: parsed.hostname,
            port: parsed.port || (parsed.protocol === "https:" ? 443 : 80),
            path: parsed.path,
            method: "GET",
            headers: { "User-Agent": "DAST-RateLimit/1.0" },
            timeout: 10000,
            rejectUnauthorized: false,
        };
        const proto = parsed.protocol === "https:" ? https : http;
        const req = proto.request(options, (res) => {
            resolve({
                status: res.statusCode,
                retryAfter: res.headers["retry-after"] || null,
                xRateLimit: res.headers["x-ratelimit-limit"] || null,
            });
            res.resume();
        });
        req.on("error", () => resolve({ status: 0, retryAfter: null }));
        req.on("timeout", () => { req.destroy(); resolve({ status: 0, retryAfter: null }); });
        req.end();
    });
}

// Run a burst test and analyse results
async function runBurst(name, requestFn, count) {
    console.log(`\n[TEST] ${name} — sending ${count} rapid requests...`);
    const responses = [];

    for (let i = 0; i < count; i++) {
        const res = await requestFn();
        responses.push(res);
        process.stdout.write(`  [${i + 1}/${count}] HTTP ${res.status}\r`);
    }
    process.stdout.write("\n");

    const statusCounts = {};
    for (const r of responses) {
        statusCounts[r.status] = (statusCounts[r.status] || 0) + 1;
    }

    const got429 = responses.some((r) => r.status === 429);
    const got429Count = responses.filter((r) => r.status === 429).length;
    const hasRetryAfter = responses.some((r) => r.retryAfter !== null);
    const hasRateLimitHeaders = responses.some((r) => r.xRateLimit !== null);
    const allSucceeded = responses.every((r) => r.status >= 200 && r.status < 300);

    // Determine verdict
    let verdict, severity, description, solution;

    if (got429) {
        verdict = "pass";
        severity = "info";
        description = `Rate limiting is active. Got ${got429Count}/${count} HTTP 429 responses.`;
        solution = "Rate limiting is working correctly.";
        if (!hasRetryAfter) {
            verdict = "warn";
            severity = "low";
            description += " However, no Retry-After header was returned.";
            solution = "Add a Retry-After header to 429 responses so clients know when to retry.";
        }
    } else if (allSucceeded) {
        verdict = "fail";
        severity = "medium";
        description = `No rate limiting detected. All ${count} rapid requests succeeded (HTTP 2xx).`;
        solution = "Implement rate limiting on this endpoint to prevent abuse and brute-force attacks.";
    } else {
        verdict = "warn";
        severity = "low";
        description = `Mixed responses received. Status distribution: ${JSON.stringify(statusCounts)}. No explicit 429 detected.`;
        solution = "Review rate limiting configuration. Consider returning explicit 429 responses.";
    }

    console.log(`  Result: ${verdict.toUpperCase()} — ${description}`);

    return {
        name,
        burst_count: count,
        status_distribution: statusCounts,
        got_429: got429,
        got_429_count: got429Count,
        has_retry_after: hasRetryAfter,
        has_rate_limit_headers: hasRateLimitHeaders,
        verdict,
        severity,
        description,
        solution,
    };
}

async function main() {
    if (!TARGET_URL) {
        console.error("[ERROR] TARGET_URL is required");
        process.exit(1);
    }

    console.log(`[INFO] Rate limit testing: ${TARGET_URL}`);
    console.log(`[INFO] Burst count: ${BURST_COUNT} requests per test`);

    const testResults = [];

    // Test 1: Login throttling
    testResults.push(await runBurst(
        "Login throttling",
        () => postRequest(TARGET_URL, LOGIN_PATH, {
            email: "test@example.com",
            password: "wrongpassword123",
        }),
        BURST_COUNT
    ));

    // Test 2: Password reset abuse
    testResults.push(await runBurst(
        "Password reset abuse",
        () => postRequest(TARGET_URL, RESET_PATH, {
            email: "test@example.com",
        }),
        BURST_COUNT
    ));

    // Test 3: Signup throttling
    testResults.push(await runBurst(
        "Signup throttling",
        () => postRequest(TARGET_URL, SIGNUP_PATH, {
            email: `test${Date.now()}@example.com`,
            password: "TestPass123!",
            name: "Test User",
        }),
        BURST_COUNT
    ));

    // Test 4: API burst (GET)
    testResults.push(await runBurst(
        "API endpoint burst",
        () => getRequest(TARGET_URL, API_PATH),
        BURST_COUNT
    ));

    // Build findings for normalize-reports.py ingestion
    const findings = testResults
        .filter((r) => r.verdict === "fail" || r.verdict === "warn")
        .map((r) => ({
            id: `rate-limit-${r.name.replace(/\s+/g, "-").toLowerCase()}`,
            tool: "rate-limit-test",
            authenticated: false,
            title: `Rate Limiting Issue: ${r.name}`,
            severity: r.severity,
            description: r.description,
            solution: r.solution,
            references: "OWASP ASVS V4.4 — Rate Limiting; CWE-307",
            affected_urls: [`${TARGET_URL}`],
            cwe: "CWE-307",
            cve: "",
        }));

    const passed = testResults.filter((r) => r.verdict === "pass").length;
    const failed = testResults.filter((r) => r.verdict === "fail").length;
    const warned = testResults.filter((r) => r.verdict === "warn").length;

    const output = {
        scan_type: "rate-limit-test",
        target: TARGET_URL,
        timestamp: new Date().toISOString(),
        burst_count: BURST_COUNT,
        summary: {
            total: testResults.length,
            passed,
            failed,
            warned,
        },
        tests: testResults,
        findings,
    };

    fs.mkdirSync(path.dirname(OUTPUT), { recursive: true });
    fs.writeFileSync(OUTPUT, JSON.stringify(output, null, 2));

    console.log(`\n[INFO] Rate limit tests: ${passed} passed, ${failed} failed, ${warned} warnings`);
    console.log(`[INFO] Findings: ${findings.length} rate limiting issues`);
    console.log(`[INFO] Output written to ${OUTPUT}`);
}

main().catch((err) => {
    console.error(`[ERROR] ${err.message}`);
    process.exit(1);
});
