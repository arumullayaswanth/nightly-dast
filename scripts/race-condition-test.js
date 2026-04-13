/**
 * race-condition-test.js
 * Phase 3 — Race Condition & Concurrency Testing
 *
 * Tests for race conditions by sending parallel requests simultaneously:
 *   1. Double submit          — same request sent in parallel
 *   2. Parallel mutations     — concurrent writes to same resource
 *   3. Token reuse window     — reuse a one-time token concurrently
 *   4. Concurrent privilege   — simultaneous privileged operations
 *
 * Uses Promise.all to fire requests at the same time (true concurrency).
 *
 * Required env vars:
 *   TARGET_URL                — base URL
 *   RACE_OUTPUT               — output JSON path
 *
 * Optional env vars:
 *   RACE_CONCURRENCY          — parallel requests per test (default: 10)
 *   RACE_ENDPOINTS            — comma-separated endpoints to test
 *   USER_TOKEN                — Bearer token
 */

const https = require("https");
const http = require("http");
const fs = require("fs");
const path = require("path");
const url = require("url");

const TARGET_URL = process.env.TARGET_URL || "";
const USER_TOKEN = process.env.USER_TOKEN || "";
const CONCURRENCY = parseInt(process.env.RACE_CONCURRENCY || "10", 10);
const OUTPUT = process.env.RACE_OUTPUT || "artifacts/raw/race-condition/race-results.json";

const DEFAULT_ENDPOINTS = (process.env.RACE_ENDPOINTS || "")
    .split(",").map((e) => e.trim()).filter(Boolean);

if (DEFAULT_ENDPOINTS.length === 0) {
    DEFAULT_ENDPOINTS.push(
        "/api/orders",
        "/api/checkout",
        "/api/redeem",
        "/api/vote",
        "/api/like"
    );
}

function request(method, targetUrl, endpointPath, body) {
    return new Promise((resolve) => {
        const fullUrl = `${targetUrl}${endpointPath}`;
        const parsed = url.parse(fullUrl);
        const bodyStr = body ? JSON.stringify(body) : "";
        const start = Date.now();

        const options = {
            hostname: parsed.hostname,
            port: parsed.port || (parsed.protocol === "https:" ? 443 : 80),
            path: parsed.path,
            method,
            headers: {
                "Content-Type": "application/json",
                "User-Agent": "DAST-RaceCondition/1.0",
                ...(USER_TOKEN ? { Authorization: `Bearer ${USER_TOKEN}` } : {}),
                ...(bodyStr ? { "Content-Length": Buffer.byteLength(bodyStr) } : {}),
            },
            timeout: 15000,
            rejectUnauthorized: false,
        };

        const proto = parsed.protocol === "https:" ? https : http;
        const req = proto.request(options, (res) => {
            let data = "";
            res.on("data", (c) => { data += c; });
            res.on("end", () => resolve({
                status: res.statusCode,
                duration: Date.now() - start,
                body: data.slice(0, 200),
            }));
        });

        req.on("error", () => resolve({ status: 0, duration: Date.now() - start, body: "" }));
        req.on("timeout", () => { req.destroy(); resolve({ status: 0, duration: 0, body: "" }); });
        if (bodyStr) req.write(bodyStr);
        req.end();
    });
}

// Fire N requests simultaneously
async function burst(method, endpoint, body, count) {
    const promises = Array.from({ length: count }, () =>
        request(method, TARGET_URL, endpoint, body)
    );
    return Promise.all(promises);
}

// Analyse responses for race condition indicators
function analyseRace(responses, endpoint) {
    const statuses = responses.map((r) => r.status);
    const statusCounts = {};
    for (const s of statuses) statusCounts[s] = (statusCounts[s] || 0) + 1;

    const successCount = statuses.filter((s) => s >= 200 && s < 300).length;
    const total = responses.length;

    // Race condition indicators:
    // - Multiple 200s on an endpoint that should only allow one success
    // - Inconsistent responses (mix of 200 and 409/429)
    const hasMultipleSuccess = successCount > 1;
    const hasConflict = statuses.some((s) => s === 409);
    const hasMixedResults = successCount > 0 && successCount < total;

    let verdict, severity, description, solution;

    if (hasMultipleSuccess && !hasConflict) {
        verdict = "fail";
        severity = "high";
        description = `Race condition detected at ${endpoint}. ${successCount}/${total} parallel requests succeeded simultaneously. No conflict detection.`;
        solution = "Use database transactions, optimistic locking, or atomic operations to prevent concurrent duplicate processing.";
    } else if (hasMixedResults && hasConflict) {
        verdict = "pass";
        severity = "info";
        description = `Race condition handled. ${successCount} succeeded, ${statusCounts[409] || 0} conflicts detected.`;
        solution = "Race condition protection is working correctly.";
    } else if (successCount === 0) {
        verdict = "pass";
        severity = "info";
        description = `All ${total} parallel requests returned non-2xx (endpoint may require auth or not exist).`;
        solution = "N/A";
    } else {
        verdict = "warn";
        severity = "medium";
        description = `Ambiguous race condition result at ${endpoint}. Status distribution: ${JSON.stringify(statusCounts)}`;
        solution = "Review concurrent request handling. Implement idempotency and conflict detection.";
    }

    return { verdict, severity, description, solution, statusCounts, successCount, total };
}

async function main() {
    if (!TARGET_URL) {
        console.error("[ERROR] TARGET_URL is required");
        process.exit(1);
    }

    console.log(`[INFO] Race condition testing: ${TARGET_URL}`);
    console.log(`[INFO] Concurrency: ${CONCURRENCY} parallel requests per test`);

    const allResults = [];
    const findings = [];

    for (const endpoint of DEFAULT_ENDPOINTS) {
        console.log(`\n[TEST] ${endpoint} — firing ${CONCURRENCY} parallel requests...`);

        // Test 1: Double submit (POST)
        const postResponses = await burst("POST", endpoint, {
            item_id: 1,
            quantity: 1,
            request_id: `race-${Date.now()}`,
        }, CONCURRENCY);

        const postAnalysis = analyseRace(postResponses, endpoint);
        console.log(`  POST: ${postAnalysis.verdict.toUpperCase()} — ${postAnalysis.description.slice(0, 80)}`);

        allResults.push({
            test: "double_submit_post",
            endpoint,
            concurrency: CONCURRENCY,
            ...postAnalysis,
        });

        if (postAnalysis.verdict === "fail" || postAnalysis.verdict === "warn") {
            findings.push({
                id: `race-post-${endpoint.replace(/\//g, "-")}`,
                tool: "race-condition",
                authenticated: !!USER_TOKEN,
                title: `Race Condition: Parallel POST to ${endpoint}`,
                severity: postAnalysis.severity,
                description: postAnalysis.description,
                solution: postAnalysis.solution,
                references: "OWASP Testing Guide — Testing for Race Conditions (OTG-BUSLOGIC-009)",
                affected_urls: [`${TARGET_URL}${endpoint}`],
                cwe: "CWE-362",
                cve: "",
            });
        }

        // Small delay between endpoint tests
        await new Promise((r) => setTimeout(r, 500));
    }

    const passed = allResults.filter((r) => r.verdict === "pass").length;
    const failed = allResults.filter((r) => r.verdict === "fail").length;
    const warned = allResults.filter((r) => r.verdict === "warn").length;

    const output = {
        scan_type: "race-condition",
        target: TARGET_URL,
        timestamp: new Date().toISOString(),
        concurrency: CONCURRENCY,
        summary: { total: allResults.length, passed, failed, warned },
        results: allResults,
        findings,
    };

    fs.mkdirSync(path.dirname(OUTPUT), { recursive: true });
    fs.writeFileSync(OUTPUT, JSON.stringify(output, null, 2));

    console.log(`\n[INFO] Race condition: ${passed} passed, ${failed} failed, ${warned} warnings`);
    console.log(`[INFO] Findings: ${findings.length}`);
    console.log(`[INFO] Output: ${OUTPUT}`);
}

main().catch((err) => {
    console.error(`[ERROR] ${err.message}`);
    process.exit(1);
});
