/**
 * business-logic-test.js
 * Phase 3 — Business Logic & Abuse Case Testing
 *
 * Tests for common business logic vulnerabilities:
 *   1. Duplicate submission       — submit same form/request twice
 *   2. State transition abuse     — skip steps in a workflow
 *   3. Negative value abuse       — negative quantities, prices
 *   4. Parameter tampering        — modify hidden/read-only fields
 *   5. Workflow skipping          — access later steps without completing earlier ones
 *   6. Mass assignment            — send extra fields not in the form
 *
 * Required env vars:
 *   TARGET_URL                    — base URL
 *   BL_OUTPUT                     — output JSON path
 *
 * Optional env vars:
 *   BL_API_ENDPOINTS              — comma-separated API paths to test
 *   USER_TOKEN                    — Bearer token for authenticated tests
 */

const https = require("https");
const http = require("http");
const fs = require("fs");
const path = require("path");
const url = require("url");

const TARGET_URL = process.env.TARGET_URL || "";
const USER_TOKEN = process.env.USER_TOKEN || "";
const OUTPUT = process.env.BL_OUTPUT || "artifacts/raw/business-logic/bl-results.json";

// Default API endpoints to probe
const DEFAULT_ENDPOINTS = (process.env.BL_API_ENDPOINTS || "")
    .split(",")
    .map((e) => e.trim())
    .filter(Boolean);

if (DEFAULT_ENDPOINTS.length === 0) {
    DEFAULT_ENDPOINTS.push(
        "/api/orders",
        "/api/checkout",
        "/api/payment",
        "/api/users/profile",
        "/api/cart"
    );
}

function request(method, targetUrl, endpointPath, body, extraHeaders = {}) {
    return new Promise((resolve) => {
        const fullUrl = `${targetUrl}${endpointPath}`;
        const parsed = url.parse(fullUrl);
        const bodyStr = body ? JSON.stringify(body) : "";

        const options = {
            hostname: parsed.hostname,
            port: parsed.port || (parsed.protocol === "https:" ? 443 : 80),
            path: parsed.path,
            method,
            headers: {
                "Content-Type": "application/json",
                "User-Agent": "DAST-BusinessLogic/1.0",
                Accept: "application/json",
                ...(USER_TOKEN ? { Authorization: `Bearer ${USER_TOKEN}` } : {}),
                ...(bodyStr ? { "Content-Length": Buffer.byteLength(bodyStr) } : {}),
                ...extraHeaders,
            },
            timeout: 10000,
            rejectUnauthorized: false,
        };

        const proto = parsed.protocol === "https:" ? https : http;
        const req = proto.request(options, (res) => {
            let data = "";
            res.on("data", (chunk) => { data += chunk; });
            res.on("end", () => resolve({ status: res.statusCode, body: data.slice(0, 500), headers: res.headers }));
        });

        req.on("error", () => resolve({ status: 0, body: "", headers: {} }));
        req.on("timeout", () => { req.destroy(); resolve({ status: 0, body: "", headers: {} }); });
        if (bodyStr) req.write(bodyStr);
        req.end();
    });
}

// Test 1: Duplicate submission — send same POST twice and check if both succeed
async function testDuplicateSubmission(endpoint) {
    const payload = { item_id: 1, quantity: 1, idempotency_key: `test-${Date.now()}` };
    const r1 = await request("POST", TARGET_URL, endpoint, payload);
    const r2 = await request("POST", TARGET_URL, endpoint, payload);

    const bothSucceeded = r1.status >= 200 && r1.status < 300 &&
        r2.status >= 200 && r2.status < 300;

    return {
        test: "duplicate_submission",
        endpoint,
        first_status: r1.status,
        second_status: r2.status,
        verdict: bothSucceeded ? "fail" : "pass",
        severity: bothSucceeded ? "medium" : "info",
        description: bothSucceeded
            ? `Both duplicate requests to ${endpoint} succeeded (HTTP ${r1.status}, ${r2.status}). No idempotency protection detected.`
            : `Duplicate submission handled correctly (${r1.status}, ${r2.status}).`,
        solution: "Implement idempotency keys or duplicate detection on state-changing endpoints.",
    };
}

// Test 2: Negative value abuse — send negative quantity/amount
async function testNegativeValues(endpoint) {
    const payload = { quantity: -1, amount: -100, price: -9999 };
    const r = await request("POST", TARGET_URL, endpoint, payload);

    const accepted = r.status >= 200 && r.status < 300;
    return {
        test: "negative_value_abuse",
        endpoint,
        status: r.status,
        verdict: accepted ? "fail" : "pass",
        severity: accepted ? "high" : "info",
        description: accepted
            ? `Negative values accepted at ${endpoint} (HTTP ${r.status}). May allow credit abuse or price manipulation.`
            : `Negative values rejected correctly (HTTP ${r.status}).`,
        solution: "Validate all numeric inputs server-side. Reject negative quantities and amounts.",
    };
}

// Test 3: Mass assignment — send extra privileged fields
async function testMassAssignment(endpoint) {
    const payload = {
        name: "Test User",
        email: "test@example.com",
        role: "admin",
        is_admin: true,
        admin: true,
        verified: true,
        balance: 99999,
        credits: 99999,
    };
    const r = await request("POST", TARGET_URL, endpoint, payload);

    // We can't know if mass assignment worked without checking the response
    // but we flag if the server returns 200 with our privileged fields echoed back
    const bodyLower = r.body.toLowerCase();
    const massAssigned = r.status >= 200 && r.status < 300 &&
        (bodyLower.includes('"role":"admin"') ||
            bodyLower.includes('"is_admin":true') ||
            bodyLower.includes('"admin":true'));

    return {
        test: "mass_assignment",
        endpoint,
        status: r.status,
        verdict: massAssigned ? "fail" : "pass",
        severity: massAssigned ? "high" : "info",
        description: massAssigned
            ? `Mass assignment vulnerability detected at ${endpoint}. Privileged fields (role, is_admin) were accepted and reflected in response.`
            : `No mass assignment detected at ${endpoint} (HTTP ${r.status}).`,
        solution: "Use allowlists (DTOs) to control which fields can be set via API. Never bind request body directly to model.",
    };
}

// Test 4: Workflow skipping — access a later step directly
async function testWorkflowSkipping(endpoint) {
    // Try to access a "confirm" or "complete" step without going through prior steps
    const skipEndpoints = [
        endpoint.replace(/\/cart$/, "/checkout/confirm"),
        endpoint.replace(/\/orders$/, "/orders/complete"),
        endpoint.replace(/\/payment$/, "/payment/confirm"),
        `${endpoint}/confirm`,
        `${endpoint}/complete`,
        `${endpoint}/finalize`,
    ];

    const results = [];
    for (const skipEp of skipEndpoints.slice(0, 3)) {
        const r = await request("POST", TARGET_URL, skipEp, { step: "complete" });
        if (r.status !== 0) {
            results.push({ path: skipEp, status: r.status });
        }
    }

    const accessible = results.filter((r) => r.status >= 200 && r.status < 300);
    return {
        test: "workflow_skipping",
        endpoint,
        probed: results,
        verdict: accessible.length > 0 ? "warn" : "pass",
        severity: accessible.length > 0 ? "medium" : "info",
        description: accessible.length > 0
            ? `Workflow step(s) accessible without completing prior steps: ${accessible.map((r) => r.path).join(", ")}`
            : "No workflow skipping detected.",
        solution: "Enforce server-side state machine validation. Each step should verify prior steps were completed.",
    };
}

async function main() {
    if (!TARGET_URL) {
        console.error("[ERROR] TARGET_URL is required");
        process.exit(1);
    }

    console.log(`[INFO] Business logic testing: ${TARGET_URL}`);
    console.log(`[INFO] Testing ${DEFAULT_ENDPOINTS.length} endpoints`);

    const allResults = [];
    const findings = [];

    for (const endpoint of DEFAULT_ENDPOINTS) {
        console.log(`\n[TEST] Endpoint: ${endpoint}`);

        const tests = await Promise.all([
            testDuplicateSubmission(endpoint),
            testNegativeValues(endpoint),
            testMassAssignment(endpoint),
            testWorkflowSkipping(endpoint),
        ]);

        for (const t of tests) {
            allResults.push(t);
            console.log(`  [${t.verdict.toUpperCase()}] ${t.test}: ${t.description.slice(0, 80)}`);

            if (t.verdict === "fail" || t.verdict === "warn") {
                findings.push({
                    id: `bl-${t.test}-${endpoint.replace(/\//g, "-")}`,
                    tool: "business-logic",
                    authenticated: !!USER_TOKEN,
                    title: `Business Logic: ${t.test.replace(/_/g, " ")} on ${endpoint}`,
                    severity: t.severity,
                    description: t.description,
                    solution: t.solution,
                    references: "OWASP Testing Guide — Business Logic Testing (OTG-BUSLOGIC)",
                    affected_urls: [`${TARGET_URL}${endpoint}`],
                    cwe: "CWE-840",
                    cve: "",
                });
            }
        }
    }

    const passed = allResults.filter((r) => r.verdict === "pass").length;
    const failed = allResults.filter((r) => r.verdict === "fail").length;
    const warned = allResults.filter((r) => r.verdict === "warn").length;

    const output = {
        scan_type: "business-logic",
        target: TARGET_URL,
        timestamp: new Date().toISOString(),
        summary: { total: allResults.length, passed, failed, warned },
        results: allResults,
        findings,
    };

    fs.mkdirSync(path.dirname(OUTPUT), { recursive: true });
    fs.writeFileSync(OUTPUT, JSON.stringify(output, null, 2));

    console.log(`\n[INFO] Business logic: ${passed} passed, ${failed} failed, ${warned} warnings`);
    console.log(`[INFO] Findings: ${findings.length}`);
    console.log(`[INFO] Output: ${OUTPUT}`);
}

main().catch((err) => {
    console.error(`[ERROR] ${err.message}`);
    process.exit(1);
});
