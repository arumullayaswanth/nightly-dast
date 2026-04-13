/**
 * authz-matrix.js
 * Phase 2 — Authorization Matrix Testing
 *
 * Tests access control across three identity levels:
 *   - anonymous  (no credentials)
 *   - user       (standard authenticated user)
 *   - admin      (privileged user)
 *
 * For each role, attempts to access a set of endpoints and records:
 *   - HTTP status code received
 *   - Whether access was expected or unexpected
 *   - IDOR/BOLA indicators (accessing other users' resources)
 *
 * Required env vars:
 *   TARGET_URL              — base URL to test
 *   USER_TOKEN              — Bearer token for standard user (optional)
 *   ADMIN_TOKEN             — Bearer token for admin user (optional)
 *   AUTHZ_ENDPOINTS         — comma-separated list of paths to test (optional)
 *   AUTHZ_OUTPUT            — output JSON file path
 *
 * Outputs:
 *   artifacts/raw/authz/authz-matrix.json
 */

const https = require("https");
const http = require("http");
const fs = require("fs");
const path = require("path");
const url = require("url");

const TARGET_URL = process.env.TARGET_URL || "";
const USER_TOKEN = process.env.USER_TOKEN || "";
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || "";
const AUTHZ_OUTPUT = process.env.AUTHZ_OUTPUT || "artifacts/raw/authz/authz-matrix.json";

// Default endpoints to probe — override with AUTHZ_ENDPOINTS env var
const DEFAULT_ENDPOINTS = [
    { path: "/api/users", expected: { anonymous: 401, user: 200, admin: 200 } },
    { path: "/api/users/1", expected: { anonymous: 401, user: 200, admin: 200 } },
    { path: "/api/users/2", expected: { anonymous: 401, user: 403, admin: 200 } },
    { path: "/api/admin", expected: { anonymous: 401, user: 403, admin: 200 } },
    { path: "/api/admin/users", expected: { anonymous: 401, user: 403, admin: 200 } },
    { path: "/api/profile", expected: { anonymous: 401, user: 200, admin: 200 } },
    { path: "/api/settings", expected: { anonymous: 401, user: 200, admin: 200 } },
    { path: "/api/reports", expected: { anonymous: 401, user: 403, admin: 200 } },
    { path: "/dashboard", expected: { anonymous: 302, user: 200, admin: 200 } },
    { path: "/admin", expected: { anonymous: 302, user: 403, admin: 200 } },
];

// Parse custom endpoints from env if provided
function parseEndpoints() {
    if (process.env.AUTHZ_ENDPOINTS) {
        return process.env.AUTHZ_ENDPOINTS.split(",").map((p) => ({
            path: p.trim(),
            expected: { anonymous: 401, user: 200, admin: 200 },
        }));
    }
    return DEFAULT_ENDPOINTS;
}

// Make a single HTTP request and return status code
function makeRequest(targetUrl, endpointPath, token) {
    return new Promise((resolve) => {
        const fullUrl = `${targetUrl}${endpointPath}`;
        const parsed = url.parse(fullUrl);
        const options = {
            hostname: parsed.hostname,
            port: parsed.port || (parsed.protocol === "https:" ? 443 : 80),
            path: parsed.path,
            method: "GET",
            headers: {
                "User-Agent": "DAST-AuthzMatrix/1.0",
                Accept: "application/json, text/html",
                ...(token ? { Authorization: `Bearer ${token}` } : {}),
            },
            timeout: 10000,
            rejectUnauthorized: false,
        };

        const proto = parsed.protocol === "https:" ? https : http;
        const req = proto.request(options, (res) => {
            resolve({ status: res.statusCode, headers: res.headers });
            res.resume();
        });

        req.on("error", () => resolve({ status: 0, headers: {} }));
        req.on("timeout", () => { req.destroy(); resolve({ status: 0, headers: {} }); });
        req.end();
    });
}

// Classify a result as pass/fail/unexpected
function classify(role, actual, expected) {
    if (actual === 0) return "error";
    if (expected[role] === undefined) return "untested";
    if (actual === expected[role]) return "pass";
    // Some flexibility — 401 and 403 are both "access denied"
    const accessDenied = [401, 403];
    if (accessDenied.includes(actual) && accessDenied.includes(expected[role])) return "pass";
    // Redirect variants
    if ([301, 302, 307, 308].includes(actual) && [301, 302, 307, 308].includes(expected[role])) return "pass";
    return "fail";
}

async function main() {
    if (!TARGET_URL) {
        console.error("[ERROR] TARGET_URL is required");
        process.exit(1);
    }

    const endpoints = parseEndpoints();
    const roles = [
        { name: "anonymous", token: "" },
        { name: "user", token: USER_TOKEN },
        { name: "admin", token: ADMIN_TOKEN },
    ];

    console.log(`[INFO] Authorization matrix test: ${TARGET_URL}`);
    console.log(`[INFO] Testing ${endpoints.length} endpoints × ${roles.length} roles`);

    const results = [];
    let totalTests = 0;
    let passed = 0;
    let failed = 0;
    let errors = 0;

    for (const endpoint of endpoints) {
        const row = {
            path: endpoint.path,
            expected: endpoint.expected,
            results: {},
            issues: [],
        };

        for (const role of roles) {
            // Skip roles with no token if token is required
            const response = await makeRequest(TARGET_URL, endpoint.path, role.token);
            const verdict = classify(role.name, response.status, endpoint.expected);

            row.results[role.name] = {
                status: response.status,
                expected: endpoint.expected[role.name],
                verdict,
            };

            totalTests++;
            if (verdict === "pass") passed++;
            else if (verdict === "fail") {
                failed++;
                row.issues.push({
                    role: role.name,
                    expected: endpoint.expected[role.name],
                    actual: response.status,
                    severity: role.name === "anonymous" && response.status === 200 ? "high" : "medium",
                    description: `${role.name} got HTTP ${response.status} on ${endpoint.path} (expected ${endpoint.expected[role.name]})`,
                });
            } else if (verdict === "error") {
                errors++;
            }

            process.stdout.write(`  [${verdict.toUpperCase()}] ${role.name.padEnd(10)} ${endpoint.path} → ${response.status}\n`);
        }

        results.push(row);
    }

    // Build findings for normalize-reports.py ingestion
    const findings = [];
    for (const row of results) {
        for (const issue of row.issues) {
            findings.push({
                id: `authz-${issue.role}-${row.path.replace(/\//g, "-")}`,
                tool: "authz-matrix",
                authenticated: issue.role !== "anonymous",
                title: `Authorization Issue: ${issue.role} accessed ${row.path}`,
                severity: issue.severity,
                description: issue.description,
                solution: "Review access control logic for this endpoint. Ensure proper role-based authorization is enforced.",
                references: "OWASP ASVS V4 Access Control",
                affected_urls: [`${TARGET_URL}${row.path}`],
                cwe: "CWE-285",
                cve: "",
            });
        }
    }

    const output = {
        scan_type: "authz-matrix",
        target: TARGET_URL,
        timestamp: new Date().toISOString(),
        summary: { total: totalTests, passed, failed, errors },
        matrix: results,
        findings,
    };

    fs.mkdirSync(path.dirname(AUTHZ_OUTPUT), { recursive: true });
    fs.writeFileSync(AUTHZ_OUTPUT, JSON.stringify(output, null, 2));

    console.log(`\n[INFO] Results: ${passed} passed, ${failed} failed, ${errors} errors`);
    console.log(`[INFO] Findings: ${findings.length} authorization issues`);
    console.log(`[INFO] Output written to ${AUTHZ_OUTPUT}`);

    if (failed > 0) process.exit(1);
}

main().catch((err) => {
    console.error(`[ERROR] ${err.message}`);
    process.exit(1);
});
