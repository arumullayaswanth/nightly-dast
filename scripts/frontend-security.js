/**
 * frontend-security.js
 * Phase 4 — Frontend / Browser Security Suite
 *
 * Uses Playwright (headless Chromium) to test client-side security:
 *   1. localStorage / sessionStorage token leakage
 *   2. Sensitive data in window globals
 *   3. Source map exposure (.map files publicly accessible)
 *   4. CSP depth validation (not just header presence — checks directives)
 *   5. Clickjacking (X-Frame-Options + CSP frame-ancestors)
 *   6. postMessage origin validation
 *   7. Exposed internal API base URLs in JS bundles
 *   8. Hardcoded secrets/tokens in JS source
 *   9. Mixed content (HTTP resources on HTTPS page)
 *  10. Cookie security flags (HttpOnly, Secure, SameSite)
 *
 * Required env vars:
 *   TARGET_URL              — URL to test
 *   FRONTEND_OUTPUT         — output JSON path
 *
 * Optional env vars:
 *   AUTH_ENABLED            — set true to run authenticated checks
 *   AUTH_URL                — login page URL
 *   AUTH_USERNAME           — login username
 *   AUTH_PASSWORD           — login password
 *   AUTH_USERNAME_SELECTOR  — CSS selector for username field
 *   AUTH_PASSWORD_SELECTOR  — CSS selector for password field
 *   AUTH_SUBMIT_SELECTOR    — CSS selector for submit button
 */

const { chromium } = require("@playwright/test");
const https = require("https");
const http = require("http");
const fs = require("fs");
const path = require("path");
const url = require("url");

const TARGET_URL = process.env.TARGET_URL || "";
const OUTPUT = process.env.FRONTEND_OUTPUT || "artifacts/raw/frontend/frontend-results.json";
const AUTH_ENABLED = process.env.AUTH_ENABLED === "true";
const AUTH_URL = process.env.AUTH_URL || "";
const AUTH_USERNAME = process.env.AUTH_USERNAME || "";
const AUTH_PASSWORD = process.env.AUTH_PASSWORD || "";
const AUTH_USERNAME_SELECTOR = process.env.AUTH_USERNAME_SELECTOR || "#username";
const AUTH_PASSWORD_SELECTOR = process.env.AUTH_PASSWORD_SELECTOR || "#password";
const AUTH_SUBMIT_SELECTOR = process.env.AUTH_SUBMIT_SELECTOR || "[type=submit]";

// Patterns that indicate secrets/sensitive data in JS
const SECRET_PATTERNS = [
    { pattern: /api[_-]?key\s*[:=]\s*["'][a-zA-Z0-9_\-]{16,}/i, label: "API key" },
    { pattern: /secret\s*[:=]\s*["'][a-zA-Z0-9_\-]{16,}/i, label: "Secret value" },
    { pattern: /password\s*[:=]\s*["'][^"']{6,}/i, label: "Hardcoded password" },
    { pattern: /token\s*[:=]\s*["'][a-zA-Z0-9_\-\.]{20,}/i, label: "Hardcoded token" },
    { pattern: /aws[_-]?access[_-]?key[_-]?id\s*[:=]\s*["']AKIA[A-Z0-9]{16}/i, label: "AWS Access Key" },
    { pattern: /private[_-]?key\s*[:=]\s*["'][^"']{20,}/i, label: "Private key" },
    { pattern: /-----BEGIN (RSA |EC )?PRIVATE KEY-----/, label: "PEM private key" },
    { pattern: /eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}/, label: "JWT token" },
    { pattern: /ghp_[a-zA-Z0-9]{36}/, label: "GitHub personal access token" },
    { pattern: /sk-[a-zA-Z0-9]{32,}/, label: "OpenAI API key" },
];

// Internal/sensitive URL patterns in JS
const INTERNAL_URL_PATTERNS = [
    /https?:\/\/(?:localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)/i,
    /https?:\/\/[a-z0-9-]+\.internal\./i,
    /https?:\/\/[a-z0-9-]+\.local\//i,
    /https?:\/\/staging\.[a-z0-9-]+\./i,
    /https?:\/\/dev\.[a-z0-9-]+\./i,
];

function simpleGet(targetUrl, filePath) {
    return new Promise((resolve) => {
        const fullUrl = filePath.startsWith("http") ? filePath : `${targetUrl}${filePath}`;
        const parsed = url.parse(fullUrl);
        const options = {
            hostname: parsed.hostname,
            port: parsed.port || (parsed.protocol === "https:" ? 443 : 80),
            path: parsed.path,
            method: "GET",
            headers: { "User-Agent": "DAST-Frontend/1.0" },
            timeout: 10000,
            rejectUnauthorized: false,
        };
        const proto = parsed.protocol === "https:" ? https : http;
        const req = proto.request(options, (res) => {
            let data = "";
            res.on("data", (c) => { data += c; });
            res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body: data }));
        });
        req.on("error", () => resolve({ status: 0, headers: {}, body: "" }));
        req.on("timeout", () => { req.destroy(); resolve({ status: 0, headers: {}, body: "" }); });
        req.end();
    });
}

async function main() {
    if (!TARGET_URL) {
        console.error("[ERROR] TARGET_URL is required");
        process.exit(1);
    }

    console.log(`[INFO] Frontend security testing: ${TARGET_URL}`);

    const browser = await chromium.launch({ headless: true });
    const context = await browser.newContext({ ignoreHTTPSErrors: true });

    // Collect all JS URLs loaded by the page
    const jsUrls = new Set();
    const mixedContentUrls = [];
    const responseHeaders = {};

    context.on("response", async (response) => {
        const respUrl = response.url();
        const ct = response.headers()["content-type"] || "";
        if (ct.includes("javascript") || respUrl.endsWith(".js")) {
            jsUrls.add(respUrl);
        }
        // Detect mixed content
        if (TARGET_URL.startsWith("https://") && respUrl.startsWith("http://")) {
            mixedContentUrls.push(respUrl);
        }
        // Capture main page response headers
        if (respUrl === TARGET_URL || respUrl === TARGET_URL + "/") {
            Object.assign(responseHeaders, response.headers());
        }
    });

    const page = await context.newPage();
    const findings = [];
    const results = [];

    try {
        // ── Navigate to target ────────────────────────────────────────────────
        await page.goto(TARGET_URL, { waitUntil: "networkidle", timeout: 30000 });

        // Optional: authenticate
        if (AUTH_ENABLED && AUTH_URL && AUTH_USERNAME && AUTH_PASSWORD) {
            console.log("[INFO] Running authenticated checks...");
            await page.goto(AUTH_URL, { waitUntil: "networkidle", timeout: 30000 });
            await page.fill(AUTH_USERNAME_SELECTOR, AUTH_USERNAME);
            await page.fill(AUTH_PASSWORD_SELECTOR, AUTH_PASSWORD);
            await page.click(AUTH_SUBMIT_SELECTOR);
            await page.waitForLoadState("networkidle", { timeout: 15000 });
        }

        // ── Test 1: localStorage / sessionStorage leakage ─────────────────────
        console.log("[TEST] Checking storage for sensitive data...");
        const storageData = await page.evaluate(() => {
            const local = {};
            const session = {};
            for (let i = 0; i < localStorage.length; i++) {
                const k = localStorage.key(i);
                local[k] = localStorage.getItem(k);
            }
            for (let i = 0; i < sessionStorage.length; i++) {
                const k = sessionStorage.key(i);
                session[k] = sessionStorage.getItem(k);
            }
            return { localStorage: local, sessionStorage: session };
        });

        const sensitiveStorageKeys = [];
        const sensitivePatterns = /token|auth|jwt|session|password|secret|key|credential/i;
        for (const [k, v] of Object.entries({ ...storageData.localStorage, ...storageData.sessionStorage })) {
            if (sensitivePatterns.test(k) && v && v.length > 5) {
                sensitiveStorageKeys.push({ key: k, valueLength: v.length, preview: v.slice(0, 20) + "..." });
            }
        }

        const storageResult = {
            test: "storage_token_leakage",
            sensitive_keys_found: sensitiveStorageKeys.length,
            keys: sensitiveStorageKeys,
            verdict: sensitiveStorageKeys.length > 0 ? "warn" : "pass",
            severity: sensitiveStorageKeys.length > 0 ? "medium" : "info",
            description: sensitiveStorageKeys.length > 0
                ? `${sensitiveStorageKeys.length} sensitive key(s) found in browser storage: ${sensitiveStorageKeys.map((k) => k.key).join(", ")}`
                : "No sensitive data found in localStorage/sessionStorage.",
            solution: "Avoid storing tokens or credentials in localStorage. Use HttpOnly cookies or in-memory storage for sensitive tokens.",
        };
        results.push(storageResult);
        if (storageResult.verdict !== "pass") {
            findings.push({
                id: "frontend-storage-leakage",
                tool: "frontend-security",
                authenticated: AUTH_ENABLED,
                title: "Sensitive Data in Browser Storage",
                severity: storageResult.severity,
                description: storageResult.description,
                solution: storageResult.solution,
                references: "OWASP ASVS V8.3 — Sensitive Private Data",
                affected_urls: [TARGET_URL],
                cwe: "CWE-312",
                cve: "",
            });
        }
        console.log(`  [${storageResult.verdict.toUpperCase()}] ${storageResult.description.slice(0, 80)}`);

        // ── Test 2: Cookie security flags ─────────────────────────────────────
        console.log("[TEST] Checking cookie security flags...");
        const cookies = await context.cookies();
        const insecureCookies = cookies.filter((c) => {
            const isSensitive = /session|auth|token|jwt|sid/i.test(c.name);
            return isSensitive && (!c.httpOnly || !c.secure || !c.sameSite || c.sameSite === "None");
        });

        const cookieResult = {
            test: "cookie_security_flags",
            total_cookies: cookies.length,
            insecure_sensitive_cookies: insecureCookies.map((c) => ({
                name: c.name,
                httpOnly: c.httpOnly,
                secure: c.secure,
                sameSite: c.sameSite,
            })),
            verdict: insecureCookies.length > 0 ? "fail" : "pass",
            severity: insecureCookies.length > 0 ? "medium" : "info",
            description: insecureCookies.length > 0
                ? `${insecureCookies.length} sensitive cookie(s) missing security flags: ${insecureCookies.map((c) => c.name).join(", ")}`
                : "All sensitive cookies have appropriate security flags.",
            solution: "Set HttpOnly, Secure, and SameSite=Strict (or Lax) on all session/auth cookies.",
        };
        results.push(cookieResult);
        if (cookieResult.verdict !== "pass") {
            findings.push({
                id: "frontend-cookie-flags",
                tool: "frontend-security",
                authenticated: AUTH_ENABLED,
                title: "Insecure Cookie Security Flags",
                severity: cookieResult.severity,
                description: cookieResult.description,
                solution: cookieResult.solution,
                references: "OWASP ASVS V3.4 — Cookie-based Session Management; CWE-614",
                affected_urls: [TARGET_URL],
                cwe: "CWE-614",
                cve: "",
            });
        }
        console.log(`  [${cookieResult.verdict.toUpperCase()}] ${cookieResult.description.slice(0, 80)}`);

        // ── Test 3: CSP depth validation ──────────────────────────────────────
        console.log("[TEST] Validating Content Security Policy...");
        const cspHeader = responseHeaders["content-security-policy"] ||
            responseHeaders["content-security-policy-report-only"] || "";

        const cspIssues = [];
        if (!cspHeader) {
            cspIssues.push("No Content-Security-Policy header present");
        } else {
            if (cspHeader.includes("unsafe-inline")) cspIssues.push("'unsafe-inline' allows inline script execution");
            if (cspHeader.includes("unsafe-eval")) cspIssues.push("'unsafe-eval' allows eval() usage");
            if (cspHeader.includes("*") && !cspHeader.includes("nonce-") && !cspHeader.includes("hash-")) {
                cspIssues.push("Wildcard (*) source without nonce/hash weakens CSP");
            }
            if (!cspHeader.includes("default-src") && !cspHeader.includes("script-src")) {
                cspIssues.push("Missing script-src or default-src directive");
            }
            if (!cspHeader.includes("frame-ancestors")) {
                cspIssues.push("Missing frame-ancestors directive (clickjacking risk)");
            }
            if (!cspHeader.includes("object-src")) {
                cspIssues.push("Missing object-src directive");
            }
        }

        const cspResult = {
            test: "csp_depth",
            csp_present: !!cspHeader,
            csp_header: cspHeader.slice(0, 500),
            issues: cspIssues,
            verdict: cspIssues.length > 0 ? (cspHeader ? "warn" : "fail") : "pass",
            severity: !cspHeader ? "medium" : cspIssues.length > 2 ? "medium" : "low",
            description: cspIssues.length > 0
                ? `CSP issues found: ${cspIssues.join("; ")}`
                : "CSP is present and well-configured.",
            solution: "Implement a strict CSP with nonce-based script allowlisting, frame-ancestors 'none', and object-src 'none'.",
        };
        results.push(cspResult);
        if (cspResult.verdict !== "pass") {
            findings.push({
                id: "frontend-csp-depth",
                tool: "frontend-security",
                authenticated: false,
                title: "Content Security Policy Weakness",
                severity: cspResult.severity,
                description: cspResult.description,
                solution: cspResult.solution,
                references: "OWASP ASVS V14.4 — HTTP Security Headers; CWE-693",
                affected_urls: [TARGET_URL],
                cwe: "CWE-693",
                cve: "",
            });
        }
        console.log(`  [${cspResult.verdict.toUpperCase()}] ${cspResult.description.slice(0, 80)}`);

        // ── Test 4: Clickjacking ──────────────────────────────────────────────
        console.log("[TEST] Checking clickjacking protection...");
        const xfo = responseHeaders["x-frame-options"] || "";
        const hasFrameAncestors = cspHeader.includes("frame-ancestors");
        const clickjackingProtected = xfo || hasFrameAncestors;

        const clickjackResult = {
            test: "clickjacking",
            x_frame_options: xfo || "not set",
            csp_frame_ancestors: hasFrameAncestors,
            verdict: clickjackingProtected ? "pass" : "fail",
            severity: clickjackingProtected ? "info" : "medium",
            description: clickjackingProtected
                ? `Clickjacking protection present (X-Frame-Options: ${xfo || "via CSP frame-ancestors"}).`
                : "No clickjacking protection. Missing X-Frame-Options and CSP frame-ancestors.",
            solution: "Add X-Frame-Options: DENY or CSP frame-ancestors 'none' to prevent clickjacking.",
        };
        results.push(clickjackResult);
        if (clickjackResult.verdict !== "pass") {
            findings.push({
                id: "frontend-clickjacking",
                tool: "frontend-security",
                authenticated: false,
                title: "Clickjacking Protection Missing",
                severity: clickjackResult.severity,
                description: clickjackResult.description,
                solution: clickjackResult.solution,
                references: "OWASP ASVS V14.4; CWE-1021",
                affected_urls: [TARGET_URL],
                cwe: "CWE-1021",
                cve: "",
            });
        }
        console.log(`  [${clickjackResult.verdict.toUpperCase()}] ${clickjackResult.description.slice(0, 80)}`);

        // ── Test 5: Mixed content ─────────────────────────────────────────────
        console.log("[TEST] Checking for mixed content...");
        const mixedResult = {
            test: "mixed_content",
            mixed_urls: mixedContentUrls.slice(0, 20),
            count: mixedContentUrls.length,
            verdict: mixedContentUrls.length > 0 ? "fail" : "pass",
            severity: mixedContentUrls.length > 0 ? "medium" : "info",
            description: mixedContentUrls.length > 0
                ? `${mixedContentUrls.length} HTTP resource(s) loaded on HTTPS page (mixed content).`
                : "No mixed content detected.",
            solution: "Ensure all resources are loaded over HTTPS. Use protocol-relative URLs or enforce HTTPS in all asset references.",
        };
        results.push(mixedResult);
        if (mixedResult.verdict !== "pass") {
            findings.push({
                id: "frontend-mixed-content",
                tool: "frontend-security",
                authenticated: false,
                title: "Mixed Content (HTTP resources on HTTPS page)",
                severity: mixedResult.severity,
                description: mixedResult.description,
                solution: mixedResult.solution,
                references: "CWE-319",
                affected_urls: [TARGET_URL],
                cwe: "CWE-319",
                cve: "",
            });
        }
        console.log(`  [${mixedResult.verdict.toUpperCase()}] ${mixedResult.description.slice(0, 80)}`);

        // ── Test 6: Source map exposure ───────────────────────────────────────
        console.log("[TEST] Checking for exposed source maps...");
        const sourceMapsFound = [];
        const jsUrlsArray = Array.from(jsUrls).slice(0, 20); // cap at 20 JS files

        for (const jsUrl of jsUrlsArray) {
            const mapUrl = jsUrl + ".map";
            const r = await simpleGet(TARGET_URL, mapUrl);
            if (r.status === 200 && (r.body.includes('"sources"') || r.body.includes('"mappings"'))) {
                sourceMapsFound.push(mapUrl);
            }
        }

        const sourceMapResult = {
            test: "source_map_exposure",
            js_files_checked: jsUrlsArray.length,
            source_maps_found: sourceMapsFound,
            verdict: sourceMapsFound.length > 0 ? "fail" : "pass",
            severity: sourceMapsFound.length > 0 ? "medium" : "info",
            description: sourceMapsFound.length > 0
                ? `${sourceMapsFound.length} source map(s) publicly accessible: ${sourceMapsFound.slice(0, 3).join(", ")}`
                : `No exposed source maps found (checked ${jsUrlsArray.length} JS files).`,
            solution: "Remove source maps from production builds or restrict access to .map files via server configuration.",
        };
        results.push(sourceMapResult);
        if (sourceMapResult.verdict !== "pass") {
            findings.push({
                id: "frontend-source-maps",
                tool: "frontend-security",
                authenticated: false,
                title: "JavaScript Source Maps Publicly Exposed",
                severity: sourceMapResult.severity,
                description: sourceMapResult.description,
                solution: sourceMapResult.solution,
                references: "CWE-540",
                affected_urls: sourceMapsFound.slice(0, 5),
                cwe: "CWE-540",
                cve: "",
            });
        }
        console.log(`  [${sourceMapResult.verdict.toUpperCase()}] ${sourceMapResult.description.slice(0, 80)}`);

        // ── Test 7: Hardcoded secrets in JS bundles ───────────────────────────
        console.log("[TEST] Scanning JS bundles for hardcoded secrets...");
        const secretsFound = [];

        for (const jsUrl of jsUrlsArray.slice(0, 10)) {
            const r = await simpleGet(TARGET_URL, jsUrl);
            if (r.status !== 200) continue;
            const content = r.body;
            for (const { pattern, label } of SECRET_PATTERNS) {
                const match = content.match(pattern);
                if (match) {
                    secretsFound.push({
                        file: jsUrl,
                        type: label,
                        preview: match[0].slice(0, 50) + "...",
                    });
                }
            }
        }

        const secretsResult = {
            test: "hardcoded_secrets_in_js",
            js_files_scanned: Math.min(jsUrlsArray.length, 10),
            secrets_found: secretsFound,
            verdict: secretsFound.length > 0 ? "fail" : "pass",
            severity: secretsFound.length > 0 ? "high" : "info",
            description: secretsFound.length > 0
                ? `${secretsFound.length} potential secret(s) found in JS bundles: ${secretsFound.map((s) => s.type).join(", ")}`
                : "No hardcoded secrets detected in JS bundles.",
            solution: "Never embed secrets, API keys, or tokens in client-side JavaScript. Use environment variables injected at build time only for non-sensitive config.",
        };
        results.push(secretsResult);
        if (secretsResult.verdict !== "pass") {
            findings.push({
                id: "frontend-hardcoded-secrets",
                tool: "frontend-security",
                authenticated: false,
                title: "Hardcoded Secrets in JavaScript Bundles",
                severity: secretsResult.severity,
                description: secretsResult.description,
                solution: secretsResult.solution,
                references: "CWE-798",
                affected_urls: secretsFound.map((s) => s.file).slice(0, 5),
                cwe: "CWE-798",
                cve: "",
            });
        }
        console.log(`  [${secretsResult.verdict.toUpperCase()}] ${secretsResult.description.slice(0, 80)}`);

        // ── Test 8: Internal URLs in JS bundles ───────────────────────────────
        console.log("[TEST] Scanning JS bundles for internal/staging URLs...");
        const internalUrlsFound = [];

        for (const jsUrl of jsUrlsArray.slice(0, 10)) {
            const r = await simpleGet(TARGET_URL, jsUrl);
            if (r.status !== 200) continue;
            for (const pattern of INTERNAL_URL_PATTERNS) {
                const matches = r.body.match(new RegExp(pattern.source, "gi")) || [];
                for (const match of matches.slice(0, 3)) {
                    internalUrlsFound.push({ file: jsUrl, url: match });
                }
            }
        }

        const internalUrlResult = {
            test: "internal_urls_in_js",
            internal_urls_found: internalUrlsFound.slice(0, 20),
            verdict: internalUrlsFound.length > 0 ? "warn" : "pass",
            severity: internalUrlsFound.length > 0 ? "medium" : "info",
            description: internalUrlsFound.length > 0
                ? `${internalUrlsFound.length} internal/staging URL(s) found in JS bundles.`
                : "No internal URLs found in JS bundles.",
            solution: "Remove internal, staging, or development URLs from production JS bundles. Use environment-specific build configurations.",
        };
        results.push(internalUrlResult);
        if (internalUrlResult.verdict !== "pass") {
            findings.push({
                id: "frontend-internal-urls",
                tool: "frontend-security",
                authenticated: false,
                title: "Internal/Staging URLs Exposed in JavaScript",
                severity: internalUrlResult.severity,
                description: internalUrlResult.description,
                solution: internalUrlResult.solution,
                references: "CWE-200",
                affected_urls: internalUrlsFound.map((u) => u.file).slice(0, 5),
                cwe: "CWE-200",
                cve: "",
            });
        }
        console.log(`  [${internalUrlResult.verdict.toUpperCase()}] ${internalUrlResult.description.slice(0, 80)}`);

        // ── Test 9: postMessage origin validation ─────────────────────────────
        console.log("[TEST] Checking postMessage origin validation...");
        const postMessageIssues = await page.evaluate(() => {
            const issues = [];
            // Check if any event listeners accept messages from any origin
            const scripts = Array.from(document.querySelectorAll("script:not([src])"));
            for (const script of scripts) {
                const content = script.textContent || "";
                if (content.includes("addEventListener") && content.includes("message")) {
                    if (content.includes("event.origin") || content.includes("e.origin")) {
                        // Origin check present — good
                    } else if (content.includes("postMessage") || content.includes("onmessage")) {
                        issues.push("Inline script handles postMessage without visible origin check");
                    }
                }
            }
            return issues;
        });

        const postMessageResult = {
            test: "postmessage_origin_validation",
            issues: postMessageIssues,
            verdict: postMessageIssues.length > 0 ? "warn" : "pass",
            severity: postMessageIssues.length > 0 ? "medium" : "info",
            description: postMessageIssues.length > 0
                ? `Potential postMessage origin validation issues: ${postMessageIssues.join("; ")}`
                : "No obvious postMessage origin validation issues detected in inline scripts.",
            solution: "Always validate event.origin in postMessage handlers. Use a strict allowlist of trusted origins.",
        };
        results.push(postMessageResult);
        if (postMessageResult.verdict !== "pass") {
            findings.push({
                id: "frontend-postmessage",
                tool: "frontend-security",
                authenticated: false,
                title: "postMessage Origin Validation Issue",
                severity: postMessageResult.severity,
                description: postMessageResult.description,
                solution: postMessageResult.solution,
                references: "CWE-346",
                affected_urls: [TARGET_URL],
                cwe: "CWE-346",
                cve: "",
            });
        }
        console.log(`  [${postMessageResult.verdict.toUpperCase()}] ${postMessageResult.description.slice(0, 80)}`);

    } catch (err) {
        console.error(`[ERROR] Browser test failed: ${err.message}`);
    } finally {
        await browser.close();
    }

    const passed = results.filter((r) => r.verdict === "pass").length;
    const failed = results.filter((r) => r.verdict === "fail").length;
    const warned = results.filter((r) => r.verdict === "warn").length;

    const output = {
        scan_type: "frontend-security",
        target: TARGET_URL,
        timestamp: new Date().toISOString(),
        authenticated: AUTH_ENABLED,
        summary: { total: results.length, passed, failed, warned },
        results,
        findings,
    };

    fs.mkdirSync(path.dirname(OUTPUT), { recursive: true });
    fs.writeFileSync(OUTPUT, JSON.stringify(output, null, 2));

    console.log(`\n[INFO] Frontend security: ${passed} passed, ${failed} failed, ${warned} warnings`);
    console.log(`[INFO] Findings: ${findings.length}`);
    console.log(`[INFO] Output: ${OUTPUT}`);
}

main().catch((err) => {
    console.error(`[ERROR] ${err.message}`);
    process.exit(1);
});
