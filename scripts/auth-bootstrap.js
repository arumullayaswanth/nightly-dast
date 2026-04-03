// Playwright headless login, exports cookies + tokens
/**
 * auth-bootstrap.js
 * Uses Playwright to perform a login flow and export session cookies/tokens
 * for use by downstream scan tools (ZAP, Nuclei, etc.)
 *
 * Required env vars:
 *   AUTH_URL                  — login page URL
 *   AUTH_USERNAME             — username/email
 *   AUTH_PASSWORD             — password
 *   AUTH_USERNAME_SELECTOR    — CSS selector for username field (default: #username)
 *   AUTH_PASSWORD_SELECTOR    — CSS selector for password field (default: #password)
 *   AUTH_SUBMIT_SELECTOR      — CSS selector for submit button (default: [type=submit])
 *   SESSION_COOKIE_NAME       — cookie name to extract (default: session)
 *
 * Outputs:
 *   /tmp/zap-session.txt      — cookie header string for ZAP
 *   /tmp/session-cookies.json — full cookie jar as JSON
 *   /tmp/auth-token.txt       — Bearer token if found in localStorage/response
 */

const { chromium } = require("playwright");
const fs = require("fs");

const {
    AUTH_URL,
    AUTH_USERNAME,
    AUTH_PASSWORD,
    AUTH_USERNAME_SELECTOR = "#username",
    AUTH_PASSWORD_SELECTOR = "#password",
    AUTH_SUBMIT_SELECTOR = "[type=submit]",
    SESSION_COOKIE_NAME = "session",
} = process.env;

if (!AUTH_URL || !AUTH_USERNAME || !AUTH_PASSWORD) {
    console.error(
        "[ERROR] AUTH_URL, AUTH_USERNAME, and AUTH_PASSWORD must be set."
    );
    process.exit(1);
}

(async () => {
    console.log(`[INFO] Launching browser for auth bootstrap: ${AUTH_URL}`);
    const browser = await chromium.launch({ headless: true });
    const context = await browser.newContext({
        ignoreHTTPSErrors: true,
    });

    // Capture any auth tokens from network responses
    let bearerToken = null;
    context.on("response", async (response) => {
        try {
            const ct = response.headers()["content-type"] || "";
            if (ct.includes("application/json")) {
                const body = await response.json().catch(() => null);
                if (body && (body.token || body.access_token || body.accessToken)) {
                    bearerToken = body.token || body.access_token || body.accessToken;
                    console.log("[INFO] Captured Bearer token from response.");
                }
            }
        } catch (_) { }
    });

    const page = await context.newPage();

    try {
        await page.goto(AUTH_URL, { waitUntil: "networkidle", timeout: 30000 });
        console.log("[INFO] Login page loaded.");

        await page.fill(AUTH_USERNAME_SELECTOR, AUTH_USERNAME);
        await page.fill(AUTH_PASSWORD_SELECTOR, AUTH_PASSWORD);
        await page.click(AUTH_SUBMIT_SELECTOR);

        // Wait for navigation after login
        await page.waitForLoadState("networkidle", { timeout: 15000 });
        console.log(`[INFO] Post-login URL: ${page.url()}`);

        // Check for obvious login failure indicators
        const pageText = await page.textContent("body").catch(() => "");
        const failureKeywords = [
            "invalid credentials",
            "login failed",
            "incorrect password",
            "unauthorized",
        ];
        for (const kw of failureKeywords) {
            if (pageText.toLowerCase().includes(kw)) {
                console.error(`[ERROR] Login may have failed — found: "${kw}"`);
                process.exit(1);
            }
        }

        // Extract cookies
        const cookies = await context.cookies();
        fs.writeFileSync("/tmp/session-cookies.json", JSON.stringify(cookies, null, 2));
        console.log(`[INFO] Saved ${cookies.length} cookies to /tmp/session-cookies.json`);

        // Build cookie header string for ZAP
        const cookieHeader = cookies
            .map((c) => `${c.name}=${c.value}`)
            .join("; ");
        fs.writeFileSync("/tmp/zap-session.txt", cookieHeader);
        console.log("[INFO] Saved cookie header to /tmp/zap-session.txt");

        // Try to grab token from localStorage as fallback
        if (!bearerToken) {
            bearerToken = await page.evaluate(() => {
                return (
                    localStorage.getItem("token") ||
                    localStorage.getItem("access_token") ||
                    localStorage.getItem("authToken") ||
                    null
                );
            });
            if (bearerToken) {
                console.log("[INFO] Captured Bearer token from localStorage.");
            }
        }

        if (bearerToken) {
            fs.writeFileSync("/tmp/auth-token.txt", bearerToken);
            console.log("[INFO] Saved auth token to /tmp/auth-token.txt");
        } else {
            console.log("[INFO] No Bearer token found — cookie-based auth only.");
        }

        // Verify session cookie exists
        const sessionCookie = cookies.find((c) => c.name === SESSION_COOKIE_NAME);
        if (!sessionCookie) {
            console.warn(
                `[WARN] Expected session cookie "${SESSION_COOKIE_NAME}" not found. ` +
                "Check SESSION_COOKIE_NAME or inspect /tmp/session-cookies.json."
            );
        } else {
            console.log(`[INFO] Session cookie "${SESSION_COOKIE_NAME}" found.`);
        }
    } catch (err) {
        console.error(`[ERROR] Auth bootstrap failed: ${err.message}`);
        await browser.close();
        process.exit(1);
    }

    await browser.close();
    console.log("[INFO] Auth bootstrap complete.");
})();
