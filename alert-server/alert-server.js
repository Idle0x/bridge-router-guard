/**
 * alert-server.js  (v3)
 *
 * Drosera telemetry receiver for BridgeRouterGuardTrap.
 * Receives alert payloads from the Drosera network, decodes AlertData,
 * validates authenticity, and dispatches to Slack via webhook.
 *
 * CHANGES FROM v1/v2:
 *   - x-alert-secret header authentication (shared secret)
 *   - Input validation (required fields, type checks, payload shape)
 *   - Trap address verification (only accepts alerts from EXPECTED_TRAP)
 *   - Actual Slack dispatch via SLACK_WEBHOOK_URL (v1 was console.log only)
 *   - Defensive normalizeAlertData() handles object/array/ABI-decoded shapes
 *   - Slack Block Kit formatting for machine-readable alert cards
 *   - Body size limit (64kb) to prevent payload flooding
 *   - Error handling for failed Slack sends (logged, not swallowed)
 *   - v3 payload support: 4 uint256 fields + willRespondSoon proximity flag
 *
 * DROSERA CONSTRAINT:
 *   This server is OFF-CHAIN TELEMETRY ONLY. It does not execute responses.
 *   snapFreeze() is executed by the Drosera operator network on-chain.
 *   This server routes alerts to human operators for incident review.
 *
 * Environment variables (set in .env, NEVER committed):
 *   PORT              — server port (default: 3000)
 *   ALERT_SECRET      — shared secret for x-alert-secret header
 *   EXPECTED_TRAP     — Ethereum address of deployed BridgeRouterGuardTrap
 *   SLACK_WEBHOOK_URL — Slack incoming webhook URL
 *
 * Run:
 *   export ALERT_SECRET="your-long-random-secret"
 *   export EXPECTED_TRAP="0x1D880D83Ce107C6961495Ef767b8E4099A94F72E"
 *   export SLACK_WEBHOOK_URL="https://hooks.slack.com/services/..."
 *   node alert-server.js
 */
"use strict";
const express = require("express");
const app  = express();
const PORT = process.env.PORT || 3000;

// ─── Environment validation ───────────────────────────────────────────────────
const ALERT_SECRET      = process.env.ALERT_SECRET;
const EXPECTED_TRAP     = process.env.EXPECTED_TRAP?.toLowerCase();
const SLACK_WEBHOOK_URL = process.env.SLACK_WEBHOOK_URL;

if (!ALERT_SECRET) {
    console.warn("[WARN] ALERT_SECRET not set — endpoint is unauthenticated");
}
if (!EXPECTED_TRAP) {
    console.warn("[WARN] EXPECTED_TRAP not set — any trap address will be accepted");}
if (!SLACK_WEBHOOK_URL) {
    console.warn("[WARN] SLACK_WEBHOOK_URL not set — alerts will log only, not dispatch to Slack");
}

// ─── Middleware ───────────────────────────────────────────────────────────────
app.use(express.json({ limit: "64kb" }));

// ─── Payload normalization ────────────────────────────────────────────────────
// Drosera may encode AlertData as:
//   { unmatchedDrain, unbackedMinted, unauthorizedExecs, reserveDrain, willRespondSoon } (v3 object)
//   { vaultDrainVelocity, phantomMintVelocity, routerSpoofed } (v1 legacy object)
//   [value0, value1, value2, value3, bool] (array — ABI decode order)
// Defensive normalization handles all three. Missing fields default to "0"/false.
function normalizeAlertData(responseData) {
    if (!responseData) {
        return { unmatchedDrain: "0", unbackedMinted: "0", unauthorizedExecs: "0", reserveDrain: "0", willRespondSoon: false };
    }
    if (Array.isArray(responseData)) {
        return {
            unmatchedDrain:    String(responseData[0] ?? "0"),
            unbackedMinted:    String(responseData[1] ?? "0"),
            unauthorizedExecs: String(responseData[2] ?? "0"),
            reserveDrain:      String(responseData[3] ?? "0"),
            willRespondSoon:   Boolean(responseData[4])
        };
    }
    return {
        unmatchedDrain: String(
            responseData.unmatchedDrain ??
            responseData.vaultDrainVelocity ??
            responseData.vaultVelocity ?? "0"
        ),
        unbackedMinted: String(
            responseData.unbackedMinted ??
            responseData.phantomMintVelocity ??
            responseData.phantomVelocity ?? "0"
        ),
        unauthorizedExecs: String(
            responseData.unauthorizedExecs ??
            (responseData.routerSpoofed ? "1" : "0")
        ),
        reserveDrain: String(responseData.reserveDrain ?? "0"),
        willRespondSoon: Boolean(responseData.willRespondSoon ?? false)
    };
}

// ─── Slack dispatch ───────────────────────────────────────────────────────────
async function sendSlackAlert(title, severity, trapAddress, blockNumber, labels, alertData) {
    if (!SLACK_WEBHOOK_URL) {        console.log("[Slack disabled] SLACK_WEBHOOK_URL not set — skipping dispatch");
        return;
    }
    const routerSpoofed = alertData.unauthorizedExecs !== "0";
    const proximityFlag = alertData.willRespondSoon ? "⚠️ APPROACHING RESPONSE THRESHOLD" : "Monitoring";

    const payload = {
        text: `🚨 ${title}`,
        blocks: [
            {
                type: "header",
                text: { type: "plain_text", text: "🚨 Bridge Compromise Detected" },
            },
            {
                type: "section",
                fields: [
                    { type: "mrkdwn", text: `*Severity:*\n${String(severity).toUpperCase()}` },
                    { type: "mrkdwn", text: `*Block:*\n${blockNumber}` },
                    { type: "mrkdwn", text: `*Trap Contract:*\n\`${trapAddress}\`` },
                    { type: "mrkdwn", text: `*Component:*\n${labels?.component ?? "bridge-router-guard"}` },
                ],
            },
            {
                type: "section",
                text: { type: "mrkdwn", text: "*Detection Payload:*" },
            },
            {
                type: "section",
                fields: [
                    { type: "mrkdwn", text: `*Drain Mismatch Delta:*\n${alertData.unmatchedDrain} (wei)` },
                    { type: "mrkdwn", text: `*Mint Mismatch Delta:*\n${alertData.unbackedMinted} (wei)` },
                    { type: "mrkdwn", text: `*Unauthorized Router Execs:*\n${routerSpoofed ? `⚠️ YES (${alertData.unauthorizedExecs})` : "NO"}` },
                    { type: "mrkdwn", text: `*Reserve Reconciliation Drain:*\n${alertData.reserveDrain} (wei)` },
                ],
            },
            {
                type: "context",
                elements: [
                    { type: "mrkdwn", text: `_BridgeRouterGuard v3 · Drosera Network · Block ${blockNumber} · ${proximityFlag}_` },
                ],
            },
        ],
    };

    const res = await fetch(SLACK_WEBHOOK_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
    });
    if (!res.ok) {        const body = await res.text();
        throw new Error(`Slack webhook failed: ${res.status} ${body}`);
    }
}

// ─── Alert endpoint ───────────────────────────────────────────────────────────
app.post("/api/alerts", async (req, res) => {
    try {
        // ── Authentication ────────────────────────────────────────────────────
        if (ALERT_SECRET) {
            const provided = req.header("x-alert-secret");
            if (provided !== ALERT_SECRET) {
                console.warn(`[AUTH FAIL] Invalid x-alert-secret from ${req.ip}`);
                return res.status(401).json({ error: "unauthorized" });
            }
        }

        // ── Input validation ──────────────────────────────────────────────────
        const { trap_address, block_number, title, severity, labels, response_data } = req.body;
        if (!trap_address || !block_number || !title || !severity) {
            return res.status(400).json({ error: "invalid alert payload: missing required fields" });
        }
        if (typeof trap_address !== "string" || !trap_address.startsWith("0x")) {
            return res.status(400).json({ error: "invalid trap_address format" });
        }

        // ── Trap address verification ─────────────────────────────────────────
        if (EXPECTED_TRAP && trap_address.toLowerCase() !== EXPECTED_TRAP) {
            console.warn(`[TRAP MISMATCH] Got ${trap_address}, expected ${EXPECTED_TRAP}`);
            return res.status(403).json({ error: "unexpected trap address" });
        }

        // ── Normalize payload ─────────────────────────────────────────────────
        const alertData = normalizeAlertData(response_data);

        // ── Log to stdout ─────────────────────────────────────────────────────
        console.log("\n=============================================");
        console.log("🚨 DROSERA CRITICAL SECURITY ALERT 🚨");
        console.log("=============================================");
        console.log(`Title:              ${title}`);
        console.log(`Severity:           ${String(severity).toUpperCase()}`);
        console.log(`Trap:               ${trap_address}`);
        console.log(`Block:              ${block_number}`);
        console.log(`Labels:             ${JSON.stringify(labels)}`);
        console.log(`--- Detection Payload ---`);
        console.log(`Drain Mismatch:     ${alertData.unmatchedDrain} wei`);
        console.log(`Mint Mismatch:      ${alertData.unbackedMinted} wei`);
        console.log(`Unauthorized Execs: ${alertData.unauthorizedExecs}`);
        console.log(`Reserve Drain:      ${alertData.reserveDrain} wei`);
        console.log(`Proximity Flag:     ${alertData.willRespondSoon ? "APPROACHING RESPONSE" : "MONITORING"}`);        console.log("=============================================\n");

        // ── Dispatch to Slack ─────────────────────────────────────────────────
        await sendSlackAlert(title, severity, trap_address, block_number, labels, alertData);
        return res.status(200).json({ received: true });
    } catch (err) {
        console.error("[ERROR] Alert handling failed:", err.message);
        return res.status(500).json({ error: "alert handling failed" });
    }
});

// ─── Health check ─────────────────────────────────────────────────────────────
app.get("/health", (_, res) => {
    res.json({
        status: "ok",
        trap:   EXPECTED_TRAP ?? "not configured",
        slack:  SLACK_WEBHOOK_URL ? "configured" : "not configured",
    });
});

// ─── Start ────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
    console.log(`\n🛡️  BridgeRouterGuard Telemetry Server v3`);
    console.log(`   Listening on port ${PORT}`);
    console.log(`   Expected trap: ${EXPECTED_TRAP ?? "any (EXPECTED_TRAP not set)"}`);
    console.log(`   Slack: ${SLACK_WEBHOOK_URL ? "configured ✓" : "not configured ✗"}`);
    console.log(`   Auth:  ${ALERT_SECRET ? "enabled ✓" : "disabled ✗ (ALERT_SECRET not set)"}\n`);
});
