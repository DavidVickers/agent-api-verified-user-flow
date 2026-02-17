/**
 * MIAW Verified User Demo — Local Server
 *
 * Serves the chat UI and proxies the JWT endpoint to avoid CORS.
 * All SCRT2 calls (token exchange, conversation, message, SSE)
 * go directly from the browser — SCRT2 has CORS support (§6.0).
 *
 * The only server-side call is /api/jwt which proxies to the
 * Salesforce Site REST endpoint (§5.2).
 *
 * Usage:
 *   npm install
 *   npm start
 *   Open http://localhost:3000
 */

const express = require('express');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

const SITE_BASE_URL     = process.env.SITE_BASE_URL;
const SCRT2_URL         = process.env.SCRT2_URL;
const SF_ORG_ID         = process.env.SF_ORG_ID;
const ES_DEVELOPER_NAME = process.env.ES_DEVELOPER_NAME;

// ── Serve static files ───────────────────────────────────────
app.use(express.static(path.join(__dirname, 'public')));

// ── /api/config — values the browser needs for SCRT2 calls ──
app.get('/api/config', (req, res) => {
    res.json({
        scrt2Url:        SCRT2_URL,
        orgId:           SF_ORG_ID,
        esDeveloperName: ES_DEVELOPER_NAME,
    });
});

// ── /api/jwt — proxy to SF Site JWT endpoint (avoids CORS) ──
// The Apex REST endpoint signs the JWT server-side (§6.1).
// We proxy it because Salesforce Sites don't add CORS headers
// to custom REST endpoints by default.
app.get('/api/jwt', async (req, res) => {
    try {
        const url = new URL(
            `${SITE_BASE_URL}/services/apexrest/agent-verify/jwt`
        );
        if (req.query.sub) {
            url.searchParams.set('sub', req.query.sub);
        }

        const response = await fetch(url.toString(), { timeout: 30000 });
        const data = await response.json();
        res.json(data);
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// ── /api/resolve-identity — proxy to SF Site resolve-identity endpoint ──
// Calls the Apex REST service to resolve verified identity to
// Salesforce records (Contact/Account/Lead). Logs full response.
app.get('/api/resolve-identity', async (req, res) => {
    try {
        const subject = req.query.subject;
        if (!subject) {
            return res.status(400).json({ error: 'Missing required parameter: subject' });
        }

        const url = new URL(
            `${SITE_BASE_URL}/services/apexrest/agent-verify/resolve-identity`
        );
        url.searchParams.set('subject', subject);

        console.log(`[resolve-identity] --> GET ${url.toString()}`);
        const response = await fetch(url.toString(), { timeout: 30000 });
        const text = await response.text();
        console.log(`[resolve-identity] <-- ${response.status} (${text.length} chars)`);

        // SF Site may return HTML error page if class isn't in Guest User access
        let data;
        try {
            data = JSON.parse(text);
        } catch {
            console.error(`[resolve-identity] Non-JSON response (HTML error page?):`);
            console.error(`[resolve-identity] ${text.substring(0, 200)}`);
            return res.status(502).json({
                error: 'Salesforce Site returned non-JSON response. '
                     + 'Check that AgentAPI_ResolveIdentity is added to '
                     + 'the Site Guest User Apex Class Access.',
                httpStatus: response.status,
                preview: text.substring(0, 200),
            });
        }

        console.log(`[resolve-identity] Response:`, JSON.stringify(data, null, 2));
        res.status(response.status).json(data);
    } catch (e) {
        console.error(`[resolve-identity] ERROR: ${e.message}`);
        res.status(500).json({ error: e.message });
    }
});

// ── Start ────────────────────────────────────────────────────
app.listen(PORT, () => {
    console.log(`
╔══════════════════════════════════════════╗
║   MIAW Verified User Demo               ║
╠══════════════════════════════════════════╣
║   Open: http://localhost:${PORT}            ║
║   SCRT2: ${SCRT2_URL ? SCRT2_URL.substring(0, 30) + '...' : 'not set'}  ║
║   Org:   ${SF_ORG_ID || 'not set'}                  ║
╚══════════════════════════════════════════╝
`);
});
