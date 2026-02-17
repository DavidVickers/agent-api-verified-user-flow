#!/usr/bin/env node
/**
 * Agent API Verified User Flow — Node.js E2E Test
 * ═══════════════════════════════════════════════════════════════
 *
 * Node.js equivalent of the Python test (python-test/agent_api_test.py).
 * Runs the complete MIAW verified-user flow with full SSE support.
 *
 * See SETUP_GUIDE.md §5.2 for documentation.
 *
 * THE FLOW (order matters! — see §6.0–§6.6):
 *   1. Call public Site endpoint → signed identity JWT     (§6.1)
 *   2. Exchange JWT with SCRT2 → MIAW access token         (§6.2)
 *   3. Create conversation                                 (§6.3)
 *   4. Subscribe to SSE stream — MUST be before sending!   (§6.4)
 *   5. Send message (with routingAttributes + language)     (§6.5)
 *   6. Listen for agent response via SSE + polling          (§7.3)
 *
 * CRITICAL: SSE must be established BEFORE the first message.
 * Agent responses are delivered exclusively via SSE (§6.4).
 *
 * Requires Node.js 18+ (uses built-in fetch and crypto.randomUUID).
 *
 * USAGE:
 *   npm install
 *   node agent-api-test.js
 *   node agent-api-test.js "What are my open cases?"
 *   node agent-api-test.js --sub user@example.com "Hello"
 * ═══════════════════════════════════════════════════════════════
 */

const crypto = require('crypto');
require('dotenv').config();

// ── Config from .env ─────────────────────────────────────────
const SITE_BASE_URL     = process.env.SITE_BASE_URL;
const SF_ORG_ID         = process.env.SF_ORG_ID;
const SCRT2_URL         = process.env.SCRT2_URL;
const ES_DEVELOPER_NAME = process.env.ES_DEVELOPER_NAME;
const JWT_SUBJECT       = process.env.JWT_SUBJECT || '';
const TEST_MESSAGE      = process.env.TEST_MESSAGE || 'Hello, what can you help me with?';

// ── SSE state ────────────────────────────────────────────────
let sseEvents    = [];
let sseRunning   = false;
let sseConnected = false;
let sseController = null;

// ═════════════════════════════════════════════════════════════
// DISPLAY HELPERS (match Python output format)
// ═════════════════════════════════════════════════════════════

function banner(title) {
    const line = '='.repeat(64);
    console.log(`\n${line}`);
    console.log(`  ${title}`);
    console.log(line);
}

function step(num, title) {
    const line = '-'.repeat(64);
    console.log(`\n${line}`);
    console.log(`  STEP ${num}: ${title}`);
    console.log(line);
}

function detail(label, value) {
    const str = String(value);
    console.log(`  [${label}] ${str.length > 200 ? str.substring(0, 200) + '...' : str}`);
}

function success(msg) { console.log(`  >> SUCCESS: ${msg}`); }
function error(msg)   { console.log(`  ** ERROR: ${msg}`); }
function note(msg)    { console.log(`  (!) ${msg}`); }

function httpReq(method, url, body) {
    console.log(`  --> ${method} ${url}`);
    if (body) {
        const pretty = JSON.stringify(body, null, 2);
        const lines = pretty.split('\n');
        const show = lines.length > 10 ? lines.slice(0, 10) : lines;
        show.forEach(l => console.log(`      ${l}`));
        if (lines.length > 10) console.log(`      ... (${lines.length} lines total)`);
    }
}

function httpRes(status, body) {
    console.log(`  <-- ${status}`);
    if (body) {
        try {
            const parsed = typeof body === 'string' ? JSON.parse(body) : body;
            const pretty = JSON.stringify(parsed, null, 2);
            const lines = pretty.split('\n');
            const show = lines.length > 15 ? lines.slice(0, 15) : lines;
            show.forEach(l => console.log(`      ${l}`));
            if (lines.length > 15) console.log(`      ... (${lines.length} lines total)`);
        } catch {
            console.log(`      ${String(body).substring(0, 500)}`);
        }
    }
}

// ═════════════════════════════════════════════════════════════
// STEP 1: Get Signed Identity JWT from Public Site Endpoint (§6.1)
// ═════════════════════════════════════════════════════════════

async function getSignedJwt(customSub) {
    step(1, 'Get Signed Identity JWT (Public Site Endpoint)');

    const url = new URL(`${SITE_BASE_URL}/services/apexrest/agent-verify/jwt`);
    if (customSub) url.searchParams.set('sub', customSub);

    httpReq('GET', url.toString());
    const resp = await fetch(url.toString(), { signal: AbortSignal.timeout(30000) });
    const data = await resp.json();
    httpRes(resp.status, data);

    if (resp.status !== 200 || data.error) {
        error(data.error || `HTTP ${resp.status}`);
        process.exit(1);
    }

    detail('Subject', data.subject);
    detail('Issuer', data.issuer);
    detail('KID', data.kid);
    detail('Audience', data.audience);
    detail('Expires In', `${data.expiresInSeconds}s`);
    detail('JWT', `${data.jwt.substring(0, 60)}... (${data.jwt.length} chars)`);
    success('Signed identity JWT obtained from Salesforce Site');
    note('No OAuth needed — the Site endpoint is public.');

    return { jwt: data.jwt, info: data };
}

// ═════════════════════════════════════════════════════════════
// STEP 2: Exchange JWT for MIAW Access Token (§6.2)
//
// SCRT2 internally: fetches JWKS → finds kid → verifies sig →
// checks claims → returns AUTH or ANON token (§2.1).
// Returns 200 OK EITHER WAY — check context.endUser.subject (§7.1).
// ═════════════════════════════════════════════════════════════

async function getMiawToken(identityJwt) {
    step(2, 'Exchange JWT for MIAW Access Token (SCRT2)');

    const url = `${SCRT2_URL}/iamessage/api/v2/authorization/authenticated/access-token`;
    const body = {
        orgId:                 SF_ORG_ID,
        esDeveloperName:       ES_DEVELOPER_NAME,
        capabilitiesVersion:   '1',
        platform:              'Web',
        authorizationType:     'JWT',
        customerIdentityToken: identityJwt,
    };

    httpReq('POST', url, body);
    const resp = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(30000),
    });

    const text = await resp.text();
    httpRes(resp.status, text);

    if (resp.status < 200 || resp.status >= 300) {
        error(`MIAW token exchange failed: ${text}`);
        process.exit(1);
    }

    const result = JSON.parse(text);
    const miawToken   = result.accessToken;
    const lastEventId = result.lastEventId;

    // Check AUTH vs ANON — THE critical verification evidence (§7.1)
    const subject = result.context?.endUser?.subject || '';
    detail('MIAW Token', `${miawToken.substring(0, 50)}... (${miawToken.length} chars)`);
    detail('End User Subject', subject);
    detail('Last Event ID', lastEventId);

    if (subject.includes('/AUTH/')) {
        success('USER IS VERIFIED (AUTH) — identity confirmed!');
        const parts = subject.split('/');
        if (parts.length >= 5) {
            detail('JWKS Keyset', parts[3]);
            detail('Verified Identity', parts[4].replace('uid:', ''));
        }
    } else if (subject.includes('/ANON/')) {
        error('USER IS ANONYMOUS (ANON) — verification FAILED!');
        error('SCRT2 returned 200 OK but silently fell back to anonymous (§2.4).');
    } else {
        note(`Unknown subject format: ${subject}`);
    }

    return { token: miawToken, result, lastEventId, subject };
}

// ═════════════════════════════════════════════════════════════
// STEP 2b: Resolve Verified Identity (Apex REST Service)
//
// Calls the public Apex REST endpoint to resolve the verified
// uid from the MIAW platform key to Salesforce records
// (Contact/Account or Lead). This is ONE approach to tying
// the external uid to org records — many variations exist.
// ═════════════════════════════════════════════════════════════

async function resolveIdentity(subject) {
    step('3b', 'Resolve Verified Identity (Apex REST)');

    if (!subject || !subject.includes('/AUTH/')) {
        note('Skipping identity resolution — subject is not AUTH.');
        return null;
    }

    const url = new URL(
        `${SITE_BASE_URL}/services/apexrest/agent-verify/resolve-identity`
    );
    url.searchParams.set('subject', subject);

    httpReq('GET', url.toString());

    try {
        const resp = await fetch(url.toString(), {
            signal: AbortSignal.timeout(30000),
        });
        const data = await resp.json();
        httpRes(resp.status, data);

        if (data.error) {
            error(`Identity resolution error: ${data.error}`);
            if (data.errorType) detail('Error Type', data.errorType);
            return data;
        }

        // Log all returned fields
        for (const [key, val] of Object.entries(data)) {
            detail(key, String(val));
        }

        if (data.resolved) {
            const matchType = data.matchType || 'Unknown';
            success(`Identity resolved (${matchType}): ${data.message}`);
        } else {
            note(`Identity not yet resolved: ${data.message || 'Unknown reason'}`);
        }

        return data;
    } catch (e) {
        error(`Identity resolution failed: ${e.message}`);
        return null;
    }
}

// ═════════════════════════════════════════════════════════════
// STEP 3: Create Conversation (§6.3)
// ═════════════════════════════════════════════════════════════

async function createConversation(miawToken) {
    step(3, 'Create Conversation');

    // UUID must be v4 — SCRT2 enforces strict compliance (§10)
    const conversationId = crypto.randomUUID();
    detail('Conversation ID', conversationId);

    const url  = `${SCRT2_URL}/iamessage/api/v2/conversation`;
    const body = {
        conversationId,
        esDeveloperName: ES_DEVELOPER_NAME,
    };

    httpReq('POST', url, body);
    const resp = await fetch(url, {
        method: 'POST',
        headers: {
            'Content-Type':  'application/json',
            'Authorization': `Bearer ${miawToken}`,
        },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(30000),
    });

    const text = await resp.text();
    httpRes(resp.status, text);

    if (resp.status < 200 || resp.status >= 300) {
        error(`Create conversation failed: ${text}`);
        process.exit(1);
    }

    success(`Conversation created: ${conversationId}`);
    note('Conversation is now open and routed via Omni-Channel.');
    return conversationId;
}

// ═════════════════════════════════════════════════════════════
// STEP 4: Subscribe to SSE Stream (§6.4)
//
// CRITICAL: Must be established BEFORE sending the first message.
// Required headers: Authorization, X-Org-Id, Last-Event-Id.
// ═════════════════════════════════════════════════════════════

async function startSSEListener(miawToken, lastEventId) {
    step(4, 'Subscribe to SSE Stream (BEFORE sending message)');

    const sseUrl = `${SCRT2_URL}/eventrouter/v1/sse`;
    detail('SSE URL', sseUrl);
    detail('X-Org-Id', SF_ORG_ID);
    detail('Last-Event-Id', lastEventId);

    sseRunning   = true;
    sseConnected = false;
    sseController = new AbortController();

    const headers = {
        'Authorization': `Bearer ${miawToken}`,
        'Accept':        'text/event-stream',
        'Cache-Control': 'no-cache',
        'X-Org-Id':      SF_ORG_ID,
    };
    if (lastEventId) {
        headers['Last-Event-Id'] = String(lastEventId);
    }

    console.log(`  [SSE] Connecting to ${sseUrl}`);

    // Run SSE in background (non-blocking)
    const ssePromise = (async () => {
        try {
            const resp = await fetch(sseUrl, {
                headers,
                signal: sseController.signal,
            });

            if (resp.status !== 200) {
                const body = await resp.text();
                console.log(`  [SSE] ** FAILED: HTTP ${resp.status}`);
                console.log(`  [SSE] ${body.substring(0, 500)}`);
                sseRunning = false;
                return;
            }

            sseConnected = true;
            console.log(`  >> SSE CONNECTED! Status=${resp.status}`);

            // Read the stream
            const reader  = resp.body.getReader();
            const decoder = new TextDecoder();
            let buffer    = '';

            while (true) {
                const { done, value } = await reader.read();
                if (done) break;

                buffer += decoder.decode(value, { stream: true });

                // SSE events separated by double newline
                const parts = buffer.split('\n\n');
                buffer = parts.pop();

                for (const part of parts) {
                    if (!part.trim()) continue;

                    let eventType = 'message';
                    let dataLines = [];

                    for (const line of part.split('\n')) {
                        if (line.startsWith('event:')) {
                            eventType = line.substring(6).trim();
                        } else if (line.startsWith('data:')) {
                            dataLines.push(line.substring(5).trim());
                        }
                    }

                    const dataStr = dataLines.join('\n');
                    if (!dataStr) continue;

                    const timestamp = new Date().toISOString();
                    console.log(`\n  [SSE EVENT] type=${eventType} at ${timestamp}`);

                    try {
                        const parsed = JSON.parse(dataStr);
                        const pretty = JSON.stringify(parsed, null, 2);
                        console.log(`  [SSE DATA]  ${pretty.substring(0, 800)}`);
                    } catch {
                        console.log(`  [SSE DATA]  ${dataStr.substring(0, 800)}`);
                    }

                    sseEvents.push({ type: eventType, data: dataStr, timestamp });
                }
            }

            console.log('  [SSE] Stream ended');
        } catch (e) {
            if (e.name !== 'AbortError') {
                console.log(`  [SSE] Error: ${e.message}`);
            }
        } finally {
            sseRunning = false;
        }
    })();

    // Wait for SSE to connect (up to 10s) before proceeding
    note('Waiting for SSE connection before sending message...');
    for (let i = 0; i < 20; i++) {
        await sleep(500);
        if (sseConnected) {
            success('SSE connected — safe to send message now.');
            return;
        }
        if (!sseRunning) {
            error('SSE failed to connect. Will rely on polling.');
            return;
        }
    }

    note('SSE connection still pending after 10s — proceeding anyway.');
}

// ═════════════════════════════════════════════════════════════
// STEP 5: Send Message (§6.5)
//
// First message requires routingAttributes + language (§6.5).
// ═════════════════════════════════════════════════════════════

async function sendMessage(miawToken, conversationId, messageText) {
    step(5, 'Send Message');

    const messageId = crypto.randomUUID();
    const url = `${SCRT2_URL}/iamessage/api/v2/conversation/${conversationId}/message`;

    const body = {
        message: {
            id:          messageId,
            messageType: 'StaticContentMessage',
            staticContent: { formatType: 'Text', text: messageText },
        },
        esDeveloperName:    ES_DEVELOPER_NAME,
        isNewMessagingSession: true,
        // CRITICAL: Required for the first message (§6.5)
        routingAttributes: {},
        language: 'en',
    };

    httpReq('POST', url, body);
    detail('Message', messageText);
    detail('Message ID', messageId);

    const resp = await fetch(url, {
        method: 'POST',
        headers: {
            'Content-Type':  'application/json',
            'Authorization': `Bearer ${miawToken}`,
        },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(120000),
    });

    const text = await resp.text();
    httpRes(resp.status, text);

    if (resp.status < 200 || resp.status >= 300) {
        error(`Send message failed: ${text}`);
        process.exit(1);
    }

    success(`Message sent to conversation ${conversationId}`);
    note('Agent processes asynchronously. Listening for response via SSE...');
    return text ? JSON.parse(text) : {};
}

// ═════════════════════════════════════════════════════════════
// STEP 6: Wait for Agent Response — SSE + Polling (§7.3)
// ═════════════════════════════════════════════════════════════

// Routing events that are NOT agent text messages (§6.4)
const ROUTING_ENTRY_TYPES = new Set([
    'RoutingWorkResult', 'RoutingResult', 'SessionStatusChanged',
    'ParticipantChanged', 'TypingStartedIndicator', 'TypingStoppedIndicator',
]);

async function waitForResponse(miawToken, conversationId, maxWait = 60) {
    step(6, `Wait for Agent Response (up to ${maxWait}s)`);

    const entriesUrl = `${SCRT2_URL}/iamessage/api/v2/conversation/${conversationId}/entries`;
    let agentTextFound = false;
    const start = Date.now();
    let pollCount = 0;
    const seenEntryTypes = new Set();

    note(`Waiting up to ${maxWait}s for agent response...`);
    note(`SSE connected: ${sseConnected} | SSE running: ${sseRunning}`);

    while ((Date.now() - start) / 1000 < maxWait) {
        pollCount++;
        const elapsed = ((Date.now() - start) / 1000).toFixed(1);

        // ── Check SSE events for agent text messages ──
        for (const evt of sseEvents) {
            try {
                const data = JSON.parse(evt.data);
                if (typeof data !== 'object' || data === null) continue;

                let entries = data.conversationEntries || [];
                if (!entries.length && data.conversationEntry) {
                    entries = [data.conversationEntry];
                }

                for (const entry of entries) {
                    const entryType = entry.entryType || '';
                    if (!seenEntryTypes.has(entryType)) {
                        seenEntryTypes.add(entryType);
                        detail('New Entry Type (SSE)', entryType);
                    }

                    if (isAgentTextMessage(entry)) {
                        displayAgentEntry(entry);
                        agentTextFound = true;
                    }
                }
            } catch { /* skip */ }
        }

        if (agentTextFound) break;

        // ── Poll the entries endpoint ──
        detail('Poll', `#${pollCount} at ${elapsed}s`);
        try {
            const resp = await fetch(entriesUrl, {
                headers: {
                    'Authorization': `Bearer ${miawToken}`,
                    'Accept': 'application/json',
                },
                signal: AbortSignal.timeout(10000),
            });

            if (resp.status === 200) {
                const body = await resp.json();
                const entries = body.conversationEntries || body.entries || [];

                if (pollCount === 1) {
                    detail('Raw Entries Response',
                        JSON.stringify(body, null, 2).substring(0, 1500));
                }
                detail('Entries Count', entries.length);

                for (const entry of entries) {
                    const entryType = entry.entryType || '';
                    if (!seenEntryTypes.has(entryType)) {
                        seenEntryTypes.add(entryType);
                        detail('New Entry Type (poll)', entryType);
                    }
                    if (isAgentTextMessage(entry)) {
                        displayAgentEntry(entry);
                        agentTextFound = true;
                    }
                }

                if (agentTextFound) break;
            } else {
                const errText = await resp.text();
                detail('Entries HTTP', `${resp.status}: ${errText.substring(0, 200)}`);
            }
        } catch (e) {
            detail('Poll Error', e.message);
        }

        await sleep(3000);
    }

    if (seenEntryTypes.size > 0) {
        detail('All Entry Types Seen', [...seenEntryTypes].sort().join(', '));
    }

    if (!agentTextFound) {
        note(`No agent TEXT response after ${maxWait}s (${pollCount} polls, ${sseEvents.length} SSE events)`);
        note('');
        note('TROUBLESHOOTING — Why the agent may not respond:');
        note('  1. SSE connection: Did SSE connect? (Check Step 4 output)');
        note('  2. Omni-Channel routing: Is there a flow routing to your agent?');
        note('  3. Agent/bot status: Is it online in Omni Supervisor?');
        note('  4. Messaging channel: Is it linked to the ES deployment?');
        note('  5. Agent topics: Does any topic match the message?');
    }

    return agentTextFound;
}

/**
 * Extract text from an entryPayload JSON string (§7.3).
 */
function extractTextFromPayload(payload) {
    if (!payload) return null;
    try {
        const p = typeof payload === 'string' ? JSON.parse(payload) : payload;
        return p?.abstractMessage?.staticContent?.text
            || p?.message?.staticContent?.text
            || p?.text
            || null;
    } catch {
        return null;
    }
}

/**
 * Is this entry a TEXT message from the agent? (§6.4)
 * Filters out routing events and end-user messages.
 */
function isAgentTextMessage(entry) {
    const entryType = entry.entryType || '';
    if (ROUTING_ENTRY_TYPES.has(entryType)) return false;
    if (entryType && entryType !== 'Message') return false;

    const sender = entry.sender || {};
    if (typeof sender === 'object' && sender.role?.toLowerCase() === 'enduser') {
        return false;
    }

    const actorType = entry.actorType || '';
    if (actorType && actorType.toLowerCase().includes('user') &&
        actorType.toLowerCase().includes('end')) {
        return false;
    }

    const payload = entry.entryPayload || '';
    if (payload) {
        const text = extractTextFromPayload(payload);
        if (text) return true;
    }

    const message = entry.message;
    if (message && typeof message === 'string') return true;

    return false;
}

/**
 * Display an agent conversation entry.
 */
function displayAgentEntry(entry) {
    const agentName = entry.actorName
        || entry.senderDisplayName
        || (entry.sender?.subject)
        || (entry.sender?.role)
        || 'Agent';

    const payload = entry.entryPayload || '';
    if (payload) {
        const text = extractTextFromPayload(payload);
        if (text) {
            success(`${agentName} says: ${text}`);
            return;
        }
        detail(`${agentName} (${entry.entryType})`, String(payload).substring(0, 500));
        return;
    }

    const message = entry.message;
    if (message) {
        success(`${agentName} says: ${message}`);
        return;
    }

    detail(`${agentName} (${entry.entryType})`, `Entry keys: ${Object.keys(entry).join(', ')}`);
}

// ═════════════════════════════════════════════════════════════
// SUMMARY
// ═════════════════════════════════════════════════════════════

function showSummary(miawResult, conversationId, agentResponded) {
    banner('SUMMARY');

    const subject = miawResult.context?.endUser?.subject || '';
    const isAuth = subject.includes('/AUTH/');

    detail('Auth Status', isAuth ? 'VERIFIED (AUTH)' : 'ANONYMOUS (ANON)');
    detail('Conversation ID', conversationId);
    detail('SSE Connected', sseConnected);
    detail('SSE Events Received', sseEvents.length);
    detail('Agent Text Response', agentResponded ? 'Yes' : 'No');

    if (!agentResponded) {
        console.log();
        note('The agent did not send a text response within the polling window.');
    }
}

// ═════════════════════════════════════════════════════════════
// HELPERS
// ═════════════════════════════════════════════════════════════

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

// ═════════════════════════════════════════════════════════════
// MAIN
// ═════════════════════════════════════════════════════════════

async function main() {
    // Parse args
    let message = TEST_MESSAGE;
    let customSub = JWT_SUBJECT;

    const args = process.argv.slice(2);
    for (let i = 0; i < args.length; i++) {
        if (args[i] === '--sub' && i + 1 < args.length) {
            customSub = args[++i];
        } else {
            message = args[i];
        }
    }

    banner('MIAW VERIFIED USER FLOW — NODE.JS E2E TEST');
    detail('Timestamp', new Date().toISOString());
    detail('Site URL', SITE_BASE_URL);
    detail('SCRT2 URL', SCRT2_URL);
    detail('Org ID', SF_ORG_ID);
    detail('ES Deployment', ES_DEVELOPER_NAME);
    detail('Message', message);
    if (customSub) detail('Subject Override', customSub);

    try {
        // Step 1: Get signed JWT (§6.1)
        const { jwt: identityJwt } = await getSignedJwt(customSub);

        // Step 2: Exchange for MIAW token (§6.2)
        const { token: miawToken, result: miawResult, lastEventId, subject: endUserSubject } =
            await getMiawToken(identityJwt);

        // Step 3: Create conversation (§6.3)
        const conversationId = await createConversation(miawToken);

        // Step 3b: Resolve verified identity to SF records
        // (after conversation, so MessagingEndUser exists)
        const identityResult = await resolveIdentity(endUserSubject);

        // Step 4: Start SSE BEFORE sending message (§6.4)
        await startSSEListener(miawToken, lastEventId);

        // Step 5: Send message with routingAttributes + language (§6.5)
        await sendMessage(miawToken, conversationId, message);

        // Step 6: Wait for agent response — SSE + polling (§7.3)
        const agentResponded = await waitForResponse(
            miawToken, conversationId, 60
        );

        // Summary
        showSummary(miawResult, conversationId, agentResponded);

    } catch (e) {
        error(`Unhandled error: ${e.message}`);
        console.error(e.stack);
    } finally {
        if (sseController) {
            note('Stopping SSE listener...');
            sseController.abort();
        }
    }

    banner('DONE');
    process.exit(0);
}

main();
