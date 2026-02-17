/**
 * MIAW Verified User Demo — Client-Side Application
 * ═══════════════════════════════════════════════════════════════
 *
 * Runs the full MIAW verified-user flow from the browser:
 *   1. Get signed JWT from local server proxy         (§6.1)
 *   2. Exchange JWT for MIAW token via SCRT2           (§6.2)
 *   3. Create conversation                            (§6.3)
 *   4. Subscribe to SSE (fetch streaming)              (§6.4)
 *   5. Send messages as verified user                  (§6.5)
 *
 * SSE uses fetch() with ReadableStream because EventSource
 * doesn't support custom headers (Authorization, X-Org-Id).
 *
 * See SETUP_GUIDE.md §5.2 for the full flow documentation.
 * ═══════════════════════════════════════════════════════════════
 */

// ── State ────────────────────────────────────────────────────
let config = {};
let miawToken = null;
let conversationId = null;
let lastEventId = null;
let isVerified = false;
let isFirstMessage = true;
let sseAbortController = null;

// ── DOM Elements ─────────────────────────────────────────────
const connectBtn   = document.getElementById('connect-btn');
const messageInput = document.getElementById('message-input');
const sendBtn      = document.getElementById('send-btn');
const chatArea     = document.getElementById('chat-area');
const logArea      = document.getElementById('log-area');
const statusBadge  = document.getElementById('status-badge');

// ═════════════════════════════════════════════════════════════
// INITIALIZE
// ═════════════════════════════════════════════════════════════

async function init() {
    connectBtn.addEventListener('click', connect);
    sendBtn.addEventListener('click', () => sendMessage());
    messageInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            sendMessage();
        }
    });

    // Load config from server
    try {
        const resp = await fetch('/api/config');
        config = await resp.json();
        addLog('info', `Config loaded — Org: ${config.orgId}`);
    } catch (e) {
        addLog('error', `Config failed: ${e.message}`);
    }
}

// ═════════════════════════════════════════════════════════════
// CONNECT — Steps 1–4 (§6.1–§6.4)
// ═════════════════════════════════════════════════════════════

async function connect() {
    connectBtn.disabled = true;
    connectBtn.textContent = 'Connecting...';
    setStatus('connecting', 'Connecting');

    try {
        // ── Step 1: Get signed JWT (§6.1) ────────────────
        updateFlowStep(1, 'active');
        addLog('step', 'Step 1: Getting signed JWT...');
        console.log('[step-1] Fetching JWT from /api/jwt...');
        const jwtResp = await fetch('/api/jwt');
        const jwtData = await jwtResp.json();
        console.log('[step-1] JWT response:', JSON.stringify(jwtData, null, 2));

        if (jwtData.error) {
            console.error('[step-1] ERROR:', jwtData.error);
            throw new Error(`JWT endpoint: ${jwtData.error}`);
        }

        addLog('success', `JWT obtained (${jwtData.jwt.length} chars)`);
        addLog('info', `Subject: ${jwtData.subject}`);
        addLog('info', `Issuer: ${jwtData.issuer}`);
        addLog('info', `KID: ${jwtData.kid}`);
        console.log('[step-1] Subject:', jwtData.subject);
        console.log('[step-1] JWT:', jwtData.jwt.substring(0, 80) + '...');
        updateFlowStep(1, 'completed');

        // ── Step 2: Exchange JWT for MIAW token (§6.2) ───
        updateFlowStep(2, 'active');
        // SCRT2 fetches JWKS, validates signature, returns
        // AUTH or ANON token. 200 OK either way (§2.4).
        addLog('step', 'Step 2: Exchanging JWT for MIAW token...');
        console.log('[step-2] Exchanging JWT with SCRT2...');
        const tokenResp = await fetch(
            `${config.scrt2Url}/iamessage/api/v2/authorization/authenticated/access-token`,
            {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    orgId:                 config.orgId,
                    esDeveloperName:       config.esDeveloperName,
                    capabilitiesVersion:   '1',
                    platform:              'Web',
                    authorizationType:     'JWT',
                    customerIdentityToken: jwtData.jwt,
                }),
            }
        );

        if (!tokenResp.ok) {
            const errText = await tokenResp.text();
            throw new Error(`Token exchange HTTP ${tokenResp.status}: ${errText}`);
        }

        const tokenData = await tokenResp.json();
        console.log('[step-2] Token response:', JSON.stringify(tokenData, null, 2));
        miawToken   = tokenData.accessToken;
        lastEventId = tokenData.lastEventId;

        // Check AUTH vs ANON — the ONLY verification proof (§7.1)
        const subject = tokenData.context?.endUser?.subject || '';

        if (subject.includes('/AUTH/')) {
            isVerified = true;
            const parts = subject.split('/');
            const identity = parts.length >= 5
                ? parts[4].replace('uid:', '')
                : '?';
            addLog('success', `VERIFIED (AUTH) — ${identity}`);
            console.log('[step-2] VERIFIED (AUTH):', identity);
            setStatus('verified', `AUTH: ${identity}`);
        } else if (subject.includes('/ANON/')) {
            addLog('error', 'ANONYMOUS — verification failed (§2.4)');
            console.error('[step-2] ANONYMOUS (ANON) — verification FAILED');
            setStatus('anonymous', 'ANON — Not Verified');
        } else {
            addLog('info', `Subject: ${subject}`);
            setStatus('connecting', 'Unknown auth');
        }

        addLog('info', `Last Event ID: ${lastEventId}`);
        updateFlowStep(2, 'completed');

        // ── Step 3: Create conversation (§6.3) ───────────
        updateFlowStep(3, 'active');
        addLog('step', 'Step 3: Creating conversation...');
        conversationId = crypto.randomUUID();

        const convResp = await fetch(
            `${config.scrt2Url}/iamessage/api/v2/conversation`,
            {
                method: 'POST',
                headers: {
                    'Content-Type':  'application/json',
                    'Authorization': `Bearer ${miawToken}`,
                },
                body: JSON.stringify({
                    conversationId,
                    esDeveloperName: config.esDeveloperName,
                }),
            }
        );

        if (!convResp.ok) {
            const errText = await convResp.text();
            throw new Error(`Conversation HTTP ${convResp.status}: ${errText}`);
        }

        addLog('success', `Conversation: ${conversationId.substring(0, 8)}...`);
        console.log('[step-3] Conversation created:', conversationId);
        updateFlowStep(3, 'completed');

        // ── Resolve Identity (after conversation, so MEU exists) ──
        // Call the Apex REST service to resolve the verified
        // identity to Salesforce records (Contact/Account/Lead).
        // This is ONE approach — see §8.2 for alternatives.
        if (subject && subject.includes('/AUTH/')) {
            addLog('step', 'Resolving identity to Salesforce records...');
            console.log('[resolve-identity] Subject:', subject);
            try {
                const resolveResp = await fetch(
                    `/api/resolve-identity?subject=${encodeURIComponent(subject)}`
                );
                const resolveData = await resolveResp.json();
                console.log('[resolve-identity] Response:', JSON.stringify(resolveData, null, 2));

                if (resolveData.error) {
                    addLog('error', `Identity resolution error: ${resolveData.error}`);
                    console.error('[resolve-identity] ERROR:', resolveData.error);
                } else if (resolveData.resolved) {
                    const matchType = resolveData.matchType || 'Unknown';
                    addLog('success', `Identity resolved (${matchType}): ${resolveData.message}`);

                    if (resolveData.updatedContactId) {
                        addLog('info', `Contact: ${resolveData.updatedContactId}`);
                    }
                    if (resolveData.updatedAccountId) {
                        addLog('info', `Account: ${resolveData.updatedAccountId}`);
                    }
                    if (resolveData.leadId) {
                        addLog('info', `Lead: ${resolveData.leadId}`);
                    }
                    if (resolveData.alreadyLinked) {
                        addLog('info', 'MEU was already linked');
                    }
                } else {
                    addLog('info', `Identity not resolved: ${resolveData.message || 'Unknown reason'}`);
                    console.log('[resolve-identity] Not resolved:', resolveData.message);
                }

                // Log all returned fields to console for debugging
                for (const [key, val] of Object.entries(resolveData)) {
                    console.log(`[resolve-identity]   ${key}: ${val}`);
                }
            } catch (resolveErr) {
                addLog('error', `Identity resolution failed: ${resolveErr.message}`);
                console.error('[resolve-identity] EXCEPTION:', resolveErr);
            }
        } else {
            addLog('info', 'Skipping identity resolution (not AUTH)');
            console.log('[resolve-identity] Skipped — subject is not AUTH:', subject);
        }

        // ── Step 4: Subscribe to SSE (§6.4) ──────────────
        // Must be established BEFORE sending the first message.
        addLog('step', 'Step 4: Connecting to SSE...');
        startSSE();

        // Enable chat input
        messageInput.disabled = false;
        sendBtn.disabled = false;
        messageInput.placeholder = 'Type a message and press Enter...';
        messageInput.focus();
        connectBtn.textContent = 'Connected';

        // Clear the pre-connect flow diagram and show chat
        const preConnect = document.getElementById('pre-connect');
        if (preConnect) preConnect.remove();
        addMessage('system', 'Connected as verified user. Type a message below.');

    } catch (e) {
        addLog('error', e.message);
        console.error('[connect] FAILED:', e.message, e.stack);
        connectBtn.disabled = false;
        connectBtn.textContent = 'Connect';
        setStatus('disconnected', 'Disconnected');
    }
}

// ═════════════════════════════════════════════════════════════
// SEND MESSAGE (§6.5)
// ═════════════════════════════════════════════════════════════

async function sendMessage() {
    const text = messageInput.value.trim();
    if (!text || !miawToken || !conversationId) return;

    messageInput.value = '';
    addMessage('user', text);

    const messageId = crypto.randomUUID();

    // Build request body (§6.5)
    const body = {
        message: {
            id:          messageId,
            messageType: 'StaticContentMessage',
            staticContent: { formatType: 'Text', text },
        },
        esDeveloperName:    config.esDeveloperName,
        isNewMessagingSession: isFirstMessage,
    };

    // First message requires routingAttributes + language (§6.5)
    if (isFirstMessage) {
        body.routingAttributes = {};
        body.language = 'en';
        isFirstMessage = false;
    }

    try {
        addLog('info', `Sending: "${text.substring(0, 40)}${text.length > 40 ? '...' : ''}"`);
        console.log('[send] Message:', text);
        console.log('[send] Body:', JSON.stringify(body, null, 2));
        const resp = await fetch(
            `${config.scrt2Url}/iamessage/api/v2/conversation/${conversationId}/message`,
            {
                method: 'POST',
                headers: {
                    'Content-Type':  'application/json',
                    'Authorization': `Bearer ${miawToken}`,
                },
                body: JSON.stringify(body),
            }
        );

        if (!resp.ok) {
            const errText = await resp.text();
            addLog('error', `Send failed: ${resp.status} — ${errText.substring(0, 100)}`);
            console.error('[send] FAILED:', resp.status, errText);
        } else {
            addLog('info', `Sent (${resp.status})`);
            console.log('[send] OK:', resp.status);
        }
    } catch (e) {
        addLog('error', `Send error: ${e.message}`);
        console.error('[send] ERROR:', e.message);
    }
}

// ═════════════════════════════════════════════════════════════
// SSE STREAM (§6.4)
//
// Uses fetch() with ReadableStream because the native
// EventSource API doesn't support custom headers.
//
// Required headers:
//   Authorization: Bearer {miawToken}
//   X-Org-Id: {orgId}
//   Last-Event-Id: {lastEventId from Step 2}
// ═════════════════════════════════════════════════════════════

function startSSE() {
    sseAbortController = new AbortController();

    const url = `${config.scrt2Url}/eventrouter/v1/sse`;
    const headers = {
        'Authorization': `Bearer ${miawToken}`,
        'Accept':        'text/event-stream',
        'X-Org-Id':      config.orgId,
    };
    if (lastEventId) {
        headers['Last-Event-Id'] = String(lastEventId);
    }

    fetch(url, { headers, signal: sseAbortController.signal })
        .then(response => {
            if (!response.ok) {
                addLog('error', `SSE HTTP ${response.status}`);
                return;
            }
            addLog('success', 'SSE connected');
            console.log('[sse] Connected to SSE stream');

            const reader  = response.body.getReader();
            const decoder = new TextDecoder();
            let buffer    = '';

            function pump() {
                reader.read().then(({ done, value }) => {
                    if (done) {
                        addLog('info', 'SSE stream ended');
                        return;
                    }

                    buffer += decoder.decode(value, { stream: true });

                    // SSE events are separated by double newline
                    const parts = buffer.split('\n\n');
                    buffer = parts.pop(); // keep incomplete tail

                    for (const part of parts) {
                        if (part.trim()) processSSEBlock(part);
                    }

                    pump();
                }).catch(e => {
                    if (e.name !== 'AbortError') {
                        addLog('error', `SSE read: ${e.message}`);
                    }
                });
            }

            pump();
        })
        .catch(e => {
            if (e.name !== 'AbortError') {
                addLog('error', `SSE connect: ${e.message}`);
            }
        });
}

/**
 * Parse a single SSE block into event type + data,
 * then dispatch to handleSSEEvent.
 */
function processSSEBlock(block) {
    let eventType = 'message';
    let dataLines = [];

    for (const line of block.split('\n')) {
        if (line.startsWith('event:')) {
            eventType = line.substring(6).trim();
        } else if (line.startsWith('data:')) {
            dataLines.push(line.substring(5).trim());
        }
    }

    const dataStr = dataLines.join('\n');
    if (!dataStr) return;

    try {
        const parsed = JSON.parse(dataStr);
        // Skip pings (integer 0) and other non-object data
        if (typeof parsed !== 'object' || parsed === null) return;
        console.log(`[sse] Event: ${eventType}`, parsed);
        handleSSEEvent(eventType, parsed);
    } catch {
        // Non-JSON SSE data — ignore
    }
}

// Routing/system events to ignore when looking for agent text (§6.4)
const ROUTING_ENTRY_TYPES = new Set([
    'RoutingWorkResult',
    'RoutingResult',
    'SessionStatusChanged',
    'ParticipantChanged',
    'TypingStartedIndicator',
    'TypingStoppedIndicator',
]);

/**
 * Handle a parsed SSE event. Extract conversation entries and
 * display agent text messages. Show typing indicators.
 */
function handleSSEEvent(eventType, data) {
    const entry   = data.conversationEntry  || null;
    const entries = data.conversationEntries || [];
    const allEntries = entry ? [entry] : entries;

    for (const e of allEntries) {
        const entryType = e.entryType || '';

        // Typing indicators
        if (entryType === 'TypingStartedIndicator') {
            showTypingIndicator(true);
            addLog('info', `${e.senderDisplayName || 'Agent'} typing...`);
            return;
        }
        if (entryType === 'TypingStoppedIndicator') {
            showTypingIndicator(false);
            return;
        }

        // Log routing events but don't treat as messages
        if (ROUTING_ENTRY_TYPES.has(entryType)) {
            addLog('info', `SSE: ${entryType}`);
            return;
        }

        // Agent text message (§7.3)
        if (entryType === 'Message') {
            const sender = e.sender || {};
            if (sender.role === 'EndUser') return; // Our own echo

            const payload = e.entryPayload;
            if (payload) {
                const p = typeof payload === 'string'
                    ? JSON.parse(payload)
                    : payload;
                const text = p?.abstractMessage?.staticContent?.text
                          || p?.message?.staticContent?.text
                          || p?.text;

                if (text) {
                    showTypingIndicator(false);
                    const agentName = e.senderDisplayName || 'Agent';
                    addMessage('agent', text, agentName);
                    addLog('success', `${agentName}: ${text.substring(0, 60)}${text.length > 60 ? '...' : ''}`);
                }
            }
        }
    }
}

// ═════════════════════════════════════════════════════════════
// UI HELPERS
// ═════════════════════════════════════════════════════════════

function addMessage(role, text, name) {
    const div = document.createElement('div');
    div.className = `message ${role}`;

    if (name && role === 'agent') {
        const nameEl = document.createElement('div');
        nameEl.className = 'message-name';
        nameEl.textContent = name;
        div.appendChild(nameEl);
    }

    const textEl = document.createElement('div');
    textEl.className = 'message-text';
    textEl.textContent = text;
    div.appendChild(textEl);

    chatArea.appendChild(div);
    chatArea.scrollTop = chatArea.scrollHeight;
}

let typingEl = null;

function showTypingIndicator(show) {
    if (show && !typingEl) {
        typingEl = document.createElement('div');
        typingEl.className = 'message agent typing';
        typingEl.innerHTML =
            '<div class="typing-dots">' +
            '<span></span><span></span><span></span>' +
            '</div>';
        chatArea.appendChild(typingEl);
        chatArea.scrollTop = chatArea.scrollHeight;
    } else if (!show && typingEl) {
        typingEl.remove();
        typingEl = null;
    }
}

function addLog(type, message) {
    const div = document.createElement('div');
    div.className = `log-entry log-${type}`;

    const time = new Date().toLocaleTimeString('en-US', { hour12: false });
    const prefix = { step: '\u25B6', success: '\u2713', error: '\u2717', info: '\u00B7' }[type] || '\u00B7';

    div.textContent = `${time} ${prefix} ${message}`;
    logArea.appendChild(div);
    logArea.scrollTop = logArea.scrollHeight;
}

function setStatus(type, text) {
    statusBadge.className = `status-badge ${type}`;
    statusBadge.textContent = text;
}

/**
 * Update a flow step in the pre-connect diagram.
 * Steps are numbered 1-4 (matching flow-step elements after step 0).
 */
function updateFlowStep(stepNum, state) {
    const steps = document.querySelectorAll('.flow-step.pending, .flow-step.active, .flow-step.completed');
    // Step 0 is the "already completed" assumption step, so stepNum 1 = index 1
    const el = steps[stepNum];
    if (!el) return;
    el.className = `flow-step ${state}`;
    if (state === 'completed') {
        el.querySelector('.flow-number').textContent = '\u2713';
    }
}

// ── Start ────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', init);
