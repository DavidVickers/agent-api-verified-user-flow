/**
 * AgentAPI_GetAgentResponse
 * ─────────────────────────────────────────────────────────────────────
 * Retrieves the agent's response after sending a message (Step 4).
 *
 * Agent responses arrive asynchronously via SSE (§6.4). Apex cannot
 * maintain SSE connections, so this class uses two fallback approaches:
 *
 *   1. Poll GET /conversation/{id}/entries — regular HTTP (§7.3)
 *   2. Fall back to SOQL on ConversationEntry via MessagingSession
 *
 * For reliable real-time responses, use the Python E2E test (§5.2)
 * which has full SSE support.
 *
 * See SETUP_GUIDE.md §7.3 for the entries endpoint format.
 * See §6.4 for the SSE event types and lifecycle.
 * ─────────────────────────────────────────────────────────────────────
 */
public with sharing class AgentAPI_GetAgentResponse {

    private static final Integer MAX_POLL_ATTEMPTS = 3;
    private static final Integer POLL_TIMEOUT_MS   = 10000;

    /**
     * Poll for the agent's response. Called after Step 4 (§6.5).
     * Uses the entries endpoint (§7.3), then falls back to SOQL.
     */
    public static void execute(String miawToken, String conversationId) {
        AgentAPI_Logger.separator();
        AgentAPI_Logger.detail('ACTION', 'Retrieve Agent Response');
        AgentAPI_Logger.note(
            'Polling SCRT2 for agent response (' +
            MAX_POLL_ATTEMPTS + ' attempts with delay between each)...'
        );

        // ── Poll the entries endpoint with delays ────────────────────
        for (Integer attempt = 1; attempt <= MAX_POLL_ATTEMPTS; attempt++) {
            // Add a delay between polls by hitting the JWKS endpoint.
            // This gives the agent time to process (~1-2s per round trip).
            if (attempt > 1) {
                addDelay(miawToken);
            }

            AgentAPI_Logger.detail('Poll Attempt',
                attempt + ' of ' + MAX_POLL_ATTEMPTS);

            Boolean found = tryGetEntries(miawToken, conversationId, attempt == 1);
            if (found) {
                return; // Response found and displayed
            }
        }

        // ── SOQL fallback ────────────────────────────────────────────
        AgentAPI_Logger.note(
            'Agent has not responded within polling window. ' +
            'Checking Salesforce records...'
        );
        querySoql();

        AgentAPI_Logger.note(
            'The agent responds asynchronously. If no response was found, ' +
            'wait a few seconds and run: ' +
            'AgentAPI_GetAgentResponse.checkLatest();'
        );
    }

    /**
     * Standalone: check the latest conversation for agent responses.
     * Use this from Anonymous Apex when the main flow has already run:
     *   AgentAPI_GetAgentResponse.checkLatest();
     */
    public static void checkLatest() {
        AgentAPI_Logger.banner('CHECK LATEST AGENT RESPONSE');
        querySoql();
    }

    // ═════════════════════════════════════════════════════════════════
    // APPROACH 1: GET conversation entries from SCRT2 (§7.3)
    // ═════════════════════════════════════════════════════════════════

    /**
     * Add delay between poll attempts via an HTTP callout.
     * Each JWKS fetch adds ~500ms-2s of natural delay.
     */
    private static void addDelay(String miawToken) {
        try {
            HttpRequest req = new HttpRequest();
            req.setEndpoint(AgentAPI_Config.SITE_BASE_URL + '/services/apexrest/jwks');
            req.setMethod('GET');
            req.setTimeout(5000);
            new Http().send(req);
        } catch (Exception e) {
            // Ignore — this is just for delay
        }
    }

    private static Boolean tryGetEntries(
        String miawToken, String conversationId, Boolean logRaw
    ) {
        String endpoint = AgentAPI_Config.SCRT2_URL
            + '/iamessage/api/v2/conversation/'
            + conversationId + '/entries';

        try {
            HttpRequest req = new HttpRequest();
            req.setEndpoint(endpoint);
            req.setMethod('GET');
            req.setHeader('Authorization', 'Bearer ' + miawToken);
            req.setHeader('Accept', 'application/json');
            req.setTimeout(POLL_TIMEOUT_MS);

            HttpResponse res = new Http().send(req);

            if (res.getStatusCode() >= 200 && res.getStatusCode() < 300) {
                String body = res.getBody();

                // Log raw response on first attempt so we can see the format
                if (logRaw && String.isNotBlank(body)) {
                    AgentAPI_Logger.detail('Entries Raw Response',
                        body.abbreviate(1500));
                }

                return parseEntriesResponse(body);
            } else {
                AgentAPI_Logger.detail('Entries HTTP',
                    res.getStatusCode() + ': ' +
                    res.getBody().abbreviate(200));
            }
        } catch (Exception e) {
            AgentAPI_Logger.detail('Entries Error', e.getMessage());
        }

        return false;
    }

    /**
     * Parse the entries response for agent messages (§7.3).
     * SCRT2 returns { "conversationEntries": [ { ... } ] }.
     * Entry types include Message, RoutingResult, etc. (§6.4).
     * We check multiple field names to handle format variations.
     */
    private static Boolean parseEntriesResponse(String responseBody) {
        if (String.isBlank(responseBody)) return false;

        try {
            Map<String, Object> data = (Map<String, Object>)
                JSON.deserializeUntyped(responseBody);

            List<Object> entries = (List<Object>) data.get('conversationEntries');
            if (entries == null) {
                entries = (List<Object>) data.get('entries');
            }
            if (entries == null) return false;

            Boolean foundAgent = false;

            for (Object entryObj : entries) {
                Map<String, Object> entry = (Map<String, Object>) entryObj;
                if (isAgentEntry(entry)) {
                    displayAgentEntry(entry);
                    foundAgent = true;
                }
            }

            return foundAgent;

        } catch (Exception e) {
            AgentAPI_Logger.detail('Parse Error', e.getMessage());
            return false;
        }
    }

    /**
     * Determine if an entry is from the agent (not the end user).
     * Checks multiple field patterns since SCRT2 format may vary.
     */
    private static Boolean isAgentEntry(Map<String, Object> entry) {
        // Check actorType (common SSE format)
        String actorType = (String) entry.get('actorType');
        if (actorType != null) {
            String lower = actorType.toLowerCase();
            if (lower.contains('bot') || lower.contains('agent') ||
                lower == 'system') {
                return true;
            }
            // If actorType is "endUser" or "EndUser", it's our message
            if (lower.contains('user')) return false;
        }

        // Check sender.role (MIAW API format)
        Object senderObj = entry.get('sender');
        if (senderObj instanceof Map<String, Object>) {
            Map<String, Object> sender = (Map<String, Object>) senderObj;
            String role = (String) sender.get('role');
            if (role != null && !role.equalsIgnoreCase('EndUser')) {
                return true;
            }
        }

        // Check senderDisplayName
        String senderName = (String) entry.get('senderDisplayName');
        if (senderName != null && !senderName.equalsIgnoreCase('Guest') &&
            !senderName.equalsIgnoreCase('End User')) {
            return true;
        }

        // If actorType and sender are both null, check entryPayload
        // to see if it looks like a bot response
        if (actorType == null && senderObj == null) {
            String entryType = (String) entry.get('entryType');
            // On the first poll, only our message exists — skip it
            // Later polls might have agent entries with null actorType
            // but different entryPayload format
            if (entryType != null && entryType != 'Message') {
                return true; // Events, routing entries, etc.
            }
        }

        return false;
    }

    /**
     * Display an agent entry's content.
     */
    private static void displayAgentEntry(Map<String, Object> entry) {
        // Get the agent's display name from various fields
        String agentName = (String) entry.get('actorName');
        if (agentName == null) {
            agentName = (String) entry.get('senderDisplayName');
        }
        if (agentName == null) {
            Object senderObj = entry.get('sender');
            if (senderObj instanceof Map<String, Object>) {
                Map<String, Object> sender = (Map<String, Object>) senderObj;
                agentName = (String) sender.get('subject');
                if (agentName == null) agentName = (String) sender.get('role');
            }
        }
        if (agentName == null) agentName = 'Agent';

        String entryType = (String) entry.get('entryType');

        // Extract the message text from entryPayload
        String payload = (String) entry.get('entryPayload');
        if (payload != null) {
            String text = extractTextFromPayload(payload);
            if (text != null) {
                AgentAPI_Logger.success(agentName + ' says: ' + text);
                return;
            }
            // Couldn't extract text — show raw payload
            AgentAPI_Logger.success(agentName + ' (' + entryType + '):');
            AgentAPI_Logger.detail('Payload', payload.abbreviate(1000));
            return;
        }

        // Check for direct message field
        String message = (String) entry.get('message');
        if (message != null) {
            AgentAPI_Logger.success(agentName + ' says: ' + message);
            return;
        }

        // No text found — show the entry keys for debugging
        AgentAPI_Logger.success(agentName + ' (' + entryType + ') — entry received');
        AgentAPI_Logger.detail('Entry Keys', String.valueOf(entry.keySet()));
    }

    /**
     * Extract text from an entryPayload JSON string (§7.3).
     * Agent messages use: abstractMessage.staticContent.text
     */
    private static String extractTextFromPayload(String payload) {
        try {
            Map<String, Object> p = (Map<String, Object>)
                JSON.deserializeUntyped(payload);

            // Format 1: abstractMessage.staticContent.text
            Map<String, Object> abstractMsg =
                (Map<String, Object>) p.get('abstractMessage');
            if (abstractMsg != null) {
                Map<String, Object> staticContent =
                    (Map<String, Object>) abstractMsg.get('staticContent');
                if (staticContent != null) {
                    String text = (String) staticContent.get('text');
                    if (text != null) return text;
                }
            }

            // Format 2: message.staticContent.text
            Map<String, Object> message =
                (Map<String, Object>) p.get('message');
            if (message != null) {
                Map<String, Object> staticContent =
                    (Map<String, Object>) message.get('staticContent');
                if (staticContent != null) {
                    String text = (String) staticContent.get('text');
                    if (text != null) return text;
                }
            }

            // Format 3: direct text field
            String text = (String) p.get('text');
            if (text != null) return text;

            // Format 4: formatType + text (flat)
            if (p.containsKey('formatType')) {
                text = (String) p.get('text');
                if (text != null) return text;
            }

        } catch (Exception e) {
            // Not JSON or unexpected format
        }

        return null;
    }

    // ═════════════════════════════════════════════════════════════════
    // APPROACH 2: SOQL fallback — query Salesforce records (§7.3)
    // ═════════════════════════════════════════════════════════════════
    private static void querySoql() {
        // Query the most recent MessagingSession records
        List<MessagingSession> sessions = [
            SELECT Id, Name, MessagingEndUserId,
                   AgentType, AgentMessageCount, EndUserMessageCount
            FROM MessagingSession
            WHERE CreatedDate = TODAY
            ORDER BY CreatedDate DESC
            LIMIT 5
        ];

        if (sessions.isEmpty()) {
            AgentAPI_Logger.note('No MessagingSession records found today.');
            return;
        }

        MessagingSession session = sessions[0];
        AgentAPI_Logger.detail('Session ID', session.Id);
        AgentAPI_Logger.detail('Session Name', session.Name);
        AgentAPI_Logger.detail('Agent Type', session.AgentType);
        AgentAPI_Logger.detail('Agent Messages',
            String.valueOf(session.AgentMessageCount));
        AgentAPI_Logger.detail('End User Messages',
            String.valueOf(session.EndUserMessageCount));

        // Try to get the conversation transcript via ConversationEntry
        try {
            List<SObject> entries = Database.query(
                'SELECT Id, Message, ActorType, ActorName, ' +
                'EntryType, ConversationId ' +
                'FROM ConversationEntry ' +
                'WHERE ConversationId IN ' +
                '(SELECT ConversationId FROM MessagingSession ' +
                'WHERE Id = \'' + String.escapeSingleQuotes(session.Id) + '\') ' +
                'ORDER BY CreatedDate ASC'
            );

            if (entries.isEmpty()) {
                AgentAPI_Logger.note(
                    'No ConversationEntry records found yet. ' +
                    'The agent may still be processing.'
                );
                return;
            }

            AgentAPI_Logger.detail('Conversation Entries Found',
                String.valueOf(entries.size()));

            for (SObject entry : entries) {
                String actorType = (String) entry.get('ActorType');
                String actorName = (String) entry.get('ActorName');
                String message   = (String) entry.get('Message');
                String eType     = (String) entry.get('EntryType');

                String displayMsg = message != null ? message : '[no text]';

                if (actorType != null &&
                    (actorType.containsIgnoreCase('bot') ||
                     actorType.containsIgnoreCase('agent') ||
                     actorType.containsIgnoreCase('chatbot'))) {
                    AgentAPI_Logger.success(
                        'AGENT (' + actorName + '): ' + displayMsg);
                } else if (actorType != null &&
                           actorType.containsIgnoreCase('user')) {
                    AgentAPI_Logger.detail('USER', displayMsg);
                } else {
                    AgentAPI_Logger.detail(
                        (actorType != null ? actorType : 'Unknown') +
                        ' (' + eType + ')', displayMsg);
                }
            }
        } catch (Exception e) {
            AgentAPI_Logger.note(
                'Could not query ConversationEntry: ' + e.getMessage() +
                '. Try checking in Omni Supervisor or run: ' +
                'SELECT Id, AgentType, AgentMessageCount, ' +
                'EndUserMessageCount FROM MessagingSession ' +
                'WHERE CreatedDate = TODAY ORDER BY CreatedDate DESC LIMIT 5'
            );
        }
    }
}
