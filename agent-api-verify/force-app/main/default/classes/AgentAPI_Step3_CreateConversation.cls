/**
 * AgentAPI_Step3_CreateConversation
 * ─────────────────────────────────────────────────────────────────────
 * STEP 3 OF 5 — Create a MIAW Conversation
 *
 * Opens a new conversation, equivalent to a user opening a chat window.
 * The conversation inherits the verified-user context from the MIAW
 * token obtained in Step 2.
 *
 * See SETUP_GUIDE.md §6.3 for the request format.
 * See §6.4 for why SSE must be subscribed BEFORE sending a message.
 * ─────────────────────────────────────────────────────────────────────
 */
public with sharing class AgentAPI_Step3_CreateConversation {

    public static String execute(String miawToken) {
        AgentAPI_Logger.step(3, 'Create Conversation');

        // Generate a UUID v4 for the conversation ID.
        // SCRT2 enforces strict v4 compliance — see §6.3 and §10.
        String conversationId = AgentAPI_JwtUtils.generateUUID();
        AgentAPI_Logger.detail('Conversation ID', conversationId);

        // ── ENDPOINT (§6.3) ─────────────────────────────────────────
        // Bearer token is the MIAW access token from Step 2,
        // NOT a Salesforce OAuth token.
        String endpoint = AgentAPI_Config.SCRT2_URL
            + '/iamessage/api/v2/conversation';

        // ── REQUEST BODY ────────────────────────────────────────────
        // conversationId = our UUID v4 (strict compliance required)
        // esDeveloperName = Embedded Service Deployment name (§2.3.6)
        Map<String, Object> requestBody = new Map<String, Object>{
            'conversationId'  => conversationId,
            'esDeveloperName' => AgentAPI_Config.ES_DEVELOPER_NAME
        };

        String body = JSON.serialize(requestBody);

        HttpRequest req = new HttpRequest();
        req.setEndpoint(endpoint);
        req.setMethod('POST');
        req.setHeader('Content-Type', 'application/json');
        req.setHeader('Authorization', 'Bearer ' + miawToken);
        req.setBody(body);
        req.setTimeout(30000);

        AgentAPI_Logger.httpRequest('POST', endpoint, body);

        HttpResponse res = new Http().send(req);

        AgentAPI_Logger.httpResponse(res.getStatusCode(), res.getBody());

        if (res.getStatusCode() < 200 || res.getStatusCode() >= 300) {
            AgentAPI_Logger.error('Conversation creation failed: ' + res.getBody());
            throw new AgentAPI_Exception(
                'Step 3 failed: HTTP ' + res.getStatusCode() + ' — ' + res.getBody()
            );
        }

        AgentAPI_Logger.success('Conversation created: ' + conversationId);
        AgentAPI_Logger.note(
            'Conversation is open and routed via Omni-Channel. ' +
            'Next: SSE must be subscribed BEFORE sending a message (§6.4), ' +
            'then Step 4 sends the first message (§6.5).'
        );

        return conversationId;
    }
}
