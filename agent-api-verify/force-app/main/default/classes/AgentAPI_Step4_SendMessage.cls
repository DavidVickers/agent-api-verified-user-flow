/**
 * AgentAPI_Step4_SendMessage
 * ─────────────────────────────────────────────────────────────────────
 * STEP 4 OF 5 — Send a Message into the Conversation
 *
 * Sends a text message as the verified user. Because the conversation
 * was created with an AUTH MIAW token, the agent knows WHO is asking
 * and can access verified-only topics/actions.
 *
 * See SETUP_GUIDE.md §6.5 for the message format.
 *
 * IMPORTANT: The /message endpoint returns 202 (Accepted) — the agent
 * responds asynchronously via SSE (§6.4). Apex cannot maintain SSE
 * connections, so we poll the entries endpoint instead (§7.3).
 * For reliable real-time responses, use the Python test (§5.2).
 *
 * NOTE: The first message SHOULD include routingAttributes and language
 * when isNewMessagingSession=true. The Python test includes these;
 * the Apex version omits them because Omni-Channel still routes
 * successfully without them in our testing. See §6.5 for details.
 * ─────────────────────────────────────────────────────────────────────
 */
public with sharing class AgentAPI_Step4_SendMessage {

    public static Map<String, Object> execute(
        String miawToken,
        String conversationId,
        String userMessage
    ) {
        AgentAPI_Logger.step(4, 'Send Message');

        // ── ENDPOINT (§6.5) ─────────────────────────────────────────
        String endpoint = AgentAPI_Config.SCRT2_URL
            + '/iamessage/api/v2/conversation/'
            + conversationId + '/message';

        // ── MESSAGE STRUCTURE (§6.5) ────────────────────────────────
        // StaticContentMessage with formatType "Text" for plain text.
        // Each message needs a unique UUID as its ID.
        // isNewMessagingSession=true triggers Omni-Channel routing.
        String messageId = AgentAPI_JwtUtils.generateUUID();

        Map<String, Object> staticContent = new Map<String, Object>{
            'formatType' => 'Text',
            'text'       => userMessage
        };

        Map<String, Object> message = new Map<String, Object>{
            'id'            => messageId,
            'messageType'   => 'StaticContentMessage',
            'staticContent' => staticContent
        };

        Map<String, Object> requestBody = new Map<String, Object>{
            'message'              => message,
            'esDeveloperName'      => AgentAPI_Config.ES_DEVELOPER_NAME,
            'isNewMessagingSession' => true
        };

        String body = JSON.serialize(requestBody);

        HttpRequest req = new HttpRequest();
        req.setEndpoint(endpoint);
        req.setMethod('POST');
        req.setHeader('Content-Type', 'application/json');
        req.setHeader('Authorization', 'Bearer ' + miawToken);
        req.setBody(body);
        // 2 min timeout — agent reasoning can take time
        req.setTimeout(120000);

        AgentAPI_Logger.httpRequest('POST', endpoint, body);
        AgentAPI_Logger.detail('User Message', userMessage);
        AgentAPI_Logger.detail('Message ID', messageId);

        HttpResponse res = new Http().send(req);

        AgentAPI_Logger.httpResponse(res.getStatusCode(), res.getBody());

        if (res.getStatusCode() < 200 || res.getStatusCode() >= 300) {
            AgentAPI_Logger.error('Message send failed: ' + res.getBody());
            throw new AgentAPI_Exception(
                'Step 4 failed: HTTP ' + res.getStatusCode() + ' — ' + res.getBody()
            );
        }

        Map<String, Object> response = new Map<String, Object>();
        if (String.isNotBlank(res.getBody())) {
            response = (Map<String, Object>)
                JSON.deserializeUntyped(res.getBody());
        }

        AgentAPI_Logger.success('Message sent to conversation ' + conversationId);
        AgentAPI_Logger.note(
            'Returns 202 Accepted — agent responds asynchronously via SSE. ' +
            'Apex polls the entries endpoint as a fallback (see §7.3).'
        );

        return response;
    }
}
