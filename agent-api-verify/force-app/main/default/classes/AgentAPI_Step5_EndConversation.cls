/**
 * AgentAPI_Step5_EndConversation
 * ─────────────────────────────────────────────────────────────────────
 * STEP 5 OF 5 — End of Flow
 *
 * Logs the conversation summary. The MIAW Custom Client API does NOT
 * support client-initiated close — conversations auto-close on timeout
 * or when closed from the Salesforce side (agent or admin).
 *
 * NOTE: Matching the verified identity (uid from the MIAW platform key)
 * to a Salesforce Contact/User is NOT handled here. That will be built
 * as a separate service.
 * ─────────────────────────────────────────────────────────────────────
 */
public with sharing class AgentAPI_Step5_EndConversation {

    public static void execute(String miawToken, String conversationId) {
        AgentAPI_Logger.step(5, 'End of Flow');

        AgentAPI_Logger.detail('Conversation ID', conversationId);
        AgentAPI_Logger.detail('Verified User', AgentAPI_Config.JWT_SUBJECT);

        AgentAPI_Logger.note(
            'The MIAW Custom Client API does not support client-initiated ' +
            'conversation close. Conversations auto-close on timeout or ' +
            'when closed from the Salesforce side.'
        );

        AgentAPI_Logger.note(
            'Identity-to-Contact/User matching will be handled by a ' +
            'separate service (not part of this flow).'
        );
    }
}
