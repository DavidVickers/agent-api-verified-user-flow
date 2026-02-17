/**
 * AgentAPI_Orchestrator
 * ─────────────────────────────────────────────────────────────────────
 * Runs the full MIAW Verified User flow from a single call.
 * See SETUP_GUIDE.md §5.1 for usage instructions.
 *
 * THE FLOW (5 Steps — see §6.1–§6.6 for each API call):
 *   Step 1: Build Identity JWT (§6.1)
 *   Step 2: Get MIAW Token    (§6.2) — SCRT2 fetches JWKS here (§2.1)
 *   Step 3: Create Conversation (§6.3)
 *   Step 4: Send Message       (§6.5)
 *   (Poll)  Get Agent Response (§7.3) — Apex fallback for SSE (§6.4)
 *   Step 5: Verify MEU         (§6.6 / §7.2)
 *
 * Usage (Anonymous Apex):
 *   AgentAPI_Orchestrator.execute();                          // Full flow
 *   AgentAPI_Orchestrator.execute('What are my open cases?'); // Custom msg
 *   AgentAPI_Orchestrator.executeStep(1);                     // Single step
 *   AgentAPI_Orchestrator.executeWithToken('eyJ...');         // Skip Steps 1-2
 * ─────────────────────────────────────────────────────────────────────
 */
public with sharing class AgentAPI_Orchestrator {

    private static final String DEFAULT_MESSAGE = 'Hello, what can you help me with?';

    /**
     * Run the full flow with default message.
     */
    public static void execute() {
        execute(DEFAULT_MESSAGE);
    }

    /**
     * Run the full flow with a custom user message.
     */
    public static void execute(String userMessage) {
        AgentAPI_Logger.banner('MIAW VERIFIED USER FLOW');
        AgentAPI_Logger.config(AgentAPI_Config.describe());

        // Step 1: Build and sign the identity JWT (§6.1)
        String identityJwt = AgentAPI_Step1_BuildJwt.execute();

        // Step 2: Exchange JWT for MIAW access token (§6.2)
        // SCRT2 fetches JWKS and validates during this call (§2.1)
        String miawToken = AgentAPI_Step2_GetMiawToken.execute(identityJwt);

        // Show JWKS endpoint info (SCRT2 fetched this during Step 2)
        AgentAPI_Step4_JwksEndpoint.describeEndpoint();

        // ── Resolve Identity ─────────────────────────────────────
        // After verification, resolve the verified identity to
        // Salesforce records (Contact/Account or Lead).
        String subject = AgentAPI_Step2_GetMiawToken.endUserSubject;
        if (String.isNotBlank(subject)) {
            AgentAPI_Logger.step(0, 'Resolve Verified Identity');
            AgentAPI_Logger.detail('Subject (Platform Key)', subject);
            Map<String, Object> identity = AgentAPI_ResolveIdentity.resolveFromSubject(subject);
            for (String key : identity.keySet()) {
                AgentAPI_Logger.detail(key, String.valueOf(identity.get(key)));
            }
            Boolean resolved = identity.get('resolved') == true;
            if (resolved) {
                AgentAPI_Logger.success('Identity resolved: ' + String.valueOf(identity.get('message')));
            } else if (identity.containsKey('error')) {
                AgentAPI_Logger.error('Identity resolution failed: ' + String.valueOf(identity.get('error')));
            } else {
                AgentAPI_Logger.note('Identity not yet resolved: ' + String.valueOf(identity.get('message')));
            }
        } else {
            AgentAPI_Logger.note('No endUser subject returned — skipping identity resolution.');
        }

        // Step 3: Create a conversation (§6.3)
        String conversationId = AgentAPI_Step3_CreateConversation.execute(miawToken);

        // Step 4: Send a message as the verified user (§6.5)
        AgentAPI_Step4_SendMessage.execute(miawToken, conversationId, userMessage);

        // Poll for the agent's response (§7.3 — Apex fallback for SSE §6.4)
        AgentAPI_GetAgentResponse.execute(miawToken, conversationId);

        // Step 5: Verify the MessagingEndUser record (§6.6 / §7.2)
        AgentAPI_Step5_EndConversation.execute(miawToken, conversationId);

        AgentAPI_Logger.banner('FLOW COMPLETE');
    }

    /**
     * Run the flow with an existing MIAW token (skip Steps 1-2).
     * Useful when you already have a valid MIAW token from a prior run.
     */
    public static void executeWithToken(String miawToken) {
        executeWithToken(miawToken, DEFAULT_MESSAGE);
    }

    /**
     * Run with existing MIAW token and custom message.
     */
    public static void executeWithToken(String miawToken, String userMessage) {
        AgentAPI_Logger.banner('MIAW VERIFIED USER FLOW (with existing token)');
        AgentAPI_Logger.config(AgentAPI_Config.describe());
        AgentAPI_Logger.detail('MIAW Token', miawToken.abbreviate(60));
        AgentAPI_Logger.note('Skipping Steps 1-2 — using provided MIAW token.');

        String conversationId = AgentAPI_Step3_CreateConversation.execute(miawToken);
        AgentAPI_Step4_SendMessage.execute(miawToken, conversationId, userMessage);
        AgentAPI_GetAgentResponse.execute(miawToken, conversationId);
        AgentAPI_Step5_EndConversation.execute(miawToken, conversationId);

        AgentAPI_Logger.banner('FLOW COMPLETE');
    }

    /**
     * Run a single step for debugging. Steps that require prior
     * outputs will use placeholder values and note the limitation.
     */
    public static void executeStep(Integer stepNumber) {
        AgentAPI_Logger.banner('MIAW VERIFIED USER — STEP ' + stepNumber + ' ONLY');

        switch on stepNumber {
            when 1 {
                AgentAPI_Step1_BuildJwt.execute();
            }
            when 2 {
                AgentAPI_Logger.note(
                    'Step 2 requires an identity JWT from Step 1. ' +
                    'Use execute() for the full flow.'
                );
            }
            when 3 {
                AgentAPI_Logger.note(
                    'Step 3 requires a MIAW access token from Step 2. ' +
                    'Use execute() for the full flow.'
                );
            }
            when 4 {
                AgentAPI_Logger.note(
                    'Step 4 requires a MIAW token and conversation ID. ' +
                    'Use execute() for the full flow.'
                );
            }
            when 5 {
                AgentAPI_Logger.note(
                    'Step 5 requires a MIAW token and conversation ID. ' +
                    'Use execute() for the full flow.'
                );
            }
            when else {
                AgentAPI_Logger.error('Invalid step number: ' + stepNumber +
                    '. Valid steps are 1-5.');
            }
        }

        AgentAPI_Logger.banner('STEP ' + stepNumber + ' COMPLETE');
    }

    /**
     * Show JWKS endpoint info without running the full flow.
     */
    public static void showJwksInfo() {
        AgentAPI_Logger.banner('JWKS ENDPOINT INFO');
        AgentAPI_Step4_JwksEndpoint.describeEndpoint();
    }
}
