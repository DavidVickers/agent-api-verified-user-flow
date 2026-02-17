/**
 * AgentAPI_Step2_GetMiawToken
 * ─────────────────────────────────────────────────────────────────────
 * STEP 2 OF 5 — Exchange JWT for MIAW Access Token
 *
 * This is the CRITICAL verification step. SCRT2 receives our signed
 * JWT, fetches the JWKS, validates the signature and claims, then
 * returns either an AUTH (verified) or ANON (anonymous) token.
 *
 * See SETUP_GUIDE.md §6.2 for the complete request/response format.
 * See §2.1 for the full SCRT2 internal verification sequence.
 * See §2.4 for why failures silently fall back to ANON (the trap).
 *
 * The response also includes lastEventId — required for SSE (§6.4).
 * ─────────────────────────────────────────────────────────────────────
 */
public with sharing class AgentAPI_Step2_GetMiawToken {

    // Stored after execute() — needed for SSE subscription (§6.4)
    public static String lastEventId;

    // Stored after execute() — the endUser subject (platform key)
    // e.g. v2/iamessage/AUTH/agentverifykeys/uid:user@example.com
    // Used by the orchestrator to invoke identity resolution.
    public static String endUserSubject;

    public static String execute(String identityJwt) {
        AgentAPI_Logger.step(2, 'Exchange JWT for MIAW Access Token');

        // ── ENDPOINT: SCRT2 authenticated access-token ──────────────
        // This is the MIAW Custom Client API — NOT the headless Agent
        // API. The verified user flow goes through SCRT2 (§1.1).
        String endpoint = AgentAPI_Config.SCRT2_URL
            + '/iamessage/api/v2/authorization/authenticated/access-token';

        // ── REQUEST BODY (§6.2) ─────────────────────────────────────
        // orgId + esDeveloperName identify WHICH deployment (§2.3.6)
        // authorizationType "JWT" triggers the verification flow
        // customerIdentityToken is the signed JWT from Step 1 (§6.1)
        Map<String, Object> requestBody = new Map<String, Object>{
            'orgId'                 => AgentAPI_Config.ORG_ID,
            'esDeveloperName'       => AgentAPI_Config.ES_DEVELOPER_NAME,
            'capabilitiesVersion'   => '1',
            'platform'              => 'Web',
            'authorizationType'     => 'JWT',
            'customerIdentityToken' => identityJwt
        };

        String body = JSON.serialize(requestBody);

        HttpRequest req = new HttpRequest();
        req.setEndpoint(endpoint);
        req.setMethod('POST');
        req.setHeader('Content-Type', 'application/json');
        req.setBody(body);
        req.setTimeout(30000);

        AgentAPI_Logger.httpRequest('POST', endpoint, body);

        // SEND — this is where SCRT2 validates the JWT.
        // Internally: fetch JWKS → find kid → verify sig → check claims (§2.1)
        HttpResponse res = new Http().send(req);

        AgentAPI_Logger.httpResponse(res.getStatusCode(), res.getBody());

        if (res.getStatusCode() < 200 || res.getStatusCode() >= 300) {
            AgentAPI_Logger.error('MIAW token exchange failed: ' + res.getBody());
            throw new AgentAPI_Exception(
                'Step 2 failed: HTTP ' + res.getStatusCode() + ' — ' + res.getBody()
            );
        }

        Map<String, Object> response = (Map<String, Object>)
            JSON.deserializeUntyped(res.getBody());

        String miawToken = (String) response.get('accessToken');

        // ── lastEventId — needed for SSE (§6.4) ────────────────────
        // The Python test passes this as the Last-Event-Id header
        // when subscribing to SSE. Without it, SSE returns 400.
        lastEventId = String.valueOf(response.get('lastEventId'));
        if (lastEventId != null) {
            AgentAPI_Logger.detail('Last Event ID', lastEventId);
        }

        // ── VERIFICATION EVIDENCE (§7.1) ────────────────────────────
        // The ONLY way to know if verification succeeded is to check
        // context.endUser.subject for AUTH vs ANON.
        //   Verified:  v2/iamessage/AUTH/{keyset}/uid:{username}
        //   Anonymous: v2/iamessage/ANON/...
        // SCRT2 returns HTTP 200 for BOTH — see §2.4 for the trap.
        Map<String, Object> context = (Map<String, Object>) response.get('context');
        if (context != null) {
            Map<String, Object> endUser = (Map<String, Object>) context.get('endUser');
            if (endUser != null) {
                endUserSubject = (String) endUser.get('subject');
                String endUserRole = (String) endUser.get('role');

                AgentAPI_Logger.detail('End User Subject', endUserSubject);
                AgentAPI_Logger.detail('End User Role', endUserRole);

                // AUTH = verified, ANON = failed (see §2.5 for causes)
                if (endUserSubject != null && endUserSubject.contains('/AUTH/')) {
                    AgentAPI_Logger.success(
                        'USER IS VERIFIED (AUTH) — identity confirmed'
                    );
                    String[] parts = endUserSubject.split('/');
                    if (parts.size() >= 5) {
                        AgentAPI_Logger.detail('JWKS Keyset', parts[3]);
                        AgentAPI_Logger.detail('Verified Identity',
                            parts[4].replaceFirst('uid:', ''));
                    }
                } else if (endUserSubject != null && endUserSubject.contains('/ANON/')) {
                    AgentAPI_Logger.error(
                        'USER IS ANONYMOUS (ANON) — verification FAILED! ' +
                        'Check the 6-artifact checklist in §2.3.'
                    );
                } else {
                    AgentAPI_Logger.detail('Auth Status', 'Unknown subject format');
                }
            }

            // Show deployment type from context
            Map<String, Object> config = (Map<String, Object>) context.get('configuration');
            if (config != null) {
                Map<String, Object> esConfig = (Map<String, Object>) config.get('embeddedServiceConfig');
                if (esConfig != null) {
                    String deploymentType = (String) esConfig.get('deploymentType');
                    if (deploymentType != null) {
                        AgentAPI_Logger.detail('Deployment Type', deploymentType);
                    }
                }
            }
        }

        AgentAPI_Logger.detail('MIAW Token', miawToken != null
            ? miawToken.substring(0, Math.min(60, miawToken.length())) + '...'
            : 'null');
        AgentAPI_Logger.success('MIAW access token obtained');

        return miawToken;
    }
}
