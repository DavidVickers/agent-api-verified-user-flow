/**
 * AgentAPI_JwtRestEndpoint
 * ─────────────────────────────────────────────────────────────────────
 * REST endpoint that returns a signed identity JWT for external callers.
 *
 * WHY THIS EXISTS: The Python E2E test (§5.2) needs a signed JWT but
 * cannot access the Salesforce certificate private key. This endpoint
 * signs the JWT server-side and returns it, so the Python script can
 * complete the full MIAW verified user flow without any credentials.
 *
 * URL: {SITE_BASE_URL}/services/apexrest/agent-verify/jwt
 *
 * GET — returns a signed JWT with default subject from AgentAPI_Config
 * GET ?sub=user@example.com — override the JWT subject
 *
 * Exposed on the public Salesforce Site alongside the JWKS endpoint.
 * Setup: §3.3 (add to Site Guest User Apex Class Access).
 * ─────────────────────────────────────────────────────────────────────
 */
@RestResource(urlMapping='/agent-verify/jwt')
global with sharing class AgentAPI_JwtRestEndpoint {

    @HttpGet
    global static void getSignedJwt() {
        RestResponse res = RestContext.response;
        res.addHeader('Content-Type', 'application/json');

        try {
            // Allow subject override via ?sub= query param
            String subject = RestContext.request.params.get('sub');
            if (String.isBlank(subject)) {
                subject = AgentAPI_Config.JWT_SUBJECT;
            }

            // Build JWT — same logic as Step 1 (§6.1)
            String headerJson = AgentAPI_JwtUtils.buildJwtHeader(
                AgentAPI_Config.JWT_KID
            );
            String headerB64 = AgentAPI_JwtUtils.base64UrlEncode(
                Blob.valueOf(headerJson)
            );

            String claimsJson = AgentAPI_JwtUtils.buildJwtClaims(
                AgentAPI_Config.JWT_ISSUER,
                subject,
                AgentAPI_Config.JWT_AUDIENCE,
                AgentAPI_Config.JWT_EXPIRY_SECONDS
            );
            String claimsB64 = AgentAPI_JwtUtils.base64UrlEncode(
                Blob.valueOf(claimsJson)
            );

            // Sign with certificate (§2.3.1)
            String signingInput = headerB64 + '.' + claimsB64;
            Blob signature = Crypto.signWithCertificate(
                'RSA-SHA256',
                Blob.valueOf(signingInput),
                AgentAPI_Config.CERTIFICATE_NAME
            );
            String signatureB64 = AgentAPI_JwtUtils.base64UrlEncode(signature);

            String jwt = signingInput + '.' + signatureB64;

            // Return JWT + config the Python script needs for Steps 2-5
            Map<String, Object> result = new Map<String, Object>{
                'jwt'              => jwt,
                'subject'          => subject,
                'issuer'           => AgentAPI_Config.JWT_ISSUER,
                'audience'         => AgentAPI_Config.JWT_AUDIENCE,
                'kid'              => AgentAPI_Config.JWT_KID,
                'expiresInSeconds' => AgentAPI_Config.JWT_EXPIRY_SECONDS,
                'scrt2Url'         => AgentAPI_Config.SCRT2_URL,
                'orgId'            => AgentAPI_Config.ORG_ID,
                'esDeveloperName'  => AgentAPI_Config.ES_DEVELOPER_NAME
            };

            res.statusCode = 200;
            res.responseBody = Blob.valueOf(JSON.serialize(result));

        } catch (Exception e) {
            Map<String, String> errorResult = new Map<String, String>{
                'error'   => e.getMessage(),
                'type'    => e.getTypeName()
            };
            res.statusCode = 500;
            res.responseBody = Blob.valueOf(JSON.serialize(errorResult));
        }
    }
}
