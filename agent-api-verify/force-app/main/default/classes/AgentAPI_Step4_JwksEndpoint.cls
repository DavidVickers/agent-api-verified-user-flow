/**
 * AgentAPI_Step4_JwksEndpoint
 * ─────────────────────────────────────────────────────────────────────
 * INFRASTRUCTURE — Public JWKS Endpoint (Not a Numbered Step)
 *
 * Serves the JSON Web Key Set (JWKS) containing the public key that
 * matches our signing certificate. Exposed via a Salesforce Site so
 * the SCRT2 gateway can fetch it during token exchange (§6.2).
 *
 * URL: {SITE_BASE_URL}/services/apexrest/jwks
 *
 * This is the "other half" of the cryptographic link described in
 * §2.3.1. The certificate private key signs the JWT (Step 1), and
 * this endpoint serves the public key for SCRT2 to verify it.
 *
 * Setup requirements: §3.3 (Site creation + Guest User profile access)
 *
 * NOTE: Class name includes "Step4" for historical reasons — changing
 * it would break the deployed Site Guest User profile configuration.
 * ─────────────────────────────────────────────────────────────────────
 */
@RestResource(urlMapping='/jwks')
global with sharing class AgentAPI_Step4_JwksEndpoint {

    @HttpGet
    global static void getKeys() {
        RestResponse res = RestContext.response;
        // Must return application/json for SCRT2 to parse it
        res.addHeader('Content-Type', 'application/json');
        // Cache for 1 hour — keys rarely change, but don't cache forever
        // because certificates can be rotated (see §2.3.5)
        res.addHeader('Cache-Control', 'public, max-age=3600');
        // Allow any origin — SCRT2 fetches from a different domain
        res.addHeader('Access-Control-Allow-Origin', '*');

        // Load pre-computed JWKS from Static Resource (§3.2)
        String jwksJson = AgentAPI_JwtUtils.loadJwksFromStaticResource();
        res.responseBody = Blob.valueOf(jwksJson);
    }

    /**
     * Informational method called by the Orchestrator to show what
     * this endpoint serves. Not part of the REST interface.
     */
    public static void describeEndpoint() {
        AgentAPI_Logger.separator();
        System.debug('  JWKS ENDPOINT (Infrastructure — Not a Step)');
        AgentAPI_Logger.separator();

        String jwksJson = AgentAPI_JwtUtils.loadJwksFromStaticResource();
        String endpointUrl = AgentAPI_Config.SITE_BASE_URL + '/services/apexrest/jwks';

        AgentAPI_Logger.detail('Endpoint URL', endpointUrl);
        AgentAPI_Logger.json('Response Body (JWKS)', jwksJson);
        AgentAPI_Logger.note(
            'Public endpoint on SF Site. SCRT2 fetches this during ' +
            'Step 2 (§6.2) to verify the JWT signature from Step 1. ' +
            'The public key here must match the certificate used to sign (§2.3.1).'
        );
    }
}
