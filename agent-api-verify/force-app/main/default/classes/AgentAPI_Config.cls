/**
 * AgentAPI_Config
 * ─────────────────────────────────────────────────────────────────────
 * Central configuration for the MIAW Verified User flow.
 *
 * Every other class reads from here — change values in ONE place.
 *
 * These values form the "6-artifact checklist" described in
 * SETUP_GUIDE.md §2.3. If ANY value is wrong, verification silently
 * falls back to ANON (see §2.4).
 * ─────────────────────────────────────────────────────────────────────
 */
public with sharing class AgentAPI_Config {

    // ─── Org (§1.2) ─────────────────────────────────────────────────
    // My Domain URL — must match JWT "aud" claim EXACTLY (see §2.3.4)
    public static final String MY_DOMAIN_URL = 'https://coralcloudresort-cd.my.salesforce.com';
    // 18-char Org ID — must match "orgId" in SCRT2 API calls (see §2.3.6)
    public static final String ORG_ID        = '00D4W000009FROd';

    // ─── MIAW / SCRT2 (§1.1) ───────────────────────────────────────
    // The SCRT2 gateway hosts the MIAW Custom Client API.
    // All conversation/message/SSE calls go through this base URL.
    // Pattern: https://{MY_DOMAIN_PREFIX}.my.salesforce-scrt.com
    public static final String SCRT2_URL =
        'https://coralcloudresort-cd.my.salesforce-scrt.com';

    // Embedded Service Deployment developer name (§3.5)
    // Must be Custom Client type AND published, or API returns error.
    public static final String ES_DEVELOPER_NAME = 'Agent_API_Verify';

    // ─── Identity / JWT (§6.1) ─────────────────────────────────────
    // Certificate used by Crypto.signWithCertificate() to sign JWTs.
    // The matching public key must be in the JWKS (see §2.3.1).
    public static final String CERTIFICATE_NAME   = 'AgentVerifyCert';

    // JWT "iss" claim — must EXACTLY match the Issuer in User
    // Verification config (see §2.3.3). Case-sensitive.
    public static final String JWT_ISSUER          = 'agent-verify-demo';

    // JWT "sub" claim — the user identity. Carried through to
    // MessagingEndUser.MessagingPlatformKey as "uid:{sub}" (see §7.2).
    public static final String JWT_SUBJECT         = 'davidvickers@tdx25.020.com';

    // JWT "aud" claim — must EXACTLY match MY_DOMAIN_URL including
    // the https:// prefix (see §2.3.4). Missing prefix = silent ANON.
    public static final String JWT_AUDIENCE        = MY_DOMAIN_URL;

    // JWT "kid" — Key ID in the header. SCRT2 searches the JWKS
    // keys[] array for this exact string (see §2.3.2).
    public static final String JWT_KID             = 'agent-verify-key-1';

    // JWT lifetime — SCRT2 rejects expired tokens (see §2.3.4).
    public static final Integer JWT_EXPIRY_SECONDS = 300; // 5 minutes

    // ─── JWKS Site (§3.3) ──────────────────────────────────────────
    // The Salesforce Site that publicly serves the JWKS endpoint.
    // SCRT2 fetches {SITE_BASE_URL}/services/apexrest/jwks during
    // token exchange (§6.2) to get the public key for signature
    // verification. Also serves the JWT signing endpoint for the
    // Python test at /services/apexrest/agent-verify/jwt (§5.2).
    public static final String SITE_BASE_URL =
        'https://coralcloudresort-cd.my.salesforce-sites.com/jwks';

    // ─── Okta (preserved for swap — see §9.6) ─────────────────────
    // To switch to Okta: change the JWKS URL in User Verification
    // settings and replace Step 1 with a real Okta token call.
    public static final String OKTA_ISSUER   = 'https://trial-8552253.okta.com/oauth2/default';
    public static final String OKTA_JWKS_URL = 'https://trial-8552253.okta.com/oauth2/default/v1/keys';

    // ─── Describe config for debug output ──────────────────────────
    public static Map<String, String> describe() {
        return new Map<String, String>{
            'My Domain'       => MY_DOMAIN_URL,
            'Org ID'          => ORG_ID,
            'SCRT2 Base URL'  => SCRT2_URL,
            'ES Deployment'   => ES_DEVELOPER_NAME,
            'Certificate'     => CERTIFICATE_NAME,
            'JWKS Endpoint'   => SITE_BASE_URL + '/services/apexrest/jwks',
            'JWT Issuer'      => JWT_ISSUER,
            'JWT Subject'     => JWT_SUBJECT
        };
    }
}
