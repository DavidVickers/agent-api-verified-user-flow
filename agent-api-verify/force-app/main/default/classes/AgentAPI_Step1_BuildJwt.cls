/**
 * AgentAPI_Step1_BuildJwt
 * ─────────────────────────────────────────────────────────────────────
 * STEP 1 OF 5 — Build & Sign the Identity JWT
 *
 * Constructs a JWT that asserts the end user's identity, then signs it
 * with a Salesforce-managed certificate. This JWT is the input to
 * Step 2 (§6.2) where SCRT2 validates it and returns an AUTH token.
 *
 * The JWT has three Base64URL-encoded parts: header.claims.signature
 * See SETUP_GUIDE.md §6.1 for the complete field-by-field breakdown.
 *
 * WHY self-signed? The private key never leaves Salesforce. SCRT2
 * fetches the public key from our JWKS endpoint (§3.3) to verify.
 * This is the cryptographic link described in §2.3.1.
 * ─────────────────────────────────────────────────────────────────────
 */
public with sharing class AgentAPI_Step1_BuildJwt {

    public static String execute() {
        AgentAPI_Logger.step(1, 'Build Identity JWT');

        // ── PART 1: JWT HEADER ──────────────────────────────────────
        // Tells SCRT2 which algorithm (RS256) and key (kid) to use.
        // The kid must match a key in the JWKS — see §2.3.2.
        String headerJson = AgentAPI_JwtUtils.buildJwtHeader(
            AgentAPI_Config.JWT_KID
        );
        String headerB64 = AgentAPI_JwtUtils.base64UrlEncode(
            Blob.valueOf(headerJson)
        );

        // ── PART 2: JWT CLAIMS ──────────────────────────────────────
        // The identity assertions. Each claim is validated by SCRT2:
        //   iss → must match User Verification config (§2.3.3)
        //   sub → the user's identity, carried as uid:{sub} (§7.2)
        //   aud → must match My Domain URL exactly (§2.3.4)
        //   exp → SCRT2 rejects expired JWTs
        String claimsJson = AgentAPI_JwtUtils.buildJwtClaims(
            AgentAPI_Config.JWT_ISSUER,
            AgentAPI_Config.JWT_SUBJECT,
            AgentAPI_Config.JWT_AUDIENCE,
            AgentAPI_Config.JWT_EXPIRY_SECONDS
        );
        String claimsB64 = AgentAPI_JwtUtils.base64UrlEncode(
            Blob.valueOf(claimsJson)
        );

        // ── PART 3: SIGNATURE ───────────────────────────────────────
        // Sign "header.claims" with the certificate's private key.
        // Crypto.signWithCertificate reads the private key from
        // Setup > Certificate and Key Management — never exposed.
        // The JWKS endpoint serves the matching PUBLIC key so
        // SCRT2 can verify this signature (§2.3.1).
        String signingInput = headerB64 + '.' + claimsB64;
        Blob signature = Crypto.signWithCertificate(
            'RSA-SHA256',
            Blob.valueOf(signingInput),
            AgentAPI_Config.CERTIFICATE_NAME
        );
        String signatureB64 = AgentAPI_JwtUtils.base64UrlEncode(signature);

        // ASSEMBLE: header.claims.signature
        String jwt = signingInput + '.' + signatureB64;

        // ── Debug output ────────────────────────────────────────────
        AgentAPI_Logger.json('JWT Header (decoded)', headerJson);
        AgentAPI_Logger.json('JWT Claims (decoded)', claimsJson);
        AgentAPI_Logger.detail('Signing Algorithm', 'RSA-SHA256');
        AgentAPI_Logger.detail('Certificate Used', AgentAPI_Config.CERTIFICATE_NAME);
        AgentAPI_Logger.detail('Complete JWT', jwt);
        AgentAPI_Logger.success(
            'Identity JWT built and signed (' + jwt.length() + ' chars)'
        );
        AgentAPI_Logger.note(
            'Next: Step 2 exchanges this JWT for a MIAW token. ' +
            'SCRT2 will validate it against the JWKS at ' +
            AgentAPI_Config.SITE_BASE_URL + '/services/apexrest/jwks'
        );

        return jwt;
    }
}
