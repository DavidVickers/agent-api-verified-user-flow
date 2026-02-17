/**
 * AgentAPI_JwtUtils
 * ─────────────────────────────────────────────────────────────────────
 * Shared JWT/JWKS utilities used by multiple flow classes.
 *
 * See SETUP_GUIDE.md §6.1 for the JWT structure and why each part
 * (header, claims, signature) matters for SCRT2 verification.
 * ─────────────────────────────────────────────────────────────────────
 */
public with sharing class AgentAPI_JwtUtils {

    /**
     * Base64URL encode without padding.
     *
     * JWTs require Base64URL encoding (RFC 7515), NOT standard Base64.
     * Difference: + becomes -, / becomes _, trailing = padding removed.
     * If you use standard Base64, the JWT will be malformed and SCRT2
     * will silently fall back to ANON (see §2.4).
     */
    public static String base64UrlEncode(Blob input) {
        String base64 = EncodingUtil.base64Encode(input);
        return base64
            .replace('+', '-')
            .replace('/', '_')
            .replaceAll('=+$', '');
    }

    /**
     * Build a JWT header JSON string.
     *
     * The header tells SCRT2 which algorithm and key to use:
     *   alg = RS256 (required by SCRT2)
     *   typ = JWT
     *   kid = Key ID — SCRT2 searches JWKS keys[] for this (see §2.3.2)
     */
    public static String buildJwtHeader(String kid) {
        JSONGenerator gen = JSON.createGenerator(false);
        gen.writeStartObject();
        gen.writeStringField('alg', 'RS256');
        gen.writeStringField('typ', 'JWT');
        gen.writeStringField('kid', kid);
        gen.writeEndObject();
        return gen.getAsString();
    }

    /**
     * Build JWT claims JSON string.
     *
     * Each claim is validated by SCRT2 during token exchange (§6.2):
     *   iss = must match User Verification config Issuer (§2.3.3)
     *   sub = the user identity — carried through as uid:{sub}
     *   aud = must match org My Domain URL including https:// (§2.3.4)
     *   iat = issued-at Unix timestamp
     *   exp = expiry Unix timestamp — SCRT2 rejects expired JWTs
     */
    public static String buildJwtClaims(String issuer, String subject,
                                         String audience, Integer expirySeconds) {
        Long now = Datetime.now().getTime() / 1000;
        JSONGenerator gen = JSON.createGenerator(false);
        gen.writeStartObject();
        gen.writeStringField('iss', issuer);
        gen.writeStringField('sub', subject);
        gen.writeStringField('aud', audience);
        gen.writeNumberField('iat', now);
        gen.writeNumberField('exp', now + expirySeconds);
        gen.writeEndObject();
        return gen.getAsString();
    }

    /**
     * Load JWKS JSON from a Static Resource.
     *
     * The Static Resource contains the pre-computed JWKS with the
     * public key extracted from the signing certificate (§3.2).
     * This is what the JWKS endpoint (§3.3) serves to SCRT2.
     * The key pair relationship is described in §2.3.1.
     */
    public static String loadJwksFromStaticResource() {
        List<StaticResource> resources = [
            SELECT Body FROM StaticResource
            WHERE Name = 'AgentVerifyJWKS' LIMIT 1
        ];
        if (resources.isEmpty()) {
            return '{"keys":[],"error":"Static Resource AgentVerifyJWKS not found. Upload the JWKS JSON."}';
        }
        return resources[0].Body.toString();
    }

    /**
     * Generate a compliant UUID v4 string.
     *
     * Format: xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
     * where 4 = version and y = variant (must be 8, 9, a, or b).
     *
     * SCRT2 validates UUIDs strictly — if the variant nibble is not
     * 8/9/a/b, the conversation creation call (§6.3) rejects with:
     * "Specify the conversationId in UUID format."
     * See §10 (Common Mistakes) for this gotcha.
     */
    public static String generateUUID() {
        Blob b = Crypto.generateAesKey(128);
        String hex = EncodingUtil.convertToHex(b);
        // Map any hex nibble to a valid variant nibble (8, 9, a, or b)
        Map<String, String> toVariant = new Map<String, String>{
            '0'=>'8', '1'=>'9', '2'=>'a', '3'=>'b',
            '4'=>'8', '5'=>'9', '6'=>'a', '7'=>'b',
            '8'=>'8', '9'=>'9', 'a'=>'a', 'b'=>'b',
            'c'=>'8', 'd'=>'9', 'e'=>'a', 'f'=>'b'
        };
        return hex.substring(0, 8) + '-'
             + hex.substring(8, 12) + '-4'
             + hex.substring(13, 16) + '-'
             + toVariant.get(hex.substring(16, 17))
             + hex.substring(17, 20) + '-'
             + hex.substring(20, 32);
    }
}
