@IsTest
private class AgentAPI_Step1_BuildJwtTest {

    @IsTest
    static void testBase64UrlEncode() {
        String result = AgentAPI_JwtUtils.base64UrlEncode(Blob.valueOf('test'));
        Assert.isFalse(result.contains('+'), 'No + in Base64URL');
        Assert.isFalse(result.contains('/'), 'No / in Base64URL');
        Assert.isFalse(result.contains('='), 'No padding in Base64URL');
    }

    @IsTest
    static void testJwtHeader() {
        String header = AgentAPI_JwtUtils.buildJwtHeader('test-kid');
        Map<String, Object> parsed = (Map<String, Object>)
            JSON.deserializeUntyped(header);
        Assert.areEqual('RS256', parsed.get('alg'));
        Assert.areEqual('JWT', parsed.get('typ'));
        Assert.areEqual('test-kid', parsed.get('kid'));
    }

    @IsTest
    static void testJwtClaims() {
        String claims = AgentAPI_JwtUtils.buildJwtClaims(
            'test-issuer', 'test-subject', 'test-audience', 300
        );
        Map<String, Object> parsed = (Map<String, Object>)
            JSON.deserializeUntyped(claims);
        Assert.areEqual('test-issuer', parsed.get('iss'));
        Assert.areEqual('test-subject', parsed.get('sub'));
        Assert.areEqual('test-audience', parsed.get('aud'));
        Assert.isNotNull(parsed.get('iat'));
        Assert.isNotNull(parsed.get('exp'));
        Long iat = ((Decimal) parsed.get('iat')).longValue();
        Long exp = ((Decimal) parsed.get('exp')).longValue();
        Assert.areEqual(300, exp - iat);
    }

    @IsTest
    static void testGenerateUUID() {
        String uuid = AgentAPI_JwtUtils.generateUUID();
        Assert.areEqual(36, uuid.length(), 'UUID should be 36 chars');
        Assert.isTrue(uuid.contains('-'), 'UUID should contain hyphens');
        List<String> parts = uuid.split('-');
        Assert.areEqual(5, parts.size(), 'UUID should have 5 parts');
    }

    @IsTest
    static void testLoadJwksMissing() {
        String jwks = AgentAPI_JwtUtils.loadJwksFromStaticResource();
        Assert.isTrue(jwks.contains('keys'), 'Should contain keys array');
    }
}
