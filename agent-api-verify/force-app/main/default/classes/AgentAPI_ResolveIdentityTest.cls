@IsTest
private class AgentAPI_ResolveIdentityTest {

    // ── extractEmailFromSubject ────────────────────────────────

    @IsTest
    static void testExtractEmailAuth() {
        String email = AgentAPI_ResolveIdentity.extractEmailFromSubject(
            'v2/iamessage/AUTH/agentverifykeys/uid:davidvickers@tdx25.020.com'
        );
        System.assertEquals('davidvickers@tdx25.020.com', email);
    }

    @IsTest
    static void testExtractEmailAnon() {
        String email = AgentAPI_ResolveIdentity.extractEmailFromSubject(
            'v2/iamessage/ANON/somekeyset/uid:user@example.com'
        );
        System.assertEquals('user@example.com', email);
    }

    @IsTest
    static void testExtractEmailNoUid() {
        String email = AgentAPI_ResolveIdentity.extractEmailFromSubject(
            'v2/iamessage/AUTH/agentverifykeys/no-uid-here'
        );
        System.assertEquals(null, email);
    }

    @IsTest
    static void testExtractEmailBlank() {
        System.assertEquals(null, AgentAPI_ResolveIdentity.extractEmailFromSubject(null));
        System.assertEquals(null, AgentAPI_ResolveIdentity.extractEmailFromSubject(''));
    }

    // ── deriveNameFromEmail ────────────────────────────────────

    @IsTest
    static void testDeriveNameDotSeparator() {
        System.assertEquals('John Smith',
            AgentAPI_ResolveIdentity.deriveNameFromEmail('john.smith@example.com'));
    }

    @IsTest
    static void testDeriveNameUnderscoreSeparator() {
        System.assertEquals('Jane Doe',
            AgentAPI_ResolveIdentity.deriveNameFromEmail('jane_doe@company.com'));
    }

    @IsTest
    static void testDeriveNameNoSeparator() {
        System.assertEquals('Davidvickers',
            AgentAPI_ResolveIdentity.deriveNameFromEmail('davidvickers@tdx25.020.com'));
    }

    @IsTest
    static void testDeriveNameBlank() {
        System.assertEquals('Unknown',
            AgentAPI_ResolveIdentity.deriveNameFromEmail(null));
    }

    // ── splitName ──────────────────────────────────────────────

    @IsTest
    static void testSplitNameTwoParts() {
        Map<String, String> parts = AgentAPI_ResolveIdentity.splitName('David Vickers');
        System.assertEquals('David', parts.get('firstName'));
        System.assertEquals('Vickers', parts.get('lastName'));
    }

    @IsTest
    static void testSplitNameSinglePart() {
        Map<String, String> parts = AgentAPI_ResolveIdentity.splitName('Davidvickers');
        System.assertEquals(null, parts.get('firstName'));
        System.assertEquals('Davidvickers', parts.get('lastName'));
    }

    @IsTest
    static void testSplitNameThreeParts() {
        Map<String, String> parts = AgentAPI_ResolveIdentity.splitName('Mary Jane Watson');
        System.assertEquals('Mary', parts.get('firstName'));
        System.assertEquals('Jane Watson', parts.get('lastName'));
    }

    @IsTest
    static void testSplitNameBlank() {
        Map<String, String> parts = AgentAPI_ResolveIdentity.splitName(null);
        System.assertEquals(null, parts.get('firstName'));
        System.assertEquals('Unknown', parts.get('lastName'));
    }

    // ── REST endpoint: missing param ───────────────────────────

    @IsTest
    static void testMissingSubjectParam() {
        RestRequest req = new RestRequest();
        req.requestURI = '/services/apexrest/agent-verify/resolve-identity';
        req.httpMethod = 'GET';
        // params is final — use addParameter instead
        RestResponse res = new RestResponse();
        RestContext.request = req;
        RestContext.response = res;

        Test.startTest();
        AgentAPI_ResolveIdentity.resolveIdentity();
        Test.stopTest();

        System.assertEquals(400, res.statusCode);
        String body = res.responseBody.toString();
        System.assert(body.contains('Missing required parameter'));
    }

    // ── REST endpoint: no MessagingEndUser ─────────────────────

    @IsTest
    static void testNoMessagingEndUser() {
        RestRequest req = new RestRequest();
        req.requestURI = '/services/apexrest/agent-verify/resolve-identity';
        req.httpMethod = 'GET';
        req.addParameter('subject', 'v2/iamessage/AUTH/keys/uid:nobody@example.com');

        RestResponse res = new RestResponse();
        RestContext.request = req;
        RestContext.response = res;

        Test.startTest();
        AgentAPI_ResolveIdentity.resolveIdentity();
        Test.stopTest();

        System.assertEquals(200, res.statusCode);
        String body = res.responseBody.toString();
        System.assert(body.contains('"messagingEndUserFound":false'));
    }

    // ── REST endpoint: bad subject format ──────────────────────

    @IsTest
    static void testBadSubjectFormat() {
        RestRequest req = new RestRequest();
        req.requestURI = '/services/apexrest/agent-verify/resolve-identity';
        req.httpMethod = 'GET';
        req.addParameter('subject', 'some-random-string-no-uid');

        RestResponse res = new RestResponse();
        RestContext.request = req;
        RestContext.response = res;

        Test.startTest();
        AgentAPI_ResolveIdentity.resolveIdentity();
        Test.stopTest();

        System.assertEquals(200, res.statusCode);
        String body = res.responseBody.toString();
        System.assert(body.contains('Could not extract email'));
    }
}
