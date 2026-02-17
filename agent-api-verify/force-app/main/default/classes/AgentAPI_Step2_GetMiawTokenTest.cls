@IsTest
private class AgentAPI_Step2_GetMiawTokenTest {

    private class MockMiawTokenSuccess implements HttpCalloutMock {
        public HttpResponse respond(HttpRequest req) {
            HttpResponse res = new HttpResponse();
            res.setHeader('Content-Type', 'application/json');
            res.setStatusCode(200);
            // Matches the actual SCRT2 response structure with endUser
            res.setBody(
                '{"accessToken":"mock-miaw-token-abc123",' +
                '"lastEventId":"123",' +
                '"context":{' +
                '"configuration":{"embeddedServiceConfig":{"name":"Agent_API_Verify","deploymentType":"API"}},' +
                '"endUser":{' +
                '"appType":"iamessage",' +
                '"role":"EndUser",' +
                '"subject":"v2/iamessage/AUTH/agentverifykeys/uid:testuser@test.com"' +
                '}}}'
            );
            return res;
        }
    }

    private class MockMiawTokenAnonymous implements HttpCalloutMock {
        public HttpResponse respond(HttpRequest req) {
            HttpResponse res = new HttpResponse();
            res.setHeader('Content-Type', 'application/json');
            res.setStatusCode(200);
            res.setBody(
                '{"accessToken":"mock-anon-token",' +
                '"context":{"endUser":{' +
                '"appType":"iamessage",' +
                '"role":"EndUser",' +
                '"subject":"v2/iamessage/ANON/someid"' +
                '}}}'
            );
            return res;
        }
    }

    private class MockMiawTokenFailure implements HttpCalloutMock {
        public HttpResponse respond(HttpRequest req) {
            HttpResponse res = new HttpResponse();
            res.setHeader('Content-Type', 'application/json');
            res.setStatusCode(400);
            res.setBody('{"message":"Invalid JWT","errorCode":"INVALID_JWT"}');
            return res;
        }
    }

    @IsTest
    static void testSuccessfulVerifiedTokenExchange() {
        Test.setMock(HttpCalloutMock.class, new MockMiawTokenSuccess());

        Test.startTest();
        String token = AgentAPI_Step2_GetMiawToken.execute('mock-jwt');
        Test.stopTest();

        Assert.areEqual('mock-miaw-token-abc123', token);
    }

    @IsTest
    static void testAnonymousTokenExchange() {
        // Should still return a token but log ANON warning
        Test.setMock(HttpCalloutMock.class, new MockMiawTokenAnonymous());

        Test.startTest();
        String token = AgentAPI_Step2_GetMiawToken.execute('mock-jwt');
        Test.stopTest();

        Assert.areEqual('mock-anon-token', token);
    }

    @IsTest
    static void testFailedTokenExchange() {
        Test.setMock(HttpCalloutMock.class, new MockMiawTokenFailure());

        Test.startTest();
        try {
            AgentAPI_Step2_GetMiawToken.execute('bad-jwt');
            Assert.fail('Should have thrown AgentAPI_Exception');
        } catch (AgentAPI_Exception e) {
            Assert.isTrue(e.getMessage().contains('Step 2 failed'));
        }
        Test.stopTest();
    }
}
