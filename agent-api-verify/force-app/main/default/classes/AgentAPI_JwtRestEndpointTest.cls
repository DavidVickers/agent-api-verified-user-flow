@IsTest
private class AgentAPI_JwtRestEndpointTest {

    @IsTest
    static void testGetSignedJwt() {
        // Set up REST context
        RestRequest req = new RestRequest();
        req.requestURI = '/services/apexrest/agent-verify/jwt';
        req.httpMethod = 'GET';
        RestContext.request = req;
        RestContext.response = new RestResponse();

        Test.startTest();
        AgentAPI_JwtRestEndpoint.getSignedJwt();
        Test.stopTest();

        // The call may fail in test context without a real certificate,
        // but the endpoint should not throw — it returns a 500 with error JSON
        RestResponse res = RestContext.response;
        Assert.isNotNull(res.responseBody);

        String body = res.responseBody.toString();
        Map<String, Object> result = (Map<String, Object>)
            JSON.deserializeUntyped(body);

        if (res.statusCode == 200) {
            Assert.isTrue(result.containsKey('jwt'));
            Assert.isTrue(result.containsKey('scrt2Url'));
            Assert.isTrue(result.containsKey('orgId'));
        } else {
            // Certificate not available in test context — error is expected
            Assert.isTrue(result.containsKey('error'));
        }
    }

    @IsTest
    static void testGetSignedJwtWithCustomSubject() {
        RestRequest req = new RestRequest();
        req.requestURI = '/services/apexrest/agent-verify/jwt';
        req.httpMethod = 'GET';
        req.params.put('sub', 'custom@test.com');
        RestContext.request = req;
        RestContext.response = new RestResponse();

        Test.startTest();
        AgentAPI_JwtRestEndpoint.getSignedJwt();
        Test.stopTest();

        RestResponse res = RestContext.response;
        Assert.isNotNull(res.responseBody);
    }
}
