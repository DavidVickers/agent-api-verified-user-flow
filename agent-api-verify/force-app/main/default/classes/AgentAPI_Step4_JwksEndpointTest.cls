@IsTest
private class AgentAPI_Step4_JwksEndpointTest {

    @IsTest
    static void testJwksEndpointReturnsJson() {
        RestRequest req = new RestRequest();
        req.requestURI = '/services/apexrest/jwks';
        req.httpMethod = 'GET';
        RestContext.request = req;
        RestContext.response = new RestResponse();

        Test.startTest();
        AgentAPI_Step4_JwksEndpoint.getKeys();
        Test.stopTest();

        RestResponse res = RestContext.response;
        String body = res.responseBody.toString();

        // Should be valid JSON with a keys array
        Map<String, Object> jwks = (Map<String, Object>)
            JSON.deserializeUntyped(body);
        Assert.isTrue(jwks.containsKey('keys'), 'JWKS must contain keys array');
        Assert.areEqual('application/json',
            res.headers.get('Content-Type'));
    }

    @IsTest
    static void testDescribeEndpoint() {
        // Should not throw — just writes debug output
        Test.startTest();
        AgentAPI_Step4_JwksEndpoint.describeEndpoint();
        Test.stopTest();
    }
}
