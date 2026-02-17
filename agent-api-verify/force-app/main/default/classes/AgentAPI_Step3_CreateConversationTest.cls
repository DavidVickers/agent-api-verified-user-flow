@IsTest
private class AgentAPI_Step3_CreateConversationTest {

    private class MockConversationSuccess implements HttpCalloutMock {
        public HttpResponse respond(HttpRequest req) {
            HttpResponse res = new HttpResponse();
            res.setHeader('Content-Type', 'application/json');
            res.setStatusCode(201);
            res.setBody('{}');
            return res;
        }
    }

    private class MockConversationFailure implements HttpCalloutMock {
        public HttpResponse respond(HttpRequest req) {
            HttpResponse res = new HttpResponse();
            res.setHeader('Content-Type', 'application/json');
            res.setStatusCode(403);
            res.setBody('{"message":"Deployment not published"}');
            return res;
        }
    }

    @IsTest
    static void testSuccessfulConversationCreation() {
        Test.setMock(HttpCalloutMock.class, new MockConversationSuccess());

        Test.startTest();
        String conversationId = AgentAPI_Step3_CreateConversation.execute('mock-miaw-token');
        Test.stopTest();

        Assert.isNotNull(conversationId);
        Assert.areEqual(36, conversationId.length(), 'Should be UUID format');
    }

    @IsTest
    static void testFailedConversationCreation() {
        Test.setMock(HttpCalloutMock.class, new MockConversationFailure());

        Test.startTest();
        try {
            AgentAPI_Step3_CreateConversation.execute('mock-miaw-token');
            Assert.fail('Should have thrown AgentAPI_Exception');
        } catch (AgentAPI_Exception e) {
            Assert.isTrue(e.getMessage().contains('Step 3 failed'));
        }
        Test.stopTest();
    }
}
