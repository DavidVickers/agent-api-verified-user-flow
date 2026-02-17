@IsTest
private class AgentAPI_Step4_SendMessageTest {

    private class MockSendMessageSuccess implements HttpCalloutMock {
        public HttpResponse respond(HttpRequest req) {
            HttpResponse res = new HttpResponse();
            res.setHeader('Content-Type', 'application/json');
            res.setStatusCode(200);
            res.setBody('{"status":"accepted"}');
            return res;
        }
    }

    private class MockSendMessageFailure implements HttpCalloutMock {
        public HttpResponse respond(HttpRequest req) {
            HttpResponse res = new HttpResponse();
            res.setHeader('Content-Type', 'application/json');
            res.setStatusCode(404);
            res.setBody('{"message":"Conversation not found"}');
            return res;
        }
    }

    @IsTest
    static void testSuccessfulMessageSend() {
        Test.setMock(HttpCalloutMock.class, new MockSendMessageSuccess());

        Test.startTest();
        Map<String, Object> response = AgentAPI_Step4_SendMessage.execute(
            'mock-miaw-token', 'mock-conv-id', 'Hello agent'
        );
        Test.stopTest();

        Assert.isNotNull(response);
    }

    @IsTest
    static void testFailedMessageSend() {
        Test.setMock(HttpCalloutMock.class, new MockSendMessageFailure());

        Test.startTest();
        try {
            AgentAPI_Step4_SendMessage.execute(
                'mock-miaw-token', 'mock-conv-id', 'Hello agent'
            );
            Assert.fail('Should have thrown AgentAPI_Exception');
        } catch (AgentAPI_Exception e) {
            Assert.isTrue(e.getMessage().contains('Step 4 failed'));
        }
        Test.stopTest();
    }
}
