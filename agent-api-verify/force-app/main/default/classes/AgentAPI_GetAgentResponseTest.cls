@IsTest
private class AgentAPI_GetAgentResponseTest {

    private class MockEntriesWithAgent implements HttpCalloutMock {
        public HttpResponse respond(HttpRequest req) {
            HttpResponse res = new HttpResponse();
            res.setHeader('Content-Type', 'application/json');

            if (req.getEndpoint().contains('/entries')) {
                res.setStatusCode(200);
                res.setBody(
                    '{"conversationEntries":[' +
                    '{"entryType":"Message","entryPayload":"{\\\"abstractMessage\\\":{\\\"staticContent\\\":{\\\"text\\\":\\\"I can help you with reservations and activities!\\\"}}}","actorType":"chatbot","actorName":"CoralBot"}' +
                    ']}'
                );
            } else {
                // JWKS delay endpoint
                res.setStatusCode(200);
                res.setBody('{}');
            }
            return res;
        }
    }

    private class MockEntriesNoAgent implements HttpCalloutMock {
        public HttpResponse respond(HttpRequest req) {
            HttpResponse res = new HttpResponse();
            res.setHeader('Content-Type', 'application/json');
            res.setStatusCode(200);
            // Only user message, no agent response yet
            res.setBody(
                '{"conversationEntries":[' +
                '{"entryType":"Message","id":"abc-123","clientTimestamp":1234}' +
                ']}'
            );
            return res;
        }
    }

    @IsTest
    static void testEntriesWithAgentResponse() {
        Test.setMock(HttpCalloutMock.class, new MockEntriesWithAgent());

        Test.startTest();
        AgentAPI_GetAgentResponse.execute('mock-token', 'mock-conv-id');
        Test.stopTest();
        // Should find and display the agent's response
    }

    @IsTest
    static void testEntriesNoAgentResponse() {
        Test.setMock(HttpCalloutMock.class, new MockEntriesNoAgent());

        Test.startTest();
        AgentAPI_GetAgentResponse.execute('mock-token', 'mock-conv-id');
        Test.stopTest();
        // Should fall through to SOQL after 3 polls
    }

    @IsTest
    static void testCheckLatest() {
        Test.startTest();
        AgentAPI_GetAgentResponse.checkLatest();
        Test.stopTest();
        // SOQL-based — no callout needed
    }
}
