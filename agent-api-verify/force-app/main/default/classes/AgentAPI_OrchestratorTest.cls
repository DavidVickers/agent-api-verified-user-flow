@IsTest
private class AgentAPI_OrchestratorTest {

    /**
     * Multi-request mock that returns different responses based on SCRT2 endpoint.
     * Routes: access-token → conversation → message → close
     */
    private class MiawMultiMock implements HttpCalloutMock {
        public HttpResponse respond(HttpRequest req) {
            HttpResponse res = new HttpResponse();
            res.setHeader('Content-Type', 'application/json');

            if (req.getEndpoint().contains('/access-token')) {
                // Step 2: MIAW token exchange
                res.setStatusCode(200);
                res.setBody(
                    '{"accessToken":"mock-miaw-token-xyz",' +
                    '"context":{"authMode":"Auth",' +
                    '"verificationData":{"channelAddressIdentifier":"test",' +
                    '"subject":"uid:testuser@test.com"}}}'
                );
            }
            else if (req.getEndpoint().contains('/conversation') &&
                     !req.getEndpoint().contains('/message') &&
                     !req.getEndpoint().contains('/close')) {
                // Step 3: Create conversation
                res.setStatusCode(201);
                res.setBody('{}');
            }
            else if (req.getEndpoint().contains('/message')) {
                // Step 4: Send message
                res.setStatusCode(200);
                res.setBody('{"status":"accepted"}');
            }
            else if (req.getEndpoint().contains('/entries')) {
                // GetAgentResponse: conversation entries polling
                res.setStatusCode(200);
                res.setBody('{"conversationEntries":[]}');
            }
            else if (req.getEndpoint().contains('/jwks')) {
                // GetAgentResponse: delay callout to JWKS endpoint
                res.setStatusCode(200);
                res.setBody('{"keys":[]}');
            }
            else {
                res.setStatusCode(404);
                res.setBody('{"error":"Unknown endpoint"}');
            }
            return res;
        }
    }

    @IsTest
    static void testExecuteStepOneOnly() {
        // Step 1 builds a JWT — no callouts needed but requires certificate.
        // In test context without cert, test the executeStep routing.
        Test.startTest();
        AgentAPI_Orchestrator.showJwksInfo(); // No callout — just reads static resource
        Test.stopTest();
    }

    @IsTest
    static void testExecuteStepInvalid() {
        Test.startTest();
        AgentAPI_Orchestrator.executeStep(99);
        Test.stopTest();
        // Should not throw — just logs error
    }

    @IsTest
    static void testExecuteStepDependencyNotes() {
        // Steps 2-5 should log notes about dependencies
        Test.startTest();
        AgentAPI_Orchestrator.executeStep(2);
        AgentAPI_Orchestrator.executeStep(3);
        AgentAPI_Orchestrator.executeStep(4);
        AgentAPI_Orchestrator.executeStep(5);
        Test.stopTest();
    }

    @IsTest
    static void testLoggerMethods() {
        Test.startTest();
        AgentAPI_Logger.banner('Test Banner');
        AgentAPI_Logger.step(1, 'Test Step');
        AgentAPI_Logger.detail('key', 'value');
        AgentAPI_Logger.json('test', '{"a":"b"}');
        AgentAPI_Logger.json('bad', 'not json');
        AgentAPI_Logger.success('worked');
        AgentAPI_Logger.error('broke');
        AgentAPI_Logger.note('FYI');
        AgentAPI_Logger.httpRequest('GET', 'https://test.com', 'body');
        AgentAPI_Logger.httpResponse(200, '{"ok":true}');
        AgentAPI_Logger.config(new Map<String, String>{'k' => 'v'});
        AgentAPI_Logger.separator();
        Test.stopTest();
    }

    @IsTest
    static void testConfigDescribe() {
        Map<String, String> config = AgentAPI_Config.describe();
        Assert.isFalse(config.isEmpty());
        Assert.isTrue(config.containsKey('My Domain'));
        Assert.isTrue(config.containsKey('SCRT2 Base URL'));
        Assert.isTrue(config.containsKey('ES Deployment'));
    }
}
