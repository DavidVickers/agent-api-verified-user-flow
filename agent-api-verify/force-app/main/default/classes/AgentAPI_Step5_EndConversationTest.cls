@IsTest
private class AgentAPI_Step5_EndConversationTest {

    @IsTest
    static void testEndConversationNoRecords() {
        // Without any MessagingEndUser records, should log note (not throw)
        Test.startTest();
        AgentAPI_Step5_EndConversation.execute('mock-token', 'mock-conv-id');
        Test.stopTest();
        // Should not throw — just logs that no records found
    }
}
