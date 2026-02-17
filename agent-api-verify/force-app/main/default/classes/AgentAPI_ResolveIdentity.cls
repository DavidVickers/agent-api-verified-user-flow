/**
 * AgentAPI_ResolveIdentity
 * ─────────────────────────────────────────────────────────────────────
 * Public REST endpoint that resolves a verified MIAW identity to
 * Salesforce records (Contact/Account or Lead). See §8 for details.
 *
 * THIS IS ONE APPROACH — many variations exist depending on your
 * identity model. The uid in the platform key may not always be an
 * email — it could be an external IdP user ID, employee number, phone,
 * or any other identifier. See §8.2 for alternative strategies.
 *
 * THIS DEMO assumes the uid IS an email address and does a cascading
 * lookup by email: User → Contact → Lead.
 *
 * CASCADING IDENTITY LOOKUP:
 *   1. Extract email from uid via regex
 *   2. Query MessagingEndUser by platform key
 *   3. Is this a User?   → get name, continue to Contact/Account
 *   4. Is this a Contact? → use it + ensure Account exists
 *   5. Is this a Lead?   → just set LeadId + Name → DONE (early exit)
 *   6. None of the above? → create Contact + Account on demand
 *
 * THE RULE:
 *   - If Lead → LeadId + Name on MEU is sufficient
 *   - Everything else → MUST have a valid Contact + Account
 *     (existing or created on demand)
 *
 * CALLABLE TWO WAYS:
 *   REST:  GET {SITE_URL}/services/apexrest/agent-verify/resolve-identity?subject=...
 *   Apex:  Map<String,Object> result = AgentAPI_ResolveIdentity.resolveFromSubject(subject);
 *
 * All errors are returned as JSON — never swallowed (§8.4).
 *
 * Setup: Add to Site Guest User Apex Class Access (§3.3).
 *
 * NOTE: In production, this should be behind a Connected App with
 * proper authentication. Public access is for demo purposes only.
 * ─────────────────────────────────────────────────────────────────────
 */
@RestResource(urlMapping='/agent-verify/resolve-identity')
global without sharing class AgentAPI_ResolveIdentity {

    @HttpGet
    global static void resolveIdentity() {
        RestResponse res = RestContext.response;
        res.addHeader('Content-Type', 'application/json');

        String subject = RestContext.request.params.get('subject');
        if (String.isBlank(subject)) {
            res.statusCode = 400;
            res.responseBody = Blob.valueOf(JSON.serialize(
                new Map<String, String>{
                    'error' => 'Missing required parameter: subject',
                    'usage' => '?subject=v2/iamessage/AUTH/.../uid:user@example.com'
                }
            ));
            return;
        }

        Map<String, Object> result = resolveFromSubject(subject);

        // Map error/success to HTTP status
        Boolean hasError = result.containsKey('error');
        res.statusCode = hasError ? 500 : 200;
        res.responseBody = Blob.valueOf(JSON.serialize(result));
    }

    /**
     * Core resolution logic — callable from both REST and Apex.
     * Returns a Map with all resolution details + any errors.
     *
     * @param subject  The MIAW platform key (e.g. v2/iamessage/AUTH/.../uid:user@example.com)
     * @return Map containing resolved identity details, or error info
     */
    global static Map<String, Object> resolveFromSubject(String subject) {
        Map<String, Object> result = new Map<String, Object>();
        result.put('subject', subject);

        try {
            // ── 1. Extract email from uid ──────────────────────────
            String email = extractEmailFromSubject(subject);
            result.put('extractedEmail', email);

            if (String.isBlank(email)) {
                result.put('resolved', false);
                result.put('message', 'Could not extract email from subject. '
                    + 'Expected format: .../uid:email@example.com');
                return result;
            }

            // ── 2. Query MessagingEndUser by platform key ──────────
            List<MessagingEndUser> endUsers = [
                SELECT Id, Name, MessagingChannelId, MessageType,
                       MessagingPlatformKey, ContactId, AccountId,
                       LeadId, CreatedDate
                FROM MessagingEndUser
                WHERE MessagingPlatformKey = :subject
                ORDER BY CreatedDate DESC
                LIMIT 1
            ];

            if (endUsers.isEmpty()) {
                result.put('messagingEndUserFound', false);
                result.put('resolved', false);
                result.put('message', 'No MessagingEndUser found for this platform key. '
                    + 'The conversation may not have been created yet.');
                return result;
            }

            MessagingEndUser meu = endUsers[0];
            result.put('messagingEndUserFound', true);
            result.put('messagingEndUserId', meu.Id);
            result.put('currentName', meu.Name);
            result.put('currentContactId', meu.ContactId);
            result.put('currentAccountId', meu.AccountId);
            result.put('currentLeadId', meu.LeadId);

            // Already fully linked?
            Boolean alreadyLinked = (
                meu.ContactId != null && meu.AccountId != null
            ) || (
                meu.LeadId != null
            );

            if (alreadyLinked) {
                result.put('resolved', true);
                result.put('alreadyLinked', true);
                result.put('message', 'MessagingEndUser already linked');
                return result;
            }

            // ── 3. CASCADING IDENTITY LOOKUP ───────────────────────

            // 3a. Is this a User?
            String resolvedName = null;
            List<User> users = [
                SELECT Id, Name, Email
                FROM User
                WHERE (Email = :email OR Username = :email)
                  AND IsActive = true
                LIMIT 1
            ];
            if (!users.isEmpty()) {
                resolvedName = users[0].Name;
                result.put('userFound', true);
                result.put('userId', users[0].Id);
                result.put('userName', resolvedName);
            } else {
                result.put('userFound', false);
            }

            // 3b. Is this a Contact?
            Contact resolvedContact = null;
            List<Contact> contacts = [
                SELECT Id, Name, Email, AccountId
                FROM Contact
                WHERE Email = :email
                ORDER BY CreatedDate DESC
                LIMIT 1
            ];
            if (!contacts.isEmpty()) {
                resolvedContact = contacts[0];
                result.put('contactFound', true);
                result.put('existingContactId', resolvedContact.Id);
                result.put('existingContactName', resolvedContact.Name);
            } else {
                result.put('contactFound', false);
            }

            // 3c. Is this a Lead? → early exit, just need LeadId + Name
            List<Lead> leads = [
                SELECT Id, Name, Email
                FROM Lead
                WHERE Email = :email
                  AND IsConverted = false
                ORDER BY CreatedDate DESC
                LIMIT 1
            ];
            if (!leads.isEmpty() && resolvedContact == null) {
                // Lead path — no Contact exists, treat as Lead
                Lead lead = leads[0];
                meu.LeadId = lead.Id;
                update meu;

                result.put('matchType', 'Lead');
                result.put('leadId', lead.Id);
                result.put('leadName', lead.Name);
                result.put('resolved', true);
                result.put('updated', true);
                result.put('message', 'Lead found — linked MEU to Lead: ' + lead.Name
                    + '. No Contact/Account needed for Leads.');
                return result;
            }

            // ── 4. CONTACT + ACCOUNT PATH ──────────────────────────
            // If we get here, this person is NOT a Lead-only identity.
            // We MUST have a valid Contact + Account — create if needed.

            Account resolvedAccount = null;

            if (resolvedContact != null) {
                // Contact exists — ensure it has an Account
                if (resolvedContact.AccountId != null) {
                    // Contact + Account both exist — perfect
                    resolvedAccount = new Account(Id = resolvedContact.AccountId);
                    result.put('accountFound', true);
                } else {
                    // Contact exists but has no Account — create one
                    String acctName = resolvedContact.Name;
                    resolvedAccount = new Account(Name = acctName);
                    insert resolvedAccount;

                    resolvedContact.AccountId = resolvedAccount.Id;
                    update resolvedContact;

                    result.put('accountFound', false);
                    result.put('accountCreated', true);
                    result.put('createdAccountId', resolvedAccount.Id);
                    result.put('createdAccountName', acctName);
                }
            } else {
                // No Contact exists — create Account + Contact
                // Use User name if we found one, otherwise derive from email
                String nameToUse = resolvedName != null
                    ? resolvedName
                    : deriveNameFromEmail(email);

                // Create Account
                resolvedAccount = new Account(Name = nameToUse);
                insert resolvedAccount;

                result.put('accountCreated', true);
                result.put('createdAccountId', resolvedAccount.Id);
                result.put('createdAccountName', nameToUse);

                // Create Contact
                Map<String, String> nameParts = splitName(nameToUse);
                resolvedContact = new Contact(
                    FirstName = nameParts.get('firstName'),
                    LastName  = nameParts.get('lastName'),
                    Email     = email,
                    AccountId = resolvedAccount.Id
                );
                insert resolvedContact;

                result.put('contactCreated', true);
                result.put('createdContactId', resolvedContact.Id);
                result.put('createdContactName', resolvedContact.FirstName + ' ' + resolvedContact.LastName);
            }

            // ── 5. UPDATE MESSAGING END USER ───────────────────────
            meu.ContactId = resolvedContact.Id;
            meu.AccountId = resolvedAccount.Id;
            update meu;

            String matchType = (users.isEmpty()) ? 'Contact' : 'User';
            result.put('matchType', matchType);
            result.put('resolved', true);
            result.put('updated', true);
            result.put('updatedContactId', resolvedContact.Id);
            result.put('updatedAccountId', resolvedAccount.Id);
            result.put('message', 'MessagingEndUser linked — Contact: '
                + resolvedContact.Id + ', Account: ' + resolvedAccount.Id);

        } catch (Exception e) {
            result.put('error', e.getMessage());
            result.put('errorType', e.getTypeName());
            result.put('resolved', false);
        }

        return result;
    }

    // ═════════════════════════════════════════════════════════════════
    // HELPERS
    // ═════════════════════════════════════════════════════════════════

    /**
     * Extract the email/username from a MIAW platform key subject.
     *
     * Input:  v2/iamessage/AUTH/agentverifykeys/uid:davidvickers@tdx25.020.com
     * Output: davidvickers@tdx25.020.com
     */
    @TestVisible
    private static String extractEmailFromSubject(String subject) {
        if (String.isBlank(subject)) return null;

        Pattern uidPattern = Pattern.compile('uid:(.+)$');
        Matcher m = uidPattern.matcher(subject);
        if (m.find()) {
            return m.group(1).trim();
        }

        return null;
    }

    /**
     * Derive a display name from an email address when no User record exists.
     *
     * davidvickers@tdx25.020.com  → David Vickers
     * john.smith@example.com      → John Smith
     * jane_doe@company.com        → Jane Doe
     * singlename@example.com      → Singlename
     */
    @TestVisible
    private static String deriveNameFromEmail(String email) {
        if (String.isBlank(email)) return 'Unknown';

        String localPart = email.substringBefore('@');
        if (String.isBlank(localPart)) return 'Unknown';

        // Split on common separators: . _ -
        List<String> parts = localPart.split('[._\\-]');
        List<String> capitalized = new List<String>();

        for (String part : parts) {
            if (String.isNotBlank(part)) {
                capitalized.add(
                    part.substring(0, 1).toUpperCase()
                    + part.substring(1).toLowerCase()
                );
            }
        }

        return capitalized.isEmpty() ? 'Unknown' : String.join(capitalized, ' ');
    }

    /**
     * Split a full name into firstName / lastName.
     * If only one word, it becomes the lastName (SF requires LastName).
     */
    @TestVisible
    private static Map<String, String> splitName(String fullName) {
        Map<String, String> result = new Map<String, String>();

        if (String.isBlank(fullName)) {
            result.put('firstName', null);
            result.put('lastName', 'Unknown');
            return result;
        }

        List<String> parts = fullName.trim().split('\\s+');
        if (parts.size() == 1) {
            result.put('firstName', null);
            result.put('lastName', parts[0]);
        } else {
            result.put('firstName', parts[0]);
            // Everything after the first word is the last name
            parts.remove(0);
            result.put('lastName', String.join(parts, ' '));
        }

        return result;
    }
}
