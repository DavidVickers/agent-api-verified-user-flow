#!/usr/bin/env python3
"""
Agent API Verified User Flow — End-to-End Python Test
═══════════════════════════════════════════════════════════════════════

This script runs the complete MIAW verified-user flow with full SSE
(Server-Sent Events) support — something Apex cannot do.

See SETUP_GUIDE.md §5.2 for documentation on this test.

NO OAUTH NEEDED — The JWT signing endpoint is exposed on the public
Salesforce Site (§3.3), so Python can get a signed JWT without
authenticating.

THE FLOW (order matters! — see §6.0–§6.6 for each API call):
  1. Call public Site endpoint → signed identity JWT     (§6.1)
  2. Exchange JWT with SCRT2 → MIAW access token         (§6.2)
  3. Create conversation                                 (§6.3)
  4. Subscribe to SSE stream — MUST be before sending!   (§6.4)
  5. Send message (with routingAttributes + language)     (§6.5)
  6. Listen for agent response via SSE + polling          (§7.3)

CRITICAL: SSE must be established BEFORE the first message is sent.
Agent responses are delivered exclusively via SSE (§6.4) — if you're
not listening when the agent responds, the response is lost.

AUTH vs ANON: SCRT2 returns 200 OK either way (§2.4). The ONLY way to
know verification succeeded is to check context.endUser.subject for
AUTH vs ANON in the Step 2 response (§7.1).

Reference: github.com/Salesforce-Async-Messaging/messaging-web-api-sample-app

USAGE:
  pip install -r requirements.txt
  python agent_api_test.py

  # Custom message:
  python agent_api_test.py "What are my open cases?"

  # Custom subject:
  python agent_api_test.py --sub user@example.com "Hello"
═══════════════════════════════════════════════════════════════════════
"""

import json
import os
import sys
import threading
import time
import uuid
from datetime import datetime

import requests
from dotenv import load_dotenv

# ── Load environment ─────────────────────────────────────────────────
load_dotenv()

# The JWT endpoint is on the public Site — no OAuth needed
SITE_BASE_URL     = os.getenv("SITE_BASE_URL", "https://coralcloudresort-cd.my.salesforce-sites.com/jwks")
SF_MY_DOMAIN      = os.getenv("SF_MY_DOMAIN", "https://coralcloudresort-cd.my.salesforce.com")
SF_ORG_ID         = os.getenv("SF_ORG_ID", "00D4W000009FROd")
SCRT2_URL         = os.getenv("SCRT2_URL", "https://coralcloudresort-cd.my.salesforce-scrt.com")
ES_DEVELOPER_NAME = os.getenv("ES_DEVELOPER_NAME", "Agent_API_Verify")
JWT_SUBJECT       = os.getenv("JWT_SUBJECT", "")
TEST_MESSAGE      = os.getenv("TEST_MESSAGE", "Hello, what can you help me with?")

# ── Globals for SSE thread ───────────────────────────────────────────
sse_events = []
sse_running = False
sse_connected = False
sse_thread = None


# ═════════════════════════════════════════════════════════════════════
# DISPLAY HELPERS
# ═════════════════════════════════════════════════════════════════════

def banner(title):
    line = "=" * 64
    print(f"\n{line}")
    print(f"  {title}")
    print(f"{line}")

def step(num, title):
    line = "-" * 64
    print(f"\n{line}")
    print(f"  STEP {num}: {title}")
    print(f"{line}")

def detail(label, value):
    val_str = str(value)
    if len(val_str) > 200:
        val_str = val_str[:200] + "..."
    print(f"  [{label}] {val_str}")

def success(msg):
    print(f"  >> SUCCESS: {msg}")

def error(msg):
    print(f"  ** ERROR: {msg}")

def note(msg):
    print(f"  (!) {msg}")

def http_req(method, url, body=None):
    print(f"  --> {method} {url}")
    if body:
        try:
            pretty = json.dumps(json.loads(body) if isinstance(body, str) else body, indent=2)
            lines = pretty.split("\n")
            if len(lines) > 10:
                for line in lines[:10]:
                    print(f"      {line}")
                print(f"      ... ({len(lines)} lines total)")
            else:
                for line in lines:
                    print(f"      {line}")
        except (json.JSONDecodeError, TypeError):
            print(f"      {str(body)[:200]}")

def http_res(status, body=None):
    print(f"  <-- {status}")
    if body:
        try:
            pretty = json.dumps(json.loads(body) if isinstance(body, str) else body, indent=2)
            lines = pretty.split("\n")
            if len(lines) > 15:
                for line in lines[:15]:
                    print(f"      {line}")
                print(f"      ... ({len(lines)} lines total)")
            else:
                for line in lines:
                    print(f"      {line}")
        except (json.JSONDecodeError, TypeError):
            print(f"      {str(body)[:500]}")


# ═════════════════════════════════════════════════════════════════════
# STEP 1: Get Signed Identity JWT from Public Site Endpoint (§6.1)
#
# The JWT is signed server-side by Crypto.signWithCertificate (§2.3.1).
# The public Site endpoint avoids exposing the certificate private key.
# ═════════════════════════════════════════════════════════════════════

def get_signed_jwt():
    step(1, "Get Signed Identity JWT (Public Site Endpoint)")

    url = f"{SITE_BASE_URL}/services/apexrest/agent-verify/jwt"
    params = {}
    if JWT_SUBJECT:
        params["sub"] = JWT_SUBJECT

    http_req("GET", url)
    resp = requests.get(url, params=params, timeout=30)
    http_res(resp.status_code, resp.text)

    if resp.status_code != 200:
        error(f"JWT endpoint failed: {resp.text}")
        note("Make sure AgentAPI_JwtRestEndpoint is in the Site Guest User profile.")
        sys.exit(1)

    result = resp.json()

    # Check for error from the Apex endpoint
    if "error" in result:
        error(f"Apex error: {result['error']}")
        sys.exit(1)

    jwt_token = result.get("jwt", "")
    detail("Subject", result.get("subject", "?"))
    detail("Issuer", result.get("issuer", "?"))
    detail("KID", result.get("kid", "?"))
    detail("Audience", result.get("audience", "?"))
    detail("Expires In", f"{result.get('expiresInSeconds', '?')}s")
    detail("JWT", f"{jwt_token[:60]}... ({len(jwt_token)} chars)")
    success("Signed identity JWT obtained from Salesforce Site")
    note("No OAuth needed — the Site endpoint is public. The private key stays in SF.")
    return jwt_token, result


# ═════════════════════════════════════════════════════════════════════
# STEP 2: Exchange JWT for MIAW Access Token (§6.2)
#
# SCRT2 internally: fetches JWKS → finds kid → verifies signature →
# checks claims → returns AUTH or ANON token (§2.1).
# Returns 200 OK EITHER WAY — check context.endUser.subject (§7.1).
# ═════════════════════════════════════════════════════════════════════

def get_miaw_token(identity_jwt):
    step(2, "Exchange JWT for MIAW Access Token (SCRT2)")

    url = f"{SCRT2_URL}/iamessage/api/v2/authorization/authenticated/access-token"
    body = {
        "orgId": SF_ORG_ID,
        "esDeveloperName": ES_DEVELOPER_NAME,
        "capabilitiesVersion": "1",
        "platform": "Web",
        "authorizationType": "JWT",
        "customerIdentityToken": identity_jwt,
    }

    http_req("POST", url, body)
    resp = requests.post(url, json=body, timeout=30)
    http_res(resp.status_code, resp.text)

    if resp.status_code < 200 or resp.status_code >= 300:
        error(f"MIAW token exchange failed: {resp.text}")
        note("Common causes:")
        note("  - JWKS endpoint unreachable from SCRT2")
        note("  - JWT expired (check clock skew)")
        note("  - Issuer mismatch (JWT iss vs User Verification config)")
        note("  - Deployment not published")
        note("  - kid in JWT header doesn't match any key in JWKS")
        sys.exit(1)

    result = resp.json()
    miaw_token = result.get("accessToken", "")

    # Check AUTH vs ANON — THE critical verification evidence (§7.1)
    # SCRT2 returns 200 OK for both — silent fallback to ANON (§2.4)
    context = result.get("context", {})
    end_user = context.get("endUser", {})
    subject = end_user.get("subject", "")

    detail("MIAW Token", f"{miaw_token[:50]}... ({len(miaw_token)} chars)")
    detail("End User Subject", subject)

    # Save lastEventId — needed for SSE subscription (§6.4)
    last_event_id = result.get("lastEventId", "")
    detail("Last Event ID", last_event_id)

    if "/AUTH/" in subject:
        success("USER IS VERIFIED (AUTH) — identity confirmed!")
        parts = subject.split("/")
        if len(parts) >= 5:
            detail("JWKS Keyset", parts[3])
            detail("Verified Identity", parts[4].replace("uid:", ""))
    elif "/ANON/" in subject:
        error("USER IS ANONYMOUS (ANON) — verification FAILED!")
        error("SCRT2 returned 200 OK but silently fell back to anonymous.")
        error("Check: JWKS endpoint, issuer match, kid match, aud match")
    else:
        note(f"Unknown subject format: {subject}")

    return miaw_token, result


# ═════════════════════════════════════════════════════════════════════
# STEP 3: Create Conversation (§6.3)
#
# Conversation ID must be a valid UUID v4 — SCRT2 enforces strict
# compliance (§10 Common Mistakes).
# ═════════════════════════════════════════════════════════════════════

def create_conversation(miaw_token):
    step(3, "Create Conversation")

    conversation_id = str(uuid.uuid4())
    detail("Conversation ID", conversation_id)

    url = f"{SCRT2_URL}/iamessage/api/v2/conversation"
    body = {
        "conversationId": conversation_id,
        "esDeveloperName": ES_DEVELOPER_NAME,
    }

    headers = {
        "Authorization": f"Bearer {miaw_token}",
        "Content-Type": "application/json",
    }

    http_req("POST", url, body)
    resp = requests.post(url, json=body, headers=headers, timeout=30)
    http_res(resp.status_code, resp.text)

    if resp.status_code < 200 or resp.status_code >= 300:
        error(f"Create conversation failed: {resp.text}")
        sys.exit(1)

    success(f"Conversation created: {conversation_id}")
    note("Conversation is now open and routed via Omni-Channel.")
    return conversation_id


# ═════════════════════════════════════════════════════════════════════
# STEP 4: Subscribe to SSE Stream (§6.4)
#
# CRITICAL: Must be established BEFORE sending the first message.
# Agent responses are delivered exclusively via SSE — if you're not
# listening when the agent responds, the response is lost (§6.4).
#
# Required headers (from official SF sample app):
#   - Authorization: Bearer {miaw_token}
#   - X-Org-Id: {orgId}           — without this → 400
#   - Last-Event-Id: {lastEventId} — from Step 2 response (§6.2)
#
# SSE delivers all event types listed in §6.4. Only Message entries
# with text content are agent responses — routing events are
# infrastructure (see ROUTING_ENTRY_TYPES below).
# ═════════════════════════════════════════════════════════════════════

def start_sse_listener(miaw_token, last_event_id):
    """Start SSE listener in a background thread.

    Args:
        miaw_token: The MIAW access token from Step 2
        last_event_id: The lastEventId from the MIAW token response
    """
    global sse_running, sse_connected, sse_thread

    step(4, "Subscribe to SSE Stream (BEFORE sending message)")

    sse_url = f"{SCRT2_URL}/eventrouter/v1/sse"
    detail("SSE URL", sse_url)
    detail("X-Org-Id", SF_ORG_ID)
    detail("Last-Event-Id", last_event_id)

    sse_running = True
    sse_connected = False

    def sse_worker():
        global sse_running, sse_connected

        headers = {
            "Authorization": f"Bearer {miaw_token}",
            "Accept": "text/event-stream",
            "Cache-Control": "no-cache",
            "X-Org-Id": SF_ORG_ID,
        }

        # Only include Last-Event-Id if we have one
        if last_event_id:
            headers["Last-Event-Id"] = str(last_event_id)

        print(f"  [SSE] Connecting to {sse_url}")
        print(f"  [SSE] Headers: X-Org-Id={SF_ORG_ID}, Last-Event-Id={last_event_id}")

        try:
            resp = requests.get(
                sse_url,
                headers=headers,
                stream=True,
                timeout=(10, 120),  # (connect_timeout, read_timeout)
            )

            if resp.status_code != 200:
                print(f"  [SSE] ** FAILED: HTTP {resp.status_code}")
                print(f"  [SSE] Response: {resp.text[:500]}")
                sse_running = False
                return

            sse_connected = True
            print(f"  >> SSE CONNECTED! Status={resp.status_code}")
            print(f"  [SSE Content-Type] {resp.headers.get('Content-Type', '?')}")

            # Read SSE stream line by line
            event_type = None
            event_data = []

            for line in resp.iter_lines(decode_unicode=True):
                if not sse_running:
                    break

                if line is None:
                    continue

                if isinstance(line, bytes):
                    line = line.decode("utf-8")

                line_str = line.strip() if isinstance(line, str) else line

                if line_str.startswith("event:"):
                    event_type = line_str[6:].strip()
                elif line_str.startswith("data:"):
                    event_data.append(line_str[5:].strip())
                elif line_str == "" and event_data:
                    # End of event — process it
                    data_str = "\n".join(event_data)
                    event = {
                        "type": event_type or "message",
                        "data": data_str,
                        "timestamp": datetime.now().isoformat(),
                    }
                    sse_events.append(event)
                    print(f"\n  [SSE EVENT] type={event['type']} at {event['timestamp']}")
                    try:
                        parsed = json.loads(data_str)
                        print(f"  [SSE DATA]  {json.dumps(parsed, indent=2)[:800]}")
                    except json.JSONDecodeError:
                        print(f"  [SSE DATA]  {data_str[:800]}")

                    event_type = None
                    event_data = []

            # Stream ended
            print("  [SSE] Stream ended")

        except requests.exceptions.Timeout:
            print("  [SSE] Connection/read timeout")
        except requests.exceptions.ConnectionError as e:
            print(f"  [SSE] Connection error: {e}")
        except Exception as e:
            print(f"  [SSE] Error: {e}")
        finally:
            sse_running = False

    sse_thread = threading.Thread(target=sse_worker, daemon=True)
    sse_thread.start()

    # Wait for SSE to connect (up to 10s) before proceeding
    note("Waiting for SSE connection before sending message...")
    for i in range(20):  # 20 x 0.5s = 10s max
        time.sleep(0.5)
        if sse_connected:
            success("SSE connected — safe to send message now.")
            return
        if not sse_running:
            # SSE failed to connect
            error("SSE failed to connect. Will rely on polling for responses.")
            return

    note("SSE connection still pending after 10s — proceeding anyway.")


# ═════════════════════════════════════════════════════════════════════
# STEP 5: Send Message (§6.5)
#
# CRITICAL for first message: Must include routingAttributes and
# language when isNewMessagingSession is true (§6.5). Without these,
# the message may not be routed correctly.
# ═════════════════════════════════════════════════════════════════════

def send_message(miaw_token, conversation_id, message_text):
    step(5, "Send Message")

    message_id = str(uuid.uuid4())
    url = f"{SCRT2_URL}/iamessage/api/v2/conversation/{conversation_id}/message"

    body = {
        "message": {
            "id": message_id,
            "messageType": "StaticContentMessage",
            "staticContent": {
                "formatType": "Text",
                "text": message_text,
            },
        },
        "esDeveloperName": ES_DEVELOPER_NAME,
        "isNewMessagingSession": True,
        # CRITICAL: Required for the first message (§6.5)
        "routingAttributes": {},
        "language": "en",
    }

    headers = {
        "Authorization": f"Bearer {miaw_token}",
        "Content-Type": "application/json",
    }

    http_req("POST", url, body)
    detail("Message", message_text)
    detail("Message ID", message_id)

    resp = requests.post(url, json=body, headers=headers, timeout=120)
    http_res(resp.status_code, resp.text)

    if resp.status_code < 200 or resp.status_code >= 300:
        error(f"Send message failed: {resp.text}")
        sys.exit(1)

    success(f"Message sent to conversation {conversation_id}")
    note("Agent processes asynchronously. Listening for response via SSE...")
    return resp.json() if resp.text else {}


# ═════════════════════════════════════════════════════════════════════
# STEP 6: Wait for Agent Response — SSE + Polling (§7.3)
#
# SSE events include routing events that are NOT agent text messages.
# We filter these out using ROUTING_ENTRY_TYPES (see §6.4 for the
# full event lifecycle).
# ═════════════════════════════════════════════════════════════════════

ROUTING_ENTRY_TYPES = {
    "RoutingWorkResult",
    "RoutingResult",
    "SessionStatusChanged",
    "ParticipantChanged",
    "TypingStartedIndicator",
    "TypingStoppedIndicator",
}

def wait_for_response(miaw_token, conversation_id, max_wait=60, poll_interval=3):
    step(6, f"Wait for Agent Response (up to {max_wait}s)")

    entries_url = (
        f"{SCRT2_URL}/iamessage/api/v2/conversation/{conversation_id}/entries"
    )
    headers = {
        "Authorization": f"Bearer {miaw_token}",
        "Accept": "application/json",
    }

    agent_text_found = False
    start_time = time.time()
    poll_count = 0
    seen_entry_types = set()

    note(f"Waiting up to {max_wait}s for agent response...")
    note(f"SSE connected: {sse_connected} | SSE running: {sse_running}")

    while time.time() - start_time < max_wait:
        poll_count += 1
        elapsed = time.time() - start_time

        # ── Check SSE events for agent text messages ──
        for evt in sse_events:
            try:
                data = json.loads(evt["data"])
                if not isinstance(data, dict):
                    continue  # skip pings (integer 0) and other non-dict events
                entries = data.get("conversationEntries", [])
                # SSE entries may be nested under conversationEntry (singular)
                if not entries and "conversationEntry" in data:
                    entries = [data["conversationEntry"]]
                for entry in entries:
                    entry_type = entry.get("entryType", "")
                    if entry_type not in seen_entry_types:
                        seen_entry_types.add(entry_type)
                        detail("New Entry Type (SSE)", entry_type)

                    if is_agent_text_message(entry):
                        display_agent_entry(entry)
                        agent_text_found = True
            except (json.JSONDecodeError, TypeError):
                pass

        if agent_text_found:
            break

        # ── Poll the entries endpoint ──
        detail("Poll", f"#{poll_count} at {elapsed:.1f}s")
        try:
            resp = requests.get(entries_url, headers=headers, timeout=10)

            if resp.status_code == 200:
                body = resp.json()
                entries = body.get("conversationEntries", body.get("entries", []))

                # Log raw on first poll to see actual format
                if poll_count == 1:
                    detail("Raw Entries Response", json.dumps(body, indent=2)[:1500])

                detail("Entries Count", len(entries))

                for entry in entries:
                    entry_type = entry.get("entryType", "")
                    if entry_type not in seen_entry_types:
                        seen_entry_types.add(entry_type)
                        detail("New Entry Type (poll)", entry_type)

                    if is_agent_text_message(entry):
                        display_agent_entry(entry)
                        agent_text_found = True

                if agent_text_found:
                    break
            else:
                detail("Entries HTTP", f"{resp.status_code}: {resp.text[:200]}")
        except Exception as e:
            detail("Poll Error", str(e))

        time.sleep(poll_interval)

    if seen_entry_types:
        detail("All Entry Types Seen", ", ".join(sorted(seen_entry_types)))

    if not agent_text_found:
        note(f"No agent TEXT response after {max_wait}s ({poll_count} polls, "
             f"{len(sse_events)} SSE events)")
        note("")
        note("TROUBLESHOOTING — Why the agent may not respond:")
        note("  1. SSE connection: Did SSE connect? (Check Step 4 output)")
        note("  2. Omni-Channel routing: Is there a flow routing to your agent?")
        note("  3. Agent/bot status: Is it online in Omni Supervisor?")
        note("  4. Messaging channel: Is it linked to the ES deployment?")
        note("  5. Agent topics: Does any topic match the message?")
        note("  6. Try the web widget first to confirm the agent works")
        note("  7. Check MessagingSession in SOQL:")
        note("     SELECT Id, AgentType, AgentMessageCount, Status")
        note("     FROM MessagingSession WHERE CreatedDate = TODAY")
        note("     ORDER BY CreatedDate DESC LIMIT 5")

    return agent_text_found


def extract_text_from_payload(payload):
    """Extract text from an entryPayload JSON string (§7.3)."""
    if not payload:
        return None
    try:
        p = json.loads(payload) if isinstance(payload, str) else payload

        # Format 1: abstractMessage.staticContent.text
        abstract_msg = p.get("abstractMessage", {})
        static_content = abstract_msg.get("staticContent", {})
        text = static_content.get("text")
        if text:
            return text

        # Format 2: message.staticContent.text
        message = p.get("message", {})
        static_content = message.get("staticContent", {})
        text = static_content.get("text")
        if text:
            return text

        # Format 3: direct text
        text = p.get("text")
        if text:
            return text

    except (json.JSONDecodeError, TypeError, AttributeError):
        pass
    return None


def is_agent_text_message(entry):
    """Determine if a conversation entry is a TEXT message from the agent.

    Only returns True for actual text messages. Routing events like
    RoutingWorkResult, RoutingResult, etc. are Omni-Channel infrastructure
    — NOT agent responses. See §6.4 for the full event type list.
    """
    # Skip known routing/system entry types
    entry_type = entry.get("entryType", "")
    if entry_type in ROUTING_ENTRY_TYPES:
        return False

    # Must be a Message entry type (or have message content)
    if entry_type and entry_type != "Message":
        return False

    # Must NOT be from the end user
    sender = entry.get("sender", {})
    if isinstance(sender, dict):
        role = sender.get("role", "")
        if role.lower() == "enduser":
            return False

    actor_type = entry.get("actorType", "")
    if actor_type and "user" in actor_type.lower() and "end" in actor_type.lower():
        return False

    # Must have actual text content in the payload
    payload = entry.get("entryPayload", "")
    if payload:
        text = extract_text_from_payload(payload)
        if text:
            return True

    # Check for direct message field
    message = entry.get("message", "")
    if message and isinstance(message, str):
        return True

    return False


def display_agent_entry(entry):
    """Display a conversation entry from the agent."""
    agent_name = (
        entry.get("actorName")
        or entry.get("senderDisplayName")
        or "Agent"
    )
    if isinstance(entry.get("sender"), dict):
        sender = entry["sender"]
        if not entry.get("actorName"):
            agent_name = sender.get("subject", sender.get("role", agent_name))

    entry_type = entry.get("entryType", "?")
    payload = entry.get("entryPayload", "")

    if payload:
        text = extract_text_from_payload(payload)
        if text:
            success(f"{agent_name} says: {text}")
            return
        detail(f"{agent_name} ({entry_type})", str(payload)[:500])
        return

    message = entry.get("message", "")
    if message:
        success(f"{agent_name} says: {message}")
        return

    detail(f"{agent_name} ({entry_type})", f"Entry keys: {list(entry.keys())}")


# ═════════════════════════════════════════════════════════════════════
# SUMMARY
# ═════════════════════════════════════════════════════════════════════

def show_summary(miaw_result, conversation_id, agent_responded):
    banner("SUMMARY")

    context = miaw_result.get("context", {})
    end_user = context.get("endUser", {})
    subject = end_user.get("subject", "")

    is_auth = "/AUTH/" in subject
    detail("Auth Status", "VERIFIED (AUTH)" if is_auth else "ANONYMOUS (ANON)")
    detail("Conversation ID", conversation_id)
    detail("SSE Connected", sse_connected)
    detail("SSE Events Received", len(sse_events))
    detail("Agent Text Response", "Yes" if agent_responded else "No")

    if not agent_responded:
        print()
        note("The agent did not send a text response within the polling window.")
        note("See troubleshooting steps above.")


# ═════════════════════════════════════════════════════════════════════
# MAIN
# ═════════════════════════════════════════════════════════════════════

def main():
    global sse_running

    # Parse args
    message = TEST_MESSAGE
    custom_sub = JWT_SUBJECT

    args = sys.argv[1:]
    i = 0
    while i < len(args):
        if args[i] == "--sub" and i + 1 < len(args):
            custom_sub = args[i + 1]
            i += 2
        else:
            message = args[i]
            i += 1

    if custom_sub:
        os.environ["JWT_SUBJECT"] = custom_sub

    banner("MIAW VERIFIED USER FLOW — PYTHON E2E TEST")
    detail("Timestamp", datetime.now().isoformat())
    detail("Site URL", SITE_BASE_URL)
    detail("SCRT2 URL", SCRT2_URL)
    detail("Org ID", SF_ORG_ID)
    detail("ES Deployment", ES_DEVELOPER_NAME)
    detail("Message", message)
    if custom_sub:
        detail("Subject Override", custom_sub)

    try:
        # Step 1: Get signed JWT from public Site endpoint (§6.1)
        identity_jwt, jwt_info = get_signed_jwt()

        # Step 2: Exchange for MIAW token — also returns lastEventId (§6.2)
        miaw_token, miaw_result = get_miaw_token(identity_jwt)

        # Extract lastEventId for SSE — CRITICAL (§6.4)
        last_event_id = miaw_result.get("lastEventId", "")

        # Step 3: Create conversation (§6.3)
        conversation_id = create_conversation(miaw_token)

        # Step 4: Start SSE BEFORE sending message (§6.4)
        start_sse_listener(miaw_token, last_event_id)

        # Step 5: Send message with routingAttributes + language (§6.5)
        send_message(miaw_token, conversation_id, message)

        # Step 6: Wait for agent response — SSE + polling (§7.3)
        agent_responded = wait_for_response(
            miaw_token, conversation_id,
            max_wait=60, poll_interval=3
        )

        # Summary
        show_summary(miaw_result, conversation_id, agent_responded)

    except KeyboardInterrupt:
        print("\n\n  Interrupted by user.")
    except Exception as e:
        error(f"Unhandled error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        sse_running = False
        if sse_thread and sse_thread.is_alive():
            note("Stopping SSE listener...")
            sse_thread.join(timeout=3)

    banner("DONE")


if __name__ == "__main__":
    main()
