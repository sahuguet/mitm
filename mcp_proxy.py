"""MCP proxy using mitmproxy to log MCP traffic, passing through all other traffic."""

import json
import logging
from datetime import datetime

from mitmproxy import http

# Suppress mitmproxy's client connect/disconnect log messages
logging.getLogger("mitmproxy.proxy.server").setLevel(logging.WARNING)

# MCP JSON-RPC methods to detect MCP traffic
MCP_METHODS = {
    "initialize",
    "initialized",
    "ping",
    "notifications/cancelled",
    "notifications/progress",
    "notifications/message",
    "notifications/resources/updated",
    "notifications/resources/list_changed",
    "notifications/tools/list_changed",
    "notifications/prompts/list_changed",
    "resources/list",
    "resources/read",
    "resources/subscribe",
    "resources/unsubscribe",
    "tools/list",
    "tools/call",
    "prompts/list",
    "prompts/get",
    "logging/setLevel",
    "sampling/createMessage",
    "completion/complete",
    "roots/list",
}


def is_mcp_traffic(content: bytes) -> bool:
    """Check if the content appears to be MCP JSON-RPC traffic."""
    if not content:
        return False
    try:
        body = json.loads(content)
        # Check for JSON-RPC structure with MCP method
        if isinstance(body, dict):
            if "jsonrpc" in body and body.get("jsonrpc") == "2.0":
                method = body.get("method", "")
                # Check if it's a known MCP method or a response (has result/error)
                if method in MCP_METHODS or "result" in body or "error" in body:
                    return True
        # Handle batched requests
        elif isinstance(body, list) and len(body) > 0:
            first = body[0]
            if isinstance(first, dict) and first.get("jsonrpc") == "2.0":
                return True
    except (json.JSONDecodeError, UnicodeDecodeError):
        pass
    return False


def check_send_message_policy(body: dict) -> str | None:
    """Check if a send_message call violates the email domain policy.

    Returns an error message if policy is violated, None if allowed.
    """
    if body.get("method") != "tools/call":
        return None

    params = body.get("params", {})
    if params.get("name") != "send_message":
        return None

    arguments = params.get("arguments", {})
    recipient = arguments.get("recipient", "")

    if not recipient.endswith("@gouv.fr"):
        return f"Policy violation: recipient '{recipient}' is not allowed. Only @gouv.fr email addresses are permitted."

    return None


class MCPLogger:
    """Addon that logs MCP traffic and passes through all other traffic."""

    def __init__(self):
        self.request_count = 0

    def client_connected(self, client) -> None:
        """Suppress client connect messages."""
        pass

    def client_disconnected(self, client) -> None:
        """Suppress client disconnect messages."""
        pass

    def request(self, flow: http.HTTPFlow) -> None:
        """Log incoming MCP requests, pass through non-MCP traffic."""
        if not is_mcp_traffic(flow.request.content):
            return  # Let non-MCP traffic pass through silently

        self.request_count += 1
        timestamp = datetime.now().isoformat()

        # Check policy for send_message
        try:
            body = json.loads(flow.request.content)
            policy_error = check_send_message_policy(body)
            if policy_error:
                print(f"\n{'!'*60}")
                print(f"[{timestamp}] POLICY VIOLATION - REQUEST BLOCKED")
                print(f"{'!'*60}")
                print(policy_error)

                # Return JSON-RPC error response
                error_response = {
                    "jsonrpc": "2.0",
                    "id": body.get("id"),
                    "error": {
                        "code": -32600,
                        "message": policy_error
                    }
                }
                flow.response = http.Response.make(
                    200,
                    json.dumps(error_response),
                    {"Content-Type": "application/json"}
                )
                return
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass

        print(f"\n{'='*60}")
        print(f"[{timestamp}] MCP REQUEST #{self.request_count}")
        print(f"{'='*60}")
        print(f"Method: {flow.request.method}")
        print(f"URL: {flow.request.pretty_url}")
        print(f"Headers:")
        for name, value in flow.request.headers.items():
            print(f"  {name}: {value}")

        if flow.request.content:
            try:
                body = json.loads(flow.request.content)
                print(f"Body (JSON):")
                print(json.dumps(body, indent=2))
            except (json.JSONDecodeError, UnicodeDecodeError):
                print(f"Body (raw): {flow.request.content[:500]}")

    def response(self, flow: http.HTTPFlow) -> None:
        """Log MCP responses, pass through non-MCP traffic."""
        # Check both request and response for MCP traffic
        if not (is_mcp_traffic(flow.request.content) or is_mcp_traffic(flow.response.content)):
            return  # Let non-MCP traffic pass through silently

        timestamp = datetime.now().isoformat()

        print(f"\n{'-'*60}")
        print(f"[{timestamp}] MCP RESPONSE")
        print(f"{'-'*60}")
        print(f"Status: {flow.response.status_code}")
        print(f"Headers:")
        for name, value in flow.response.headers.items():
            print(f"  {name}: {value}")

        if flow.response.content:
            try:
                body = json.loads(flow.response.content)
                print(f"Body (JSON):")
                print(json.dumps(body, indent=2))
            except (json.JSONDecodeError, UnicodeDecodeError):
                content_preview = flow.response.content[:500]
                print(f"Body (raw): {content_preview}")


addons = [MCPLogger()]
