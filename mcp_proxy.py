"""MCP proxy using mitmproxy to log MCP traffic, passing through all other traffic."""

import json
import logging
import os
import subprocess
import urllib.error
import urllib.request
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

# --- OPA / Rego policy configuration ---
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
POLICY_PATH = os.environ.get(
    "MCP_POLICY_PATH",
    os.path.join(SCRIPT_DIR, "tool_call_examples", "mcp_policy.rego"),
)
OPA_MODE = os.environ.get("MCP_OPA_MODE", "cli")          # "cli" or "server"
OPA_URL = os.environ.get(
    "MCP_OPA_URL", "http://localhost:8181/v1/data/pretool/decision"
)
POLICY_FAIL_MODE = os.environ.get("MCP_POLICY_FAIL_MODE", "closed")  # "closed" or "open"


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


def build_opa_input(body: dict) -> dict | None:
    """Transform an MCP JSON-RPC tools/call body into OPA input format.

    Returns {"tool_name": ..., "tool_input": ...} or None for non-tools/call requests.
    """
    if body.get("method") != "tools/call":
        return None

    params = body.get("params", {})
    return {
        "tool_name": params.get("name", ""),
        "tool_input": params.get("arguments", {}),
    }


def evaluate_policy_cli(opa_input: dict) -> dict:
    """Evaluate OPA policy via the opa CLI.

    Runs: opa eval -I -d <policy> --format raw 'data.pretool.decision'
    with the input JSON piped on stdin.

    Returns the parsed decision dict.
    Raises RuntimeError on failure.
    """
    cmd = [
        "opa", "eval",
        "-I",
        "-d", POLICY_PATH,
        "--format", "raw",
        "data.pretool.decision",
    ]
    try:
        result = subprocess.run(
            cmd,
            input=json.dumps(opa_input),
            capture_output=True,
            text=True,
            timeout=5,
        )
    except FileNotFoundError:
        raise RuntimeError("opa binary not found on PATH")
    except subprocess.TimeoutExpired:
        raise RuntimeError("opa eval timed out after 5s")

    if result.returncode != 0:
        raise RuntimeError(f"opa eval failed (rc={result.returncode}): {result.stderr.strip()}")

    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Failed to parse opa output: {exc}")


def evaluate_policy_server(opa_input: dict) -> dict:
    """Evaluate OPA policy via the OPA REST API.

    POSTs {"input": opa_input} to OPA_URL.

    Returns the parsed decision dict.
    Raises RuntimeError on failure.
    """
    payload = json.dumps({"input": opa_input}).encode()
    req = urllib.request.Request(
        OPA_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            resp_body = json.loads(resp.read())
    except urllib.error.URLError as exc:
        raise RuntimeError(f"OPA server request failed: {exc}")
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Failed to parse OPA server response: {exc}")

    # The OPA REST API wraps the result under a "result" key.
    return resp_body.get("result", resp_body)


def check_policy(body: dict) -> str | None:
    """Evaluate OPA/Rego policy for an MCP request.

    Returns an error message string on deny, or None on allow.
    """
    opa_input = build_opa_input(body)
    if opa_input is None:
        return None  # Not a tools/call request -- nothing to check.

    try:
        if OPA_MODE == "server":
            decision = evaluate_policy_server(opa_input)
        else:
            decision = evaluate_policy_cli(opa_input)
    except RuntimeError as exc:
        if POLICY_FAIL_MODE == "open":
            print(f"[OPA] Policy evaluation error (fail-open): {exc}")
            return None
        return f"Policy evaluation error (fail-closed): {exc}"

    hook_output = decision.get("hookSpecificOutput", {})
    permission = hook_output.get("permissionDecision", "deny")

    if permission == "allow":
        return None

    reason = hook_output.get(
        "permissionDecisionReason",
        "Request denied by policy.",
    )
    return f"Policy violation: {reason}"


class MCPLogger:
    """Addon that logs MCP traffic and passes through all other traffic."""

    def __init__(self):
        self.request_count = 0
        # Startup validation and config logging
        print(f"[OPA] Policy mode: {OPA_MODE}")
        print(f"[OPA] Fail mode: {POLICY_FAIL_MODE}")
        if OPA_MODE == "cli":
            print(f"[OPA] Policy file: {POLICY_PATH}")
            if not os.path.isfile(POLICY_PATH):
                print(f"[OPA] WARNING: Policy file not found: {POLICY_PATH}")
        else:
            print(f"[OPA] Server URL: {OPA_URL}")

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

        # Check OPA/Rego policy for tool calls
        try:
            body = json.loads(flow.request.content)
            policy_error = check_policy(body)
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
