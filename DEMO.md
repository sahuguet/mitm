 Terminal 1 -- MCP server:
  uv run python mcp_server.py

  Terminal 2 -- mitm proxy (forward mode, not reverse):
  mitmdump -s mcp_proxy.py --set flow_detail=0 -p 8080

  Terminal 3 -- Claude Code with proxy env vars:
  HTTP_PROXY=http://127.0.0.1:8080 NO_PROXY=api.anthropic.com,statsig.anthropic.com,sentry.io claude

  HTTP_PROXY forces HTTP traffic through the mitm proxy. NO_PROXY excludes Anthropic's API and telemetry endpoints so only MCP traffic
  hits the proxy.
  
  # Flow diagram
  
  ⏺ ┌─────────────┐         ┌──────────────────┐         ┌─────────────────┐
    │             │  HTTP   │                  │  HTTP   │                 │
    │ Claude Code │────────▶│  mitmdump:8080   │────────▶│ MCP Server:8000 │
    │             │         │  (mcp_proxy.py)  │         │ (mcp_server.py) │
    │             │◀────────│                  │◀────────│                 │
    └──────┬──────┘         │  ┌────────────┐  │         └─────────────────┘
           │                │  │ OPA / Rego │  │
           │                │  │  policy    │  │
           │                │  └────────────┘  │
           │                │                  │
           │                │  ALLOW ──▶ forward to MCP  
           │                │  DENY  ──▶ JSON-RPC error  
           │                └──────────────────┘
           │
           │  DIRECT (NO_PROXY)
           ▼
    ┌───────────────────┐
    │ api.anthropic.com │
    │ statsig.*         │
    │ sentry.io         │
    └───────────────────┘
  
      HTTP_PROXY=http://127.0.0.1:8080
      NO_PROXY=api.anthropic.com,statsig.anthropic.com,sentry.io
  
    MCP tool calls from Claude Code go through the proxy, where mcp_proxy.py evaluates the OPA/Rego policy. Allowed requests are forwarded
    to the MCP server; denied requests get a JSON-RPC error response back. All other traffic (Anthropic API, telemetry) bypasses the proxy
    via NO_PROXY.
