#!/usr/bin/env bash

echo "=== mcp_tool1.json (send_message to @gouv.fr — should ALLOW) ==="
cat mcp_tool1.json | opa eval -I -d mcp_policy.rego --format raw 'data.pretool.decision' | jq .

echo ""
echo "=== mcp_tool2.json (send_message to @external.com — should DENY) ==="
cat mcp_tool2.json | opa eval -I -d mcp_policy.rego --format raw 'data.pretool.decision' | jq .

echo ""
echo "=== mcp_tool3.json (create_draft to @gmail.com — should DENY) ==="
cat mcp_tool3.json | opa eval -I -d mcp_policy.rego --format raw 'data.pretool.decision' | jq .
