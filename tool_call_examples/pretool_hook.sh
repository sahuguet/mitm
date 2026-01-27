#!/usr/bin/env bash
#
# PreToolUse hook script for Claude Code.
# Evaluates a Rego policy against the tool call input received on stdin.
#
# Usage (in .claude/settings.json):
#   {
#     "hooks": {
#       "PreToolUse": [{
#         "matcher": "Bash",
#         "hooks": [{
#           "type": "command",
#           "command": "/path/to/tool_call_examples/pretool_hook.sh"
#         }]
#       }]
#     }
#   }

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
POLICY="${SCRIPT_DIR}/policy.rego"

opa eval -I -d "${POLICY}" --format raw 'data.pretool.decision'
