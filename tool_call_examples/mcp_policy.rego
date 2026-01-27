package pretool

# Default: allow tool calls that don't match any deny rule.
default decision := {
	"hookSpecificOutput": {
		"hookEventName": "PreToolUse",
		"permissionDecision": "allow",
		"permissionDecisionReason": "MCP tool call permitted by policy",
	},
}

# Only @gouv.fr recipients are allowed.
allowed_domain := "@gouv.fr"

# Tools that take a recipient argument.
recipient_tools := {"send_message", "create_draft"}

# Deny when an MCP recipient tool is called with a disallowed email domain.
decision := {
	"hookSpecificOutput": {
		"hookEventName": "PreToolUse",
		"permissionDecision": "deny",
		"permissionDecisionReason": sprintf(
			"Denied: recipient '%s' is not allowed. Only %s addresses are permitted.",
			[input.tool_input.recipient, allowed_domain],
		),
	},
} if {
	input.tool_name in recipient_tools
	not endswith(input.tool_input.recipient, allowed_domain)
}
