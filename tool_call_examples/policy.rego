package pretool

# Default: allow tool calls that are not Bash or don't contain denied commands.
default decision := {
	"hookSpecificOutput": {
		"hookEventName": "PreToolUse",
		"permissionDecision": "allow",
		"permissionDecisionReason": "Tool call permitted by policy",
	},
}

# Commands that must never be executed.
denied_commands := {
	"rm", "rmdir", "mkfs", "dd",
	"shutdown", "reboot",
	"kill", "killall",
	"chmod", "chown", "chgrp",
	"sudo", "su",
}

# Tokenise the command string on whitespace and common shell metacharacters.
tokens contains token if {
	some token in regex.split("[\\s;|&(){}$!><]+", input.tool_input.command)
	token != ""
}

# Extract basenames so that `/usr/bin/rm` is caught as `rm`.
basenames contains base if {
	some token in tokens
	parts := split(token, "/")
	base := parts[count(parts) - 1]
	base != ""
}

# Collect every denied command that appears in the input.
found_denied contains cmd if {
	some cmd in denied_commands
	cmd in basenames
}

# Deny the Bash tool call when any denied command is present.
decision := {
	"hookSpecificOutput": {
		"hookEventName": "PreToolUse",
		"permissionDecision": "deny",
		"permissionDecisionReason": sprintf(
			"Denied: command contains disallowed operation(s): %v",
			[found_denied],
		),
	},
} if {
	input.tool_name == "Bash"
	count(found_denied) > 0
}
