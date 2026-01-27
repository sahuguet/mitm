"""Simple MCP server with email-like tools using FastMCP."""

from fastmcp import FastMCP

mcp = FastMCP("Email Service")


@mcp.tool()
def create_draft(recipient: str, subject: str, content: str) -> dict:
    """Create an email draft.

    Args:
        recipient: Email address of the recipient
        subject: Subject line of the email
        content: Body content of the email

    Returns:
        Draft information with a generated ID
    """
    print('inside create_draft')
    draft_id = f"draft_{hash((recipient, subject))}"
    return {
        "status": "draft_created",
        "draft_id": draft_id,
        "recipient": recipient,
        "subject": subject,
        "content": content,
    }


@mcp.tool()
def send_message(recipient: str, subject: str, content: str) -> dict:
    """Send an email message.

    Args:
        recipient: Email address of the recipient
        subject: Subject line of the email
        content: Body content of the email

    Returns:
        Message delivery confirmation
    """
    print('inside send_messag')
    message_id = f"msg_{hash((recipient, subject, content))}"
    return {
        "status": "sent",
        "message_id": message_id,
        "recipient": recipient,
        "subject": subject,
    }


if __name__ == "__main__":
    mcp.run(transport="streamable-http", host="127.0.0.1", port=8000)
