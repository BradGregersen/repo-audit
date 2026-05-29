"""D-67 + D-68: CLIConnectionError on both attempts."""
from claude_agent_sdk._errors import CLIConnectionError

RAISE_ON_CONNECT = CLIConnectionError("transport closed")
RAISE_ALWAYS = True
MESSAGES: list = []
