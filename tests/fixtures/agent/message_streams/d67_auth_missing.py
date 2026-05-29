"""D-67 fallback: CLINotFoundError at ClaudeSDKClient construction."""
from claude_agent_sdk._errors import CLINotFoundError

RAISE_ON_CONNECT = CLINotFoundError("Claude Code CLI binary not bundled")
RAISE_ALWAYS = False  # auth-missing is terminal; no retry
MESSAGES: list = []
