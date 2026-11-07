# support-copilot

support-copilot is an internal AI agent maintained by the globex devex team. It uses MCP servers for tool access and runs its evaluation suite in GitHub Actions.

## Setup

1. Copy `.env.example` to `.env` and fill in the values.
2. Start the agent with `make dev`.

## Security

Credentials are referenced from the environment; do not paste tokens into config files.
