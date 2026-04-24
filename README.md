# enigmagent-mcp

**Encrypted local vault for AI agents — via MCP protocol**

`enigmagent-mcp` is the Model Context Protocol server for [EnigmAgent](https://github.com/Agnuxo1/EnigmAgent). It exposes your AES-256-GCM + Argon2id encrypted credential vault as MCP tools, allowing any MCP-compatible AI agent (Claude Desktop, Cursor, Continue.dev, Open WebUI, AnythingLLM, LM Studio, etc.) to resolve `{{PLACEHOLDER}}` secrets at runtime.

**The LLM never sees real API keys or credentials.**

## Quick Start

```bash
npx enigmagent-mcp --vault ./my.vault.json
```

## How it works

1. Store secrets in an encrypted vault: `{ "OPENAI_KEY": "sk-..." }`
2. Use `{{OPENAI_KEY}}` in your agent prompts
3. EnigmAgent resolves them before the LLM receives the message

## MCP Tools

- `resolve_secret` — resolve a `{{PLACEHOLDER}}` to its vault value
- `list_keys` — list available placeholder names (no values)
- `vault_status` — check vault lock state

## Security

- **AES-256-GCM** symmetric encryption
- **Argon2id** key derivation (memory-hard, GPU-resistant)
- **Zero cloud** — vault never leaves your machine
- **Zero telemetry** — no analytics, no callbacks

## Full Repository

Browser extension, npm library, Python SDK, and more integrations at:
**https://github.com/Agnuxo1/EnigmAgent**

## License

MIT

