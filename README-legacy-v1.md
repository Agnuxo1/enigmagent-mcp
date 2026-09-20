# enigmagent-mcp

[![npm version](https://img.shields.io/npm/v/enigmagent-mcp?label=npm&color=cb3837)](https://www.npmjs.com/package/enigmagent-mcp)
[![npm downloads](https://img.shields.io/npm/dw/enigmagent-mcp?label=downloads)](https://www.npmjs.com/package/enigmagent-mcp)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Crypto](https://img.shields.io/badge/crypto-Argon2id%20%2B%20AES--256--GCM-green.svg)](https://github.com/Agnuxo1/EnigmAgent/blob/main/docs/THREAT_MODEL.md)
[![Glama MCP](https://glama.ai/mcp/servers/Agnuxo1/enigmagent-mcp/badges/score.svg)](https://glama.ai/mcp/servers/Agnuxo1/enigmagent-mcp)
[![GitHub stars](https://img.shields.io/github/stars/Agnuxo1/enigmagent-mcp?style=social)](https://github.com/Agnuxo1/enigmagent-mcp)

> **Local encrypted vault MCP server. Your LLM types `{{OPENAI_KEY}}`. The real value never reaches the model — not in prompts, not in logs, not in conversation history.**

```bash
npx enigmagent-mcp --vault ./my.vault.json
```

That's the entire install. Works with **Claude Desktop, Cursor, Continue.dev, Cline, Open WebUI, AnythingLLM, LM Studio, Zed**, and anything else that speaks MCP.

> ⭐ **Star this repo if you've ever pasted a token you regretted.**

---

## The 30-second pitch

You ask Claude to call your GitHub API. Claude needs `GITHUB_TOKEN`. Three options that all suck:

1. Paste it in the chat → it lives in the provider's logs forever
2. Put it in env vars → it leaks the moment Claude reads `.env` while debugging
3. Skip the agent → you lose the whole point

**Option 4: type `{{GITHUB_TOKEN}}` in the prompt.** EnigmAgent intercepts at the MCP boundary, decrypts locally with AES-256-GCM, and returns the real token only when the requesting origin matches the secret's bound domain. The model literally never has the value.

---

## Setup per client

### Claude Desktop

`~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "enigmagent": {
      "command": "npx",
      "args": ["-y", "enigmagent-mcp", "--vault", "/absolute/path/to/my.vault.json"]
    }
  }
}
```

Restart Claude. Two new tools appear: `enigmagent_resolve` and `enigmagent_list`.

### Cursor

`~/.cursor/mcp.json`:
```json
{
  "mcpServers": {
    "enigmagent": {
      "command": "npx",
      "args": ["-y", "enigmagent-mcp", "--vault", "/abs/path/my.vault.json"]
    }
  }
}
```

### Continue.dev

`~/.continue/config.yaml`:
```yaml
mcpServers:
  - name: enigmagent
    command: npx
    args: ["-y", "enigmagent-mcp", "--vault", "/abs/path/my.vault.json"]
```

### Cline (VS Code)

`cline_mcp_settings.json`:
```json
{
  "mcpServers": {
    "enigmagent": {
      "command": "npx",
      "args": ["-y", "enigmagent-mcp", "--vault", "/abs/path/my.vault.json"]
    }
  }
}
```

### Open WebUI

```bash
# uses mcpo (https://github.com/open-webui/mcpo) as bridge
mcpo --port 8000 -- npx enigmagent-mcp --vault /abs/path/my.vault.json
```

### Custom REST integration

```bash
npx enigmagent-mcp --mode rest --port 3737 --vault /abs/path/my.vault.json
```

Then `POST /resolve` with `{"placeholder": "OPENAI_KEY", "origin": "https://api.openai.com"}` returns the decrypted value (only when the origin matches the secret's bound domain).

---

## CI / headless mode

Skip the interactive password prompt with env vars (only do this in trusted environments):

```bash
ENIGMAGENT_USER=alice ENIGMAGENT_PASS=… npx enigmagent-mcp --vault ./my.vault.json
```

Without these, the server starts in **locked mode** if there's no TTY — useful behind `mcp-proxy` and similar wrappers.

---

## MCP tools exposed

| Tool | Description |
|---|---|
| `enigmagent_resolve` | Resolve a placeholder to its vault value. **Domain binding enforced** — the requesting `origin` must match the secret's bound domain |
| `enigmagent_list` | List secret names + their bound domains. Never returns values |

```jsonc
// example tool call
{
  "name": "enigmagent_resolve",
  "arguments": {
    "placeholder": "GITHUB_TOKEN",
    "origin": "https://api.github.com"
  }
}
// → returns the decrypted token string
```

---

## How it works

```
LLM emits tool call:  fetch({headers: {Authorization: "Bearer {{OPENAI_KEY}}"}})
                                                              │
                                              ┌───────────────▼───────────────┐
                                              │  enigmagent-mcp (this server) │
                                              │  • match placeholder name     │
                                              │  • check origin == bound dom. │
                                              │  • decrypt with AES-256-GCM   │
                                              └───────────────┬───────────────┘
                                                              │  real token
                                                              ▼
                                                    HTTPS to api.openai.com
```

The plaintext value exists in process memory for one event-loop tick. Never logged, never in stdout, never visible to the model.

---

## Security model

| Layer | Implementation |
|---|---|
| KDF | **Argon2id** (m=64 MiB, t=3, p=1) — `@noble/hashes@1.4.0`, bundled |
| Encryption | **AES-256-GCM**, 96-bit nonce per entry |
| Domain binding | Every secret pinned to a domain; resolver rejects mismatched origins |
| Master key | Lives in process memory only — never written to disk |
| Vault file | Encrypted JSON, plaintext never persisted |

**What it does not protect against:** a compromised process reading session memory, a malicious MCP server you've connected to with permission to call `enigmagent_resolve`, side-channels (timing, swap, core dumps). Full threat model: [docs/THREAT_MODEL.md](https://github.com/Agnuxo1/EnigmAgent/blob/main/docs/THREAT_MODEL.md).

---

## Full ecosystem

This repo is the **MCP server** alone. The full EnigmAgent project includes:

- **Browser extension** (Chrome/Firefox/Edge) for credentials inside web forms
- **Python SDK** for LangChain / LlamaIndex / CrewAI
- **REST + stdio** dual-mode API
- **Domain-bound document injection** (`{{DOC:filename}}`)

Main repository: **https://github.com/Agnuxo1/EnigmAgent**

EnigmAgent is part of the [OpenCLAW / P2PCLAW](https://www.p2pclaw.com) ecosystem of privacy-preserving local AI tooling — a multi-agent scientific research network where dozens of LLM agents need credentials and none of them should have them.

---

## License

MIT — see [LICENSE](LICENSE).

## Contributing

Pull requests welcome. Security disclosures: see [SECURITY.md](https://github.com/Agnuxo1/EnigmAgent/blob/main/SECURITY.md) in the main repo.

— [Francisco Angulo de Lafuente](https://github.com/Agnuxo1)
