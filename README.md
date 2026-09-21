# enigmagent-mcp 2.0.0

`enigmagent-mcp` is a local encrypted vault server for MCP-capable clients. It
stores secret values with an Argon2id-derived AES-256-GCM key and keeps the
vault file encrypted at rest.

Version 2.0.0 makes the security boundary explicit:

- MCP starts in metadata-only mode. Raw secret resolution is disabled unless the
  operator passes `--allow-raw-resolve` or sets `ENIGMAGENT_ALLOW_RAW_RESOLVE=1`.
- REST binds to `127.0.0.1` and requires a 32–256 character Bearer token.
- REST requests have bounded headers, bodies, and timeouts; responses do not
  include arbitrary exception messages or permissive browser CORS.
- Vault writes use a temporary file, flush, replacement, and a recovery backup.
- Version 1 vaults remain readable. New vaults use format version 2 and the
  versioned KDF context `enigma/v2`.

Raw resolution is deliberately an opt-in escape hatch. A caller-declared origin
is not proof of the network destination, and a trusted MCP client can still pass
returned plaintext to its model. Do not enable raw resolution for an untrusted
client or a shared process.

## Install and run

```bash
npx enigmagent-mcp@2.0.0 --vault ./my.vault.json
```

The first run prompts for the existing vault credentials when attached to a
terminal. For a trusted headless process, set `ENIGMAGENT_USER` and
`ENIGMAGENT_PASS` in its private environment. The server does not print either
value.

## MCP modes

The stdio transport implements bounded JSON-RPC MCP initialization, ping,
`tools/list`, and `tools/call`. The default tool is:

- `enigmagent_list`: names, domains, and creation timestamps only.

With explicit raw-resolution opt-in, it additionally exposes:

- `enigmagent_resolve`: returns a value only when the requested origin matches
  the entry's domain binding.

The origin is normalized and limited to HTTP(S) URLs without embedded user
credentials. Notifications, malformed JSON, oversized frames, invalid tool
arguments, and calls before initialization are handled without terminating the
process.

## Authenticated REST

```bash
set ENIGMAGENT_API_TOKEN=use-a-random-32-character-token-or-longer
npx enigmagent-mcp@2.0.0 --mode rest --port 3737 --vault ./my.vault.json
```

`GET /health` is a minimal unauthenticated liveness check. `GET /status` and
`GET /list` require `Authorization: Bearer <token>`. `POST /resolve` also
requires the token, JSON content type, and the explicit raw-resolution flag.
The service rejects browser-origin requests and binds only to loopback.

## Client configuration adapters

`integrations.js` provides tested configuration builders for Claude Desktop,
Cursor, Continue, Cline, Open WebUI, AnythingLLM, LM Studio, Zed, Goose, and
Windsurf. They are maintained configuration examples using the standard MCP
stdio command; they are not upstream plugins, endorsements, or claims of
adoption by those projects.

## Development and verification

```bash
npm ci
npm test
npm run check
npm run benchmark
npm pack --dry-run
```

The tests cover encrypted-at-rest behavior, domain matching, wrong credentials,
version-1 migration reads, backup recovery, bounded MCP framing and session
ordering, authenticated REST, and all ten configuration adapters. The benchmark
uses synthetic data and reports create/add/resolve latency without printing a
secret.

## Release contents

The historical 1.0.5 tree is preserved in `versions/1.0.5/` with its source
archive and SHA-256 manifest. The 2.0.0 release is represented consistently in
`package.json`, `server.json`, and `manifest.json`; publication remains subject
to the repository's CI and release checks.

## Scope and threat model

This project protects vault contents from ordinary plaintext-at-rest exposure
and from accidental return by the metadata listing tool. It does not protect
against a compromised operating system, a process with access to the unlocked
memory, malicious client code, side channels, swap/core dumps, or an operator
who explicitly enables raw resolution for an untrusted model. Review
`SECURITY.md` in the main EnigmAgent project for broader ecosystem guidance.

MIT licensed. See [LICENSE](LICENSE).
