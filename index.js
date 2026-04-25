#!/usr/bin/env node
/**
 * EnigmAgent MCP Server
 *
 * Exposes the EnigmAgent vault as:
 *   1. An MCP (Model Context Protocol) stdio server — for Open WebUI, AnythingLLM, LM Studio, etc.
 *   2. A local REST API on http://localhost:PORT — for custom integrations
 *
 * The vault must be unlocked before resolution. The master key lives in
 * process memory only and is cleared when the server stops.
 *
 * Usage:
 *   # Start MCP server (stdio, for LLM tool use)
 *   enigmagent-mcp --vault ./my.vault.json
 *
 *   # Start REST API server
 *   enigmagent-mcp --mode rest --port 3737 --vault ./my.vault.json
 *
 * Environment variables:
 *   ENIGMAGENT_VAULT   Path to vault file (overrides --vault)
 *   ENIGMAGENT_USER    Username (skips interactive prompt)
 *   ENIGMAGENT_PASS    Password (skips interactive prompt — use only in secure envs)
 *
 * MCP tools exposed:
 *   enigmagent_resolve  — resolve a {{PLACEHOLDER}} to its real value
 *   enigmagent_list     — list secret names and domains (no values)
 */

import { createServer }    from 'node:http';
import { resolve }         from 'node:path';
import { createInterface } from 'node:readline';
import { argon2id as argon2idHash } from '@noble/hashes/argon2';

// ── vault-core (inlined) ─────────────────────────────────────────────────────

const VAULT_VERSION = 1;
const ARGON2_PARAMS = { t: 3, m: 65536, p: 1, dkLen: 32 };
const SALT_BYTES    = 16;
const NONCE_BYTES   = 12;

const enc = new TextEncoder();
const dec = new TextDecoder();

const b64 = {
  enc: (buf) => Buffer.from(buf instanceof Uint8Array ? buf : new Uint8Array(buf)).toString('base64'),
  dec: (s)   => new Uint8Array(Buffer.from(s, 'base64')),
};

function randomBytes(n) {
  const buf = new Uint8Array(n);
  crypto.getRandomValues(buf);
  return buf;
}

function newUUID() { return crypto.randomUUID(); }

async function deriveKey(password, username, saltBytes) {
  const ctx    = enc.encode(`enigma/v1|${username}`);
  const salted = new Uint8Array(saltBytes.length + ctx.length);
  salted.set(saltBytes, 0); salted.set(ctx, saltBytes.length);
  const raw = argon2idHash(enc.encode(password), salted, ARGON2_PARAMS);
  return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

async function encryptString(key, plaintext) {
  const nonce = randomBytes(NONCE_BYTES);
  const ct    = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, key, enc.encode(plaintext));
  return { nonce: b64.enc(nonce), ciphertext: b64.enc(ct) };
}

async function decryptString(key, nonceB64, ctB64) {
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64.dec(nonceB64) }, key, b64.dec(ctB64));
  return dec.decode(pt);
}

function originMatches(origin, domain) {
  try {
    const host = new URL(origin).hostname.toLowerCase();
    const d    = domain.toLowerCase();
    return host === d || host.endsWith('.' + d);
  } catch { return false; }
}

class VaultManager {
  constructor(storageAdapter) {
    this._storage  = storageAdapter || new MemoryStorage();
    this.key       = null;
    this.username  = null;
    this.vault     = null;
  }

  get isUnlocked() { return this.key !== null; }
  _requireUnlocked() { if (!this.key) throw new Error('vault_locked'); }

  async _load() { return this._storage.load(); }
  async _save() { return this._storage.save(this.vault); }

  async create(username, password) {
    const salt  = randomBytes(SALT_BYTES);
    const key   = await deriveKey(password, username, salt);
    this.key = key; this.username = username;
    this.vault = { version: VAULT_VERSION, kdf: 'argon2id', kdf_params: { ...ARGON2_PARAMS },
                   salt: b64.enc(salt), check: null, entries: [] };
    this.vault.check = await encryptString(key, `enigmagent-check|${username}`);
    await this._save();
  }

  async unlock(username, password, vaultData) {
    const vault = vaultData || await this._load();
    if (!vault) throw new Error('No vault found. Create one first with: enigmagent create');
    if (vault.kdf && vault.kdf !== 'argon2id') throw new Error(`Unsupported KDF: ${vault.kdf}`);
    const key = await deriveKey(password, username, b64.dec(vault.salt));
    if (vault.check) {
      try {
        const pt = await decryptString(key, vault.check.nonce, vault.check.ciphertext);
        if (pt !== `enigmagent-check|${username}`) throw new Error('mismatch');
      } catch { throw new Error('Wrong username or password.'); }
    } else if (vault.entries.length > 0) {
      try { await decryptString(key, vault.entries[0].nonce, vault.entries[0].ciphertext); }
      catch { throw new Error('Wrong username or password.'); }
    }
    this.key = key; this.username = username; this.vault = vault;
    if (vaultData) await this._save();
  }

  lock() { this.key = null; this.username = null; this.vault = null; }

  async addSecret({ name, domain, value }) {
    this._requireUnlocked();
    if (!name) throw new Error('Name is required.');
    if (!/^[A-Z0-9_:\-.@]+$/i.test(name)) throw new Error('Invalid secret name: use A-Z 0-9 _ : - . @');
    if (this.vault.entries.some(e => e.name.toLowerCase() === name.toLowerCase()))
      throw new Error(`Secret "${name}" already exists.`);
    const { nonce, ciphertext } = await encryptString(this.key, value || '');
    const entry = { id: newUUID(), name, domain: domain || null,
                    created: new Date().toISOString(), nonce, ciphertext };
    this.vault.entries.push(entry);
    await this._save();
    return entry;
  }

  async updateSecret(id, patch) {
    this._requireUnlocked();
    const e = this.vault.entries.find(x => x.id === id);
    if (!e) throw new Error('not_found');
    if (patch.name   !== undefined) e.name   = patch.name;
    if (patch.domain !== undefined) e.domain = patch.domain || null;
    if (patch.value  !== undefined) {
      const { nonce, ciphertext } = await encryptString(this.key, patch.value);
      e.nonce = nonce; e.ciphertext = ciphertext;
    }
    await this._save();
  }

  async deleteSecret(id) {
    this._requireUnlocked();
    this.vault.entries = this.vault.entries.filter(e => e.id !== id);
    await this._save();
  }

  async revealSecret(id) {
    this._requireUnlocked();
    const e = this.vault.entries.find(x => x.id === id);
    if (!e) throw new Error('not_found');
    return decryptString(this.key, e.nonce, e.ciphertext);
  }

  findByName(name) {
    this._requireUnlocked();
    const lower = name.toLowerCase();
    if (lower.startsWith('login:')) {
      const dom = lower.slice(6);
      return this.vault.entries.find(e => e.domain?.toLowerCase() === dom) || null;
    }
    if (lower.startsWith('doc:')) {
      const raw     = name.slice(4).replace(/[^A-Za-z0-9_.\-]/g, '_');
      const docName = 'DOC_' + raw;
      return this.vault.entries.find(e => e.name.toLowerCase() === docName.toLowerCase()) || null;
    }
    return this.vault.entries.find(e => e.name.toLowerCase() === lower) || null;
  }

  async resolve(placeholder, origin) {
    this._requireUnlocked();
    const entry = this.findByName(placeholder);
    if (!entry)        throw Object.assign(new Error('not_found'),         { code: 'not_found',         placeholder });
    if (!entry.domain) throw Object.assign(new Error('no_domain_binding'), { code: 'no_domain_binding', placeholder });
    if (!originMatches(origin, entry.domain)) {
      throw Object.assign(new Error(`domain_mismatch: bound to ${entry.domain}`),
        { code: 'domain_mismatch', expected: entry.domain, placeholder });
    }
    return this.revealSecret(entry.id);
  }

  list() {
    this._requireUnlocked();
    return this.vault.entries.map(({ id, name, domain, created }) => ({ id, name, domain, created }));
  }
}

class FileStorage {
  constructor(vaultPath) { this.path = vaultPath; }
  async load() {
    const { existsSync, readFileSync } = await import('node:fs');
    if (!existsSync(this.path)) return null;
    try { return JSON.parse(readFileSync(this.path, 'utf8')); } catch { return null; }
  }
  async save(vault) {
    const { writeFileSync, mkdirSync } = await import('node:fs');
    const { resolve: res, dirname }    = await import('node:path');
    mkdirSync(dirname(res(this.path)), { recursive: true });
    writeFileSync(this.path, JSON.stringify(vault, null, 2), 'utf8');
  }
}

class MemoryStorage {
  constructor(initialVault) { this._vault = initialVault || null; }
  async load() { return this._vault; }
  async save(vault) { this._vault = vault; }
}

// ── CLI argument parsing ──────────────────────────────────────────────────────

const args = process.argv.slice(2);
const getArg = (flag, fallback = null) => {
  const i = args.indexOf(flag);
  return i !== -1 ? args[i + 1] : fallback;
};

const MODE       = getArg('--mode', 'mcp');
const PORT       = parseInt(getArg('--port', '3737'), 10);
const VAULT_PATH = process.env.ENIGMAGENT_VAULT || getArg('--vault', './enigmagent-vault.json');

if (!VAULT_PATH) {
  console.error('Usage: enigmagent-mcp --vault <path> [--mode mcp|rest] [--port 3737]');
  process.exit(1);
}

// ── Vault unlock ─────────────────────────────────────────────────────────────

const vault = new VaultManager(new FileStorage(resolve(VAULT_PATH)));

async function promptCredentials() {
  if (process.env.ENIGMAGENT_USER && process.env.ENIGMAGENT_PASS) {
    return { username: process.env.ENIGMAGENT_USER, password: process.env.ENIGMAGENT_PASS };
  }
  const rl = createInterface({ input: process.stdin, output: process.stderr });
  const ask = (q) => new Promise((res) => rl.question(q, res));
  const username = process.env.ENIGMAGENT_USER || await ask('Username: ');
  const password = process.env.ENIGMAGENT_PASS || await ask('Password: ');
  rl.close();
  return { username, password };
}

// ── MCP protocol (stdio, JSON-RPC 2.0) ───────────────────────────────────────

function mcpResponse(id, result) {
  return JSON.stringify({ jsonrpc: '2.0', id, result }) + '\n';
}
function mcpError(id, code, message, data) {
  return JSON.stringify({ jsonrpc: '2.0', id, error: { code, message, data } }) + '\n';
}

const MCP_TOOLS = [
  {
    name:        'enigmagent_resolve',
    description: 'Resolve a secret placeholder from the EnigmAgent vault. Returns the decrypted value. Domain binding is enforced: the origin must match the secret\'s bound domain.',
    inputSchema: {
      type: 'object',
      required: ['placeholder', 'origin'],
      properties: {
        placeholder: {
          type: 'string',
          description: 'The secret name to resolve. Supports {{NAME}}, {{LOGIN:domain}}, {{DOC:filename}} syntax (pass without the braces).',
        },
        origin: {
          type: 'string',
          description: 'The requesting origin URL (e.g. https://api.example.com). Must match the secret\'s domain binding.',
        },
      },
    },
  },
  {
    name:        'enigmagent_list',
    description: 'List all secret names and their bound domains. Never returns actual secret values.',
    inputSchema: { type: 'object', properties: {} },
  },
];

async function handleMcpRequest(line) {
  let req;
  try { req = JSON.parse(line); } catch { return null; }
  const { id, method, params } = req;

  if (method === 'initialize') {
    return mcpResponse(id, {
      protocolVersion: '2024-11-05',
      capabilities: { tools: {} },
      serverInfo: { name: 'enigmagent', version: '0.2.0' },
    });
  }
  if (method === 'tools/list') return mcpResponse(id, { tools: MCP_TOOLS });
  if (method === 'tools/call') {
    const { name, arguments: toolArgs } = params || {};
    try {
      if (name === 'enigmagent_resolve') {
        const value = await vault.resolve(toolArgs.placeholder, toolArgs.origin);
        return mcpResponse(id, { content: [{ type: 'text', text: value }] });
      }
      if (name === 'enigmagent_list') {
        const entries = vault.list();
        const text = entries.map(e => `${e.name.padEnd(28)} ${e.domain ? '@' + e.domain : '(unbound)'}`).join('\n');
        return mcpResponse(id, { content: [{ type: 'text', text: text || '(no secrets)' }] });
      }
      return mcpError(id, -32601, `Unknown tool: ${name}`);
    } catch (err) {
      return mcpResponse(id, { content: [{ type: 'text', text: `Error: ${err.message}` }], isError: true });
    }
  }
  if (method === 'ping') return mcpResponse(id, {});
  return mcpError(id, -32601, `Method not found: ${method}`);
}

function startMcpMode() {
  process.stderr.write(`[EnigmAgent MCP] Vault unlocked. Listening on stdin (JSON-RPC 2.0 / MCP).\n`);
  const rl = createInterface({ input: process.stdin });
  rl.on('line', async (line) => {
    if (!line.trim()) return;
    const response = await handleMcpRequest(line);
    if (response) process.stdout.write(response);
  });
  rl.on('close', () => { vault.lock(); process.exit(0); });
}

// ── REST API ──────────────────────────────────────────────────────────────────

function cors(res) {
  res.setHeader('Access-Control-Allow-Origin', '127.0.0.1');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
}

function json(res, code, data) {
  cors(res);
  res.writeHead(code, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(data));
}

function startRestMode() {
  const server = createServer(async (req, res) => {
    cors(res);
    if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }
    const url = new URL(req.url, `http://localhost:${PORT}`);

    if (req.method === 'GET' && url.pathname === '/status')
      return json(res, 200, { status: 'ok', unlocked: vault.isUnlocked });

    if (req.method === 'GET' && url.pathname === '/list') {
      if (!vault.isUnlocked) return json(res, 401, { error: 'vault_locked' });
      return json(res, 200, { entries: vault.list() });
    }

    if (req.method === 'POST' && url.pathname === '/resolve') {
      if (!vault.isUnlocked) return json(res, 401, { error: 'vault_locked' });
      let body = '';
      req.on('data', chunk => { body += chunk; });
      req.on('end', async () => {
        try {
          const { placeholder, origin } = JSON.parse(body);
          if (!placeholder) return json(res, 400, { error: 'placeholder is required' });
          if (!origin)      return json(res, 400, { error: 'origin is required' });
          const value = await vault.resolve(placeholder, origin);
          json(res, 200, { value });
        } catch (err) {
          const code = err.code || 'resolve_error';
          json(res, 403, { error: code, message: err.message });
        }
      });
      return;
    }

    json(res, 404, { error: 'not_found' });
  });

  server.listen(PORT, '127.0.0.1', () => {
    console.error(`[EnigmAgent REST] Listening on http://127.0.0.1:${PORT}`);
    console.error(`  GET  /status     — vault health check`);
    console.error(`  GET  /list       — list secret names`);
    console.error(`  POST /resolve    — { "placeholder": "NAME", "origin": "https://..." }`);
  });

  process.on('SIGINT',  () => { vault.lock(); server.close(() => process.exit(0)); });
  process.on('SIGTERM', () => { vault.lock(); server.close(() => process.exit(0)); });
}

// ── Main ──────────────────────────────────────────────────────────────────────

(async () => {
  try {
    process.stderr.write(`[EnigmAgent MCP] Vault: ${resolve(VAULT_PATH)}\n`);
    const { username, password } = await promptCredentials();
    process.stderr.write(`[EnigmAgent MCP] Unlocking vault (Argon2id — takes ~2s)…\n`);
    await vault.unlock(username, password);
    process.stderr.write(`[EnigmAgent MCP] Vault unlocked for: ${username}\n`);

    if (MODE === 'rest') {
      startRestMode();
    } else {
      startMcpMode();
    }
  } catch (err) {
    process.stderr.write(`[EnigmAgent MCP] Fatal: ${err.message}\n`);
    process.exit(1);
  }
})();
