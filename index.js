#!/usr/bin/env node
/** EnigmAgent MCP 2.0.0 command-line entry point. */

import { createInterface } from 'node:readline';
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';
import { FileStorage, VaultManager } from './vault-secure.js';
import { createMcpHandler, serveMcpStdio } from './mcp-server.js';
import { createRestServer, validateApiToken } from './rest-server.js';

function argument(args, name, fallback = null) {
  const index = args.indexOf(name);
  return index < 0 ? fallback : args[index + 1] ?? fallback;
}

export function parseCli(args) {
  const mode = argument(args, '--mode', 'mcp');
  const port = Number(argument(args, '--port', '3737'));
  const vaultPath = process.env.ENIGMAGENT_VAULT || argument(args, '--vault', './enigmagent-vault.json');
  const allowRawResolve = args.includes('--allow-raw-resolve') || process.env.ENIGMAGENT_ALLOW_RAW_RESOLVE === '1';
  const token = process.env.ENIGMAGENT_API_TOKEN || argument(args, '--auth-token', null);
  if (!['mcp', 'rest'].includes(mode)) throw new Error('mode must be mcp or rest');
  if (!Number.isInteger(port) || port < 1 || port > 65_535) throw new Error('port must be between 1 and 65535');
  return { mode, port, vaultPath: resolve(vaultPath), allowRawResolve, token };
}

async function promptCredentials() {
  const rl = createInterface({ input: process.stdin, output: process.stderr });
  const ask = question => new Promise(resolveAnswer => rl.question(question, resolveAnswer));
  try {
    const username = process.env.ENIGMAGENT_USER || await ask('Username: ');
    const password = process.env.ENIGMAGENT_PASS || await ask('Password: ');
    return { username, password };
  } finally {
    rl.close();
  }
}

async function unlockIfConfigured(vault) {
  if (process.env.ENIGMAGENT_USER && process.env.ENIGMAGENT_PASS) {
    await vault.unlock(process.env.ENIGMAGENT_USER, process.env.ENIGMAGENT_PASS);
    return true;
  }
  if (!process.stdin.isTTY) {
    process.stderr.write('[EnigmAgent MCP] Locked mode: provide ENIGMAGENT_USER and ENIGMAGENT_PASS in a trusted environment to unlock.\n');
    return false;
  }
  const credentials = await promptCredentials();
  await vault.unlock(credentials.username, credentials.password);
  return true;
}

async function runMcp(vault, allowRawResolve) {
  const handler = createMcpHandler({ vault, allowRawResolve });
  await serveMcpStdio({ input: process.stdin, output: process.stdout, handler });
  vault.lock();
}

async function runRest(vault, options) {
  if (!options.token) throw new Error('REST mode requires ENIGMAGENT_API_TOKEN or --auth-token; use at least 32 random URL-safe characters.');
  const server = createRestServer({ vault, token: validateApiToken(options.token), allowRawResolve: options.allowRawResolve });
  await new Promise((resolveServer, reject) => {
    server.once('error', reject);
    server.listen(options.port, '127.0.0.1', () => {
      server.removeListener('error', reject);
      process.stderr.write(`[EnigmAgent REST] Listening on http://127.0.0.1:${options.port}\n`);
      process.stderr.write('[EnigmAgent REST] /health is public; /status and /list require Bearer authentication; /resolve is opt-in.\n');
      resolveServer();
    });
  });
  const shutdown = () => { vault.lock(); server.close(() => process.exit(0)); };
  process.once('SIGINT', shutdown);
  process.once('SIGTERM', shutdown);
}

export async function main(args = process.argv.slice(2)) {
  const options = parseCli(args);
  const vault = new VaultManager(new FileStorage(options.vaultPath));
  process.stderr.write(`[EnigmAgent MCP] Vault: ${options.vaultPath}\n`);
  await unlockIfConfigured(vault);
  if (options.mode === 'rest') await runRest(vault, options);
  else await runMcp(vault, options.allowRawResolve);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch(error => {
    process.stderr.write(`[EnigmAgent MCP] Fatal: ${error?.code || 'startup_error'}\n`);
    process.exitCode = 1;
  });
}
