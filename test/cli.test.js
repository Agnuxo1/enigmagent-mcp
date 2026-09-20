import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { FileStorage, VaultManager } from '../vault-secure.js';

test('published-style CLI starts a locked-by-policy MCP session without leaking values', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'enigmagent-cli-'));
  const vault = new VaultManager(new FileStorage(join(directory, 'vault.json')));
  await vault.create('cli-user', 'cli-password');
  await vault.addSecret({ name: 'KEY', domain: 'example.com', value: 'synthetic-cli-secret' });
  const child = spawn(process.execPath, ['index.js', '--vault', join(directory, 'vault.json')], {
    cwd: process.cwd(),
    env: { ...process.env, ENIGMAGENT_USER: 'cli-user', ENIGMAGENT_PASS: 'cli-password' },
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  const stdout = [];
  const stderr = [];
  child.stdout.on('data', chunk => stdout.push(chunk.toString()));
  child.stderr.on('data', chunk => stderr.push(chunk.toString()));
  child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'cli-test', version: '1' } } })}\n`);
  child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' })}\n`);
  child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'enigmagent_list', arguments: {} } })}\n`);
  child.stdin.end();
  const code = await new Promise(resolve => child.once('close', resolve));
  const output = stdout.join('');
  assert.equal(code, 0);
  assert.equal(output.includes('synthetic-cli-secret'), false);
  assert.equal(output.includes('KEY'), true);
  assert.equal(stderr.join('').includes('cli-password'), false);
});
