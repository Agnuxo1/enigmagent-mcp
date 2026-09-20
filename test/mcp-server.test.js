import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Readable, Writable } from 'node:stream';
import { MemoryStorage, VaultManager } from '../vault-secure.js';
import { createMcpHandler, serveMcpStdio } from '../mcp-server.js';

async function readyVault() {
  const vault = new VaultManager(new MemoryStorage());
  await vault.create('mcp-user', 'mcp-password');
  await vault.addSecret({ name: 'KEY', domain: 'example.com', value: 'synthetic-secret' });
  return vault;
}

async function handshake(handler) {
  const initialized = await handler({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'test', version: '1' } } });
  assert.equal(initialized.result.serverInfo.version, '2.0.0');
  assert.equal(await handler({ jsonrpc: '2.0', method: 'notifications/initialized' }), null);
}

test('MCP defaults to metadata-only and validates session order', async () => {
  const handler = createMcpHandler({ vault: await readyVault() });
  const before = await handler({ jsonrpc: '2.0', id: 1, method: 'tools/list' });
  assert.equal(before.error.code, -32002);
  await handshake(handler);
  const listed = await handler({ jsonrpc: '2.0', id: 2, method: 'tools/list' });
  assert.deepEqual(listed.result.tools.map(tool => tool.name), ['enigmagent_list']);
  const raw = await handler({ jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'enigmagent_resolve', arguments: { placeholder: 'KEY', origin: 'https://example.com' } } });
  assert.equal(raw.result.isError, true);
  assert.equal(raw.result.content[0].text, 'raw_resolve_disabled');
  const metadata = await handler({ jsonrpc: '2.0', id: 4, method: 'tools/call', params: { name: 'enigmagent_list', arguments: {} } });
  assert.equal(metadata.result.content[0].text.includes('synthetic-secret'), false);
});

test('raw resolution is explicit and remains domain-bound', async () => {
  const handler = createMcpHandler({ vault: await readyVault(), allowRawResolve: true });
  await handshake(handler);
  const response = await handler({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'enigmagent_resolve', arguments: { placeholder: 'KEY', origin: 'https://not-example.com' } } });
  assert.equal(response.result.isError, true);
  assert.equal(response.result.content[0].text, 'domain_mismatch');
});

test('stdio transport handles malformed and oversized frames without crashing', async () => {
  const output = [];
  const writable = new Writable({ write(chunk, _encoding, callback) { output.push(chunk.toString()); callback(); } });
  const input = Readable.from(['not-json\n', `${JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'ping' })}\n`]);
  const completed = await serveMcpStdio({ input, output: writable, handler: async request => ({ jsonrpc: '2.0', id: request.id, result: {} }), maxMessageBytes: 100 });
  assert.equal(completed, true);
  assert.equal(JSON.parse(output[0]).error.code, -32700);
  assert.equal(JSON.parse(output[1]).id, 1);
  const oversized = [];
  const smallOutput = new Writable({ write(chunk, _encoding, callback) { oversized.push(chunk.toString()); callback(); } });
  await serveMcpStdio({ input: Readable.from([`${'x'.repeat(120)}\n`]), output: smallOutput, handler: async () => null, maxMessageBytes: 20 });
  assert.equal(JSON.parse(oversized[0]).error.message, 'Message too large');
});
