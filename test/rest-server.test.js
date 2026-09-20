import { test } from 'node:test';
import assert from 'node:assert/strict';
import { MemoryStorage, VaultManager } from '../vault-secure.js';
import { createRestServer } from '../rest-server.js';

const TOKEN = 'synthetic-rest-token-0123456789abcdef';

async function runningServer(options) {
  const vault = new VaultManager(new MemoryStorage());
  await vault.create('rest-user', 'rest-password');
  await vault.addSecret({ name: 'KEY', domain: 'example.com', value: 'synthetic-secret' });
  const server = createRestServer({ vault, token: TOKEN, ...options });
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  const port = server.address().port;
  return { vault, server, url: `http://127.0.0.1:${port}` };
}

test('REST requires bearer authentication and keeps raw resolution disabled by default', async () => {
  const { server, url } = await runningServer({});
  try {
    const health = await fetch(`${url}/health`);
    assert.equal(health.status, 200);
    const unauthenticated = await fetch(`${url}/status`);
    assert.equal(unauthenticated.status, 401);
    const status = await fetch(`${url}/status`, { headers: { Authorization: `Bearer ${TOKEN}` } });
    assert.equal(status.status, 200);
    assert.equal((await status.json()).rawResolveEnabled, false);
    const disabled = await fetch(`${url}/resolve`, { method: 'POST', headers: { Authorization: `Bearer ${TOKEN}` }, body: '{}' });
    assert.equal(disabled.status, 403);
    assert.equal((await disabled.json()).error, 'raw_resolve_disabled');
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
});

test('authenticated opt-in REST resolution validates origin and content type', async () => {
  const { server, url } = await runningServer({ allowRawResolve: true });
  try {
    const invalidType = await fetch(`${url}/resolve`, { method: 'POST', headers: { Authorization: `Bearer ${TOKEN}` }, body: '{}' });
    assert.equal(invalidType.status, 415);
    const resolved = await fetch(`${url}/resolve`, { method: 'POST', headers: { Authorization: `Bearer ${TOKEN}`, 'Content-Type': 'application/json' }, body: JSON.stringify({ placeholder: 'KEY', origin: 'https://example.com/path' }) });
    assert.equal(resolved.status, 200);
    assert.equal((await resolved.json()).value, 'synthetic-secret');
    const denied = await fetch(`${url}/resolve`, { method: 'POST', headers: { Authorization: `Bearer ${TOKEN}`, 'Content-Type': 'application/json' }, body: JSON.stringify({ placeholder: 'KEY', origin: 'https://evil.example' }) });
    assert.equal(denied.status, 403);
    assert.equal((await denied.json()).error, 'domain_mismatch');
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
});
