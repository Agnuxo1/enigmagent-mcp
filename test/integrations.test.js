import { test } from 'node:test';
import assert from 'node:assert/strict';
import { INTEGRATIONS, buildClientConfig, integrationManifest } from '../integrations.js';

test('all maintained client adapters emit a bounded standard MCP command', () => {
  const ids = Object.keys(INTEGRATIONS);
  assert.equal(ids.length, 10);
  for (const id of ids) {
    const config = buildClientConfig(id, '/tmp/synthetic-vault.json');
    const text = JSON.stringify(config);
    assert.equal(text.includes('synthetic-vault.json'), true);
    assert.equal(text.includes('enigmagent-mcp@2.0.0'), true);
    assert.equal(text.includes('ENIGMAGENT_PASS'), false);
  }
  assert.equal(integrationManifest().length, 10);
});

test('adapter rejects empty or NUL-containing paths', () => {
  assert.throws(() => buildClientConfig('cursor', ''), /vaultPath is required/);
  assert.throws(() => buildClientConfig('cursor', 'bad\0path'), /vaultPath is required/);
  assert.throws(() => buildClientConfig('unknown', './vault.json'), /Unknown integration/);
});
