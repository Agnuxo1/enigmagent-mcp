import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  ARGON2_PARAMS, FileStorage, MemoryStorage, VaultManager, b64, deriveKey, encryptString,
  originMatches, validateVault,
} from '../vault-secure.js';

describe('vault core', () => {
  test('creates, encrypts, lists metadata, and resolves only matching domains', async () => {
    const storage = new MemoryStorage();
    const vault = new VaultManager(storage);
    await vault.create('test-user', 'synthetic-password');
    await vault.addSecret({ name: 'GITHUB_TOKEN', domain: 'api.github.com', value: 'synthetic-secret' });
    await vault.addSecret({ name: 'UNBOUND', value: 'not-resolvable' });
    assert.equal(vault.formatVersion, 2);
    assert.deepEqual(vault.list().map(item => item.name), ['GITHUB_TOKEN', 'UNBOUND']);
    assert.equal(Object.hasOwn(vault.list()[0], 'ciphertext'), false);
    assert.equal(await vault.resolve('GITHUB_TOKEN', 'https://api.github.com/v1'), 'synthetic-secret');
    assert.equal(await vault.resolve('GITHUB_TOKEN', 'https://sub.api.github.com'), 'synthetic-secret');
    await assert.rejects(() => vault.resolve('GITHUB_TOKEN', 'https://github.com'), error => error.code === 'domain_mismatch');
    await assert.rejects(() => vault.resolve('UNBOUND', 'https://api.github.com'), error => error.code === 'no_domain_binding');
    const saved = JSON.stringify(await storage.load());
    assert.equal(saved.includes('synthetic-secret'), false);
  });

  test('rejects wrong credentials, malformed origins, and duplicate names', async () => {
    const storage = new MemoryStorage();
    const original = new VaultManager(storage);
    await original.create('alice', 'password');
    await original.addSecret({ name: 'KEY', domain: 'example.com', value: 'value' });
    const locked = new VaultManager(storage);
    await assert.rejects(() => locked.unlock('alice', 'wrong'), error => error.code === 'wrong_credentials');
    assert.equal(originMatches('javascript:alert(1)', 'example.com'), false);
    assert.equal(originMatches('https://user:pass@example.com', 'example.com'), false);
    await assert.rejects(() => original.addSecret({ name: 'key', domain: 'example.com', value: 'other' }), error => error.code === 'duplicate_secret');
    await assert.rejects(() => original.addSecret({ name: 'bad name', value: 'x' }), error => error.code === 'invalid_secret_name');
  });

  test('supports the version-1 derivation context for migration reads', async () => {
    const salt = new Uint8Array(16).fill(7);
    const key = await deriveKey('legacy-password', 'legacy-user', salt, 1);
    const check = await encryptString(key, 'enigmagent-check|legacy-user');
    const legacy = { version: 1, kdf: 'argon2id', kdf_params: { ...ARGON2_PARAMS }, salt: b64.enc(salt), check, entries: [] };
    validateVault(legacy);
    const manager = new VaultManager(new MemoryStorage(legacy));
    await manager.unlock('legacy-user', 'legacy-password');
    assert.equal(manager.formatVersion, 1);
  });

  test('recovers a valid backup when the primary file is damaged', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'enigmagent-test-'));
    const path = join(directory, 'vault.json');
    const storage = new FileStorage(path);
    const manager = new VaultManager(storage);
    await manager.create('backup-user', 'backup-password');
    const valid = await readFile(path, 'utf8');
    await writeFile(`${path}.bak`, valid, 'utf8');
    await writeFile(path, '{broken', 'utf8');
    const recovered = await storage.load();
    assert.equal(recovered.version, 2);
    assert.equal(recovered.entries.length, 0);
  });
});
