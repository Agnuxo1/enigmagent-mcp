/**
 * EnigmAgent MCP vault core.
 *
 * This module has no network or agent-protocol dependencies. It owns the
 * encrypted file format, validation, domain matching, and durable storage.
 */

import { copyFile, mkdir, open, readFile, rename, rm, stat } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { randomBytes as secureRandomBytes, randomUUID, webcrypto } from 'node:crypto';
import { argon2id as argon2idHash } from '@noble/hashes/argon2';

export const VAULT_VERSION = 2;
export const SUPPORTED_VAULT_VERSIONS = Object.freeze([1, 2]);
export const ARGON2_PARAMS = Object.freeze({ t: 3, m: 65536, p: 1, dkLen: 32 });
export const MAX_MESSAGE_BYTES = 16 * 1024;
export const MAX_SECRET_VALUE_BYTES = 1024 * 1024;
export const MAX_ENTRIES = 10_000;
export const MAX_NAME_LENGTH = 128;
export const MAX_DOMAIN_LENGTH = 253;

const SALT_BYTES = 16;
const NONCE_BYTES = 12;
const enc = new TextEncoder();
const dec = new TextDecoder('utf-8', { fatal: true });
const subtle = webcrypto.subtle;

export const b64 = {
  enc: value => Buffer.from(value instanceof Uint8Array ? value : new Uint8Array(value)).toString('base64'),
  dec: value => new Uint8Array(Buffer.from(value, 'base64')),
};

export function randomBytes(size) { return new Uint8Array(secureRandomBytes(size)); }
export function newUUID() { return randomUUID(); }

function formatError(code, message = code) { return Object.assign(new Error(message), { code }); }
function contextForVersion(version) { return version === 1 ? 'enigma/v1' : 'enigma/v2'; }

export async function deriveKey(password, username, saltBytes, version = VAULT_VERSION) {
  if (typeof password !== 'string' || password.length === 0) throw formatError('invalid_credentials');
  if (typeof username !== 'string' || username.length === 0 || username.length > 128) throw formatError('invalid_username');
  if (!(saltBytes instanceof Uint8Array) || saltBytes.length < 16 || saltBytes.length > 64) throw formatError('invalid_vault');
  const context = enc.encode(`${contextForVersion(version)}|${username}`);
  const salted = new Uint8Array(saltBytes.length + context.length);
  salted.set(saltBytes, 0); salted.set(context, saltBytes.length);
  const raw = argon2idHash(enc.encode(password), salted, ARGON2_PARAMS);
  return subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

export async function encryptString(key, plaintext) {
  if (typeof plaintext !== 'string') throw formatError('invalid_secret');
  if (Buffer.byteLength(plaintext, 'utf8') > MAX_SECRET_VALUE_BYTES) throw formatError('secret_too_large');
  const nonce = randomBytes(NONCE_BYTES);
  const ciphertext = await subtle.encrypt({ name: 'AES-GCM', iv: nonce }, key, enc.encode(plaintext));
  return { nonce: b64.enc(nonce), ciphertext: b64.enc(ciphertext) };
}

export async function decryptString(key, nonceB64, ciphertextB64) {
  try {
    const plaintext = await subtle.decrypt({ name: 'AES-GCM', iv: b64.dec(nonceB64) }, key, b64.dec(ciphertextB64));
    return dec.decode(plaintext);
  } catch { throw formatError('decryption_failed'); }
}

export function originMatches(origin, domain) {
  if (typeof origin !== 'string' || typeof domain !== 'string') return false;
  try {
    const url = new URL(origin);
    const host = url.hostname.toLowerCase();
    const expected = domain.toLowerCase();
    if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) return false;
    return host === expected || host.endsWith(`.${expected}`);
  } catch { return false; }
}

export function normaliseName(name) {
  if (typeof name !== 'string' || name.length < 1 || name.length > MAX_NAME_LENGTH || !/^[A-Za-z0-9_:.@-]+$/.test(name)) {
    throw formatError('invalid_secret_name');
  }
  return name;
}

export function normaliseDomain(domain) {
  if (domain === undefined || domain === null || domain === '') return null;
  if (typeof domain !== 'string' || domain.length > MAX_DOMAIN_LENGTH ||
      !/^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/.test(domain)) {
    throw formatError('invalid_domain');
  }
  return domain.toLowerCase();
}

function validateEntry(entry) {
  if (!entry || typeof entry !== 'object' || typeof entry.id !== 'string') throw formatError('invalid_vault');
  normaliseName(entry.name);
  normaliseDomain(entry.domain);
  if (typeof entry.created !== 'string' || typeof entry.nonce !== 'string' || typeof entry.ciphertext !== 'string') throw formatError('invalid_vault');
}

export function validateVault(vault) {
  if (!vault || typeof vault !== 'object' || !SUPPORTED_VAULT_VERSIONS.includes(vault.version) ||
      vault.kdf !== 'argon2id' || typeof vault.salt !== 'string' || !Array.isArray(vault.entries) || vault.entries.length > MAX_ENTRIES) {
    throw formatError('invalid_vault');
  }
  const salt = b64.dec(vault.salt);
  if (salt.length < 16 || salt.length > 64) throw formatError('invalid_vault');
  if (vault.check !== null && (!vault.check || typeof vault.check.nonce !== 'string' || typeof vault.check.ciphertext !== 'string')) throw formatError('invalid_vault');
  const seen = new Set();
  for (const entry of vault.entries) {
    validateEntry(entry);
    const lower = entry.name.toLowerCase();
    if (seen.has(lower)) throw formatError('invalid_vault');
    seen.add(lower);
  }
  return vault;
}

export class VaultManager {
  constructor(storageAdapter = new MemoryStorage()) {
    this._storage = storageAdapter;
    this.key = null;
    this.username = null;
    this.vault = null;
  }
  get isUnlocked() { return this.key !== null; }
  get formatVersion() { return this.vault?.version ?? null; }
  _requireUnlocked() { if (!this.key || !this.vault) throw formatError('vault_locked'); }
  async _load() { return this._storage.load(); }
  async _save() { return this._storage.save(this.vault); }

  async create(username, password) {
    const salt = randomBytes(SALT_BYTES);
    const key = await deriveKey(password, username, salt, VAULT_VERSION);
    this.key = key;
    this.username = username;
    this.vault = { version: VAULT_VERSION, kdf: 'argon2id', kdf_params: { ...ARGON2_PARAMS }, kdf_context: contextForVersion(VAULT_VERSION), salt: b64.enc(salt), check: null, entries: [] };
    this.vault.check = await encryptString(key, `enigmagent-check|${username}`);
    await this._save();
  }

  async unlock(username, password, vaultData = null) {
    const loaded = vaultData ?? await this._load();
    const vault = validateVault(loaded);
    const key = await deriveKey(password, username, b64.dec(vault.salt), vault.version);
    try {
      if (vault.check) {
        const check = await decryptString(key, vault.check.nonce, vault.check.ciphertext);
        if (check !== `enigmagent-check|${username}`) throw formatError('wrong_credentials');
      } else if (vault.entries.length > 0) await decryptString(key, vault.entries[0].nonce, vault.entries[0].ciphertext);
    } catch { throw formatError('wrong_credentials'); }
    this.key = key;
    this.username = username;
    this.vault = vault;
  }

  lock() { this.key = null; this.username = null; this.vault = null; }

  async addSecret({ name, domain, value }) {
    this._requireUnlocked();
    const cleanName = normaliseName(name);
    const cleanDomain = normaliseDomain(domain);
    if (typeof value !== 'string') throw formatError('invalid_secret');
    if (this.vault.entries.some(entry => entry.name.toLowerCase() === cleanName.toLowerCase())) throw formatError('duplicate_secret');
    if (this.vault.entries.length >= MAX_ENTRIES) throw formatError('too_many_entries');
    const encrypted = await encryptString(this.key, value);
    const entry = { id: newUUID(), name: cleanName, domain: cleanDomain, created: new Date().toISOString(), ...encrypted };
    this.vault.entries = [...this.vault.entries, entry];
    await this._save();
    return { ...entry };
  }

  async updateSecret(id, patch) {
    this._requireUnlocked();
    const current = this.vault.entries.find(entry => entry.id === id);
    if (!current) throw formatError('not_found');
    const nextName = patch.name === undefined ? current.name : normaliseName(patch.name);
    const nextDomain = patch.domain === undefined ? current.domain : normaliseDomain(patch.domain);
    if (this.vault.entries.some(entry => entry.id !== id && entry.name.toLowerCase() === nextName.toLowerCase())) throw formatError('duplicate_secret');
    let encrypted = { nonce: current.nonce, ciphertext: current.ciphertext };
    if (patch.value !== undefined) encrypted = await encryptString(this.key, patch.value);
    this.vault.entries = this.vault.entries.map(entry => entry.id === id ? { ...entry, name: nextName, domain: nextDomain, ...encrypted } : entry);
    await this._save();
  }

  async deleteSecret(id) {
    this._requireUnlocked();
    const before = this.vault.entries.length;
    this.vault.entries = this.vault.entries.filter(entry => entry.id !== id);
    if (before === this.vault.entries.length) throw formatError('not_found');
    await this._save();
  }

  async revealSecret(id) {
    this._requireUnlocked();
    const entry = this.vault.entries.find(item => item.id === id);
    if (!entry) throw formatError('not_found');
    return decryptString(this.key, entry.nonce, entry.ciphertext);
  }

  findByName(name) {
    this._requireUnlocked();
    if (typeof name !== 'string' || name.length === 0 || name.length > MAX_NAME_LENGTH) throw formatError('invalid_arguments');
    const lower = name.toLowerCase();
    if (lower.startsWith('login:')) {
      const domain = normaliseDomain(lower.slice(6));
      return this.vault.entries.find(entry => entry.domain === domain) ?? null;
    }
    if (lower.startsWith('doc:')) {
      const safe = name.slice(4).replace(/[^A-Za-z0-9_.-]/g, '_');
      return this.vault.entries.find(entry => entry.name.toLowerCase() === `doc_${safe}`.toLowerCase()) ?? null;
    }
    return this.vault.entries.find(entry => entry.name.toLowerCase() === lower) ?? null;
  }

  async resolve(placeholder, origin) {
    this._requireUnlocked();
    const entry = this.findByName(placeholder);
    if (!entry) throw Object.assign(formatError('not_found'), { placeholder });
    if (!entry.domain) throw Object.assign(formatError('no_domain_binding'), { placeholder });
    if (!originMatches(origin, entry.domain)) throw Object.assign(formatError('domain_mismatch'), { placeholder, expected: entry.domain });
    return this.revealSecret(entry.id);
  }

  list() {
    this._requireUnlocked();
    return this.vault.entries.map(({ id, name, domain, created }) => ({ id, name, domain, created }));
  }
}

export class FileStorage {
  constructor(vaultPath) { this.path = resolve(vaultPath); }
  async load() {
    const candidates = [this.path, `${this.path}.bak`];
    let lastError = null;
    for (const candidate of candidates) {
      try { return validateVault(JSON.parse(await readFile(candidate, 'utf8'))); } catch (error) { lastError = error; }
    }
    try { await stat(this.path); } catch (error) { if (error.code === 'ENOENT') return null; throw error; }
    throw formatError('invalid_vault', lastError?.message ?? 'Vault is not valid JSON.');
  }
  async save(vault) {
    validateVault(vault);
    const directory = dirname(this.path);
    await mkdir(directory, { recursive: true });
    const temporary = `${this.path}.${process.pid}.${randomUUID()}.tmp`;
    const backup = `${this.path}.bak`;
    const contents = `${JSON.stringify(vault, null, 2)}\n`;
    let handle;
    try {
      handle = await open(temporary, 'wx', 0o600);
      await handle.writeFile(contents, 'utf8');
      await handle.sync();
      await handle.close();
      handle = null;
      try {
        await rename(temporary, this.path);
      } catch (error) {
        if (!['EEXIST', 'EPERM', 'ENOTEMPTY'].includes(error.code)) throw error;
        try { await copyFile(this.path, backup); } catch (copyError) { if (copyError.code !== 'ENOENT') throw copyError; }
        await rm(this.path, { force: true });
        await rename(temporary, this.path);
      }
    } finally {
      if (handle) await handle.close().catch(() => {});
      await rm(temporary, { force: true }).catch(() => {});
    }
  }
}

export class MemoryStorage {
  constructor(initialVault = null) { this._vault = initialVault; }
  async load() { return this._vault; }
  async save(vault) { this._vault = structuredClone(vault); }
}
