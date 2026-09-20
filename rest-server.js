/** Authenticated, bounded local REST transport. This is not MCP over HTTP. */

import { createHash, timingSafeEqual } from 'node:crypto';
import { createServer } from 'node:http';
import { MAX_MESSAGE_BYTES } from './vault-secure.js';
import { SERVER_VERSION } from './mcp-server.js';

const digest = value => createHash('sha256').update(value).digest();
const publicCodes = new Set(['vault_locked', 'not_found', 'no_domain_binding', 'domain_mismatch', 'decryption_failed']);

export function validateApiToken(token) {
  if (typeof token !== 'string' || !/^[A-Za-z0-9_-]{32,256}$/.test(token)) throw new TypeError('API token must be 32-256 URL-safe characters');
  return token;
}

function respond(response, status, value) {
  if (response.destroyed || response.writableEnded) return;
  response.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer', Connection: 'close' });
  response.end(JSON.stringify(value));
}

function headerCount(request, name) {
  let count = 0;
  for (let i = 0; i < request.rawHeaders.length; i += 2) if (request.rawHeaders[i].toLowerCase() === name) count++;
  return count;
}

function readJson(request, limit, timeoutMs) {
  return new Promise((resolve, reject) => {
    let chunks = [], bytes = 0, settled = false;
    const timer = setTimeout(() => finish({ status: 408, code: 'request_timeout' }), timeoutMs);
    const finish = (error, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      request.removeListener('data', onData);
      request.removeListener('end', onEnd);
      chunks = [];
      if (error) { request.resume(); reject(error); } else resolve(value);
    };
    const onData = chunk => {
      bytes += chunk.length;
      if (bytes > limit) finish({ status: 413, code: 'request_too_large' });
      else chunks.push(chunk);
    };
    const onEnd = () => {
      try { finish(null, JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks)))); }
      catch { finish({ status: 400, code: 'invalid_json' }); }
    };
    request.on('data', onData);
    request.on('end', onEnd);
    request.on('aborted', () => finish({ status: 400, code: 'request_aborted' }));
    request.on('error', () => finish({ status: 400, code: 'request_error' }));
  });
}

function validateResolvePayload(payload) {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload) || Object.keys(payload).some(key => !['placeholder', 'origin'].includes(key)) ||
      typeof payload.placeholder !== 'string' || !/^[A-Za-z0-9_:.@-]{1,128}$/.test(payload.placeholder) ||
      typeof payload.origin !== 'string' || payload.origin.length > 2048) throw Object.assign(new Error(), { code: 'invalid_arguments' });
  try {
    const origin = new URL(payload.origin);
    if (!['http:', 'https:'].includes(origin.protocol) || origin.username || origin.password || !origin.hostname) throw new Error();
    return { placeholder: payload.placeholder, origin: origin.origin };
  } catch { throw Object.assign(new Error(), { code: 'invalid_arguments' }); }
}

export function createRestServer({ vault, token, allowRawResolve = false, bodyTimeoutMs = 5000 }) {
  const tokenDigest = digest(validateApiToken(token));
  if (typeof allowRawResolve !== 'boolean' || !Number.isInteger(bodyTimeoutMs) || bodyTimeoutMs < 1 || bodyTimeoutMs > 60_000) throw new TypeError('Invalid REST server options');
  const server = createServer({ maxHeaderSize: 8192 }, async (request, response) => {
    try {
      if (request.method === 'GET' && request.url === '/health') return respond(response, 200, { status: 'ok' });
      const port = server.address()?.port;
      const hosts = new Set([`127.0.0.1:${port}`, `localhost:${port}`]);
      if (headerCount(request, 'host') !== 1 || !hosts.has(String(request.headers.host || '').toLowerCase())) return respond(response, 403, { error: 'invalid_host' });
      if (request.headers.origin !== undefined || request.headers['sec-fetch-site'] === 'cross-site') return respond(response, 403, { error: 'browser_origin_not_allowed' });
      const auth = /^Bearer ([A-Za-z0-9_-]{32,256})$/i.exec(request.headers.authorization || '');
      if (headerCount(request, 'authorization') !== 1 || !auth || !timingSafeEqual(digest(auth[1]), tokenDigest)) return respond(response, 401, { error: 'unauthorized' });
      if (request.url === '/status' && request.method === 'GET') return respond(response, 200, { status: 'ok', unlocked: vault.isUnlocked, version: SERVER_VERSION, rawResolveEnabled: allowRawResolve, vaultFormat: vault.formatVersion });
      if (request.url === '/list' && request.method === 'GET') {
        if (!vault.isUnlocked) return respond(response, 423, { error: 'vault_locked' });
        return respond(response, 200, { entries: vault.list() });
      }
      if (request.url === '/resolve' && request.method === 'POST') {
        if (!allowRawResolve) return respond(response, 403, { error: 'raw_resolve_disabled' });
        if (!vault.isUnlocked) return respond(response, 423, { error: 'vault_locked' });
        if (!/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(request.headers['content-type'] || '') || request.headers['content-encoding'] !== undefined) return respond(response, 415, { error: 'unsupported_media_type' });
        if (Number(request.headers['content-length'] || 0) > MAX_MESSAGE_BYTES) return respond(response, 413, { error: 'request_too_large' });
        let payload;
        try { payload = await readJson(request, MAX_MESSAGE_BYTES, bodyTimeoutMs); } catch (error) { return respond(response, error.status, { error: error.code }); }
        let args;
        try { args = validateResolvePayload(payload); } catch { return respond(response, 400, { error: 'invalid_arguments' }); }
        const value = await vault.resolve(args.placeholder, args.origin);
        return respond(response, 200, { value });
      }
      return respond(response, 404, { error: 'not_found' });
    } catch (error) {
      const code = publicCodes.has(error?.code) ? error.code : 'vault_error';
      const status = code === 'vault_locked' ? 423 : code === 'not_found' ? 404 : code === 'vault_error' ? 500 : 403;
      return respond(response, status, { error: code });
    }
  });
  server.headersTimeout = 10_000;
  server.requestTimeout = 10_000;
  server.timeout = 10_000;
  server.keepAliveTimeout = 1_000;
  server.maxConnections = 32;
  server.maxRequestsPerSocket = 1;
  server.on('clientError', (_error, socket) => socket.writable ? socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n') : socket.destroy());
  return server;
}
