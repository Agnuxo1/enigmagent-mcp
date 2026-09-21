/** Bounded MCP JSON-RPC transport with an explicit raw-resolution policy. */

import { once } from 'node:events';
import { MAX_MESSAGE_BYTES } from './vault-secure.js';

export const SERVER_VERSION = '2.0.0';
export const PROTOCOL_VERSIONS = Object.freeze(['2025-06-18', '2024-11-05']);

const publicCodes = new Set([
  'vault_locked', 'not_found', 'no_domain_binding', 'domain_mismatch', 'invalid_arguments',
  'invalid_secret_name', 'invalid_domain', 'secret_too_large', 'wrong_credentials',
  'duplicate_secret', 'invalid_vault', 'raw_resolve_disabled', 'decryption_failed',
]);

function isObject(value) { return value !== null && typeof value === 'object' && !Array.isArray(value); }
function errorResponse(id, code, message = code) { return { jsonrpc: '2.0', id, error: { code, message } }; }
function resultResponse(id, result) { return { jsonrpc: '2.0', id, result }; }
function publicError(error) { return publicCodes.has(error?.code) ? error.code : 'vault_error'; }
function validId(id) { return (typeof id === 'string' && id.length <= 128) || Number.isSafeInteger(id); }

function validateResolveArgs(args) {
  if (!isObject(args) || Object.keys(args).some(key => !['placeholder', 'origin'].includes(key)) ||
      typeof args.placeholder !== 'string' || !/^[A-Za-z0-9_:.@-]{1,128}$/.test(args.placeholder) ||
      typeof args.origin !== 'string' || args.origin.length > 2048) throw new TypeError('invalid_arguments');
  try {
    const origin = new URL(args.origin);
    if (!['http:', 'https:'].includes(origin.protocol) || !origin.hostname || origin.username || origin.password) throw new Error();
    return { placeholder: args.placeholder, origin: origin.origin };
  } catch { throw new TypeError('invalid_arguments'); }
}

function toolResult(text, isError = false) {
  return { content: [{ type: 'text', text }], ...(isError ? { isError: true } : {}) };
}

export function createMcpHandler({ vault, allowRawResolve = false }) {
  if (typeof allowRawResolve !== 'boolean') throw new TypeError('allowRawResolve must be boolean');
  let initialized = false;
  let ready = false;
  const listTool = {
    name: 'enigmagent_list',
    description: 'List secret names and bound domains. Values are never returned.',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
  };
  const resolveTool = {
    name: 'enigmagent_resolve',
    description: 'Returns a plaintext secret to this client. Disabled by default; enable only for a trusted client. The origin is caller-declared, not attestation.',
    inputSchema: {
      type: 'object', required: ['placeholder', 'origin'], additionalProperties: false,
      properties: {
        placeholder: { type: 'string', minLength: 1, maxLength: 128 },
        origin: { type: 'string', minLength: 1, maxLength: 2048 },
      },
    },
  };

  return async function handle(request) {
    if (!isObject(request) || request.jsonrpc !== '2.0') return errorResponse(null, -32600, 'Invalid Request');
    const hasId = Object.hasOwn(request, 'id');
    if (hasId && !validId(request.id)) return errorResponse(null, -32600, 'Invalid Request');
    if (!Object.hasOwn(request, 'method') && hasId && (Object.hasOwn(request, 'result') || Object.hasOwn(request, 'error'))) return null;
    if (typeof request.method !== 'string' || request.method.length > 128) return errorResponse(hasId ? request.id : null, -32600, 'Invalid Request');
    if (!hasId) {
      if (request.method === 'notifications/initialized' && initialized) ready = true;
      return null;
    }
    const { id, method, params } = request;
    if (method === 'initialize') {
      if (initialized || !isObject(params) || typeof params.protocolVersion !== 'string' || !isObject(params.capabilities) || !isObject(params.clientInfo) ||
          typeof params.clientInfo.name !== 'string' || typeof params.clientInfo.version !== 'string') return errorResponse(id, -32602, 'Invalid params');
      initialized = true;
      const protocolVersion = PROTOCOL_VERSIONS.includes(params.protocolVersion) ? params.protocolVersion : PROTOCOL_VERSIONS[0];
      return resultResponse(id, { protocolVersion, capabilities: { tools: {} }, serverInfo: { name: 'enigmagent-mcp', version: SERVER_VERSION },
        instructions: allowRawResolve ? 'Raw resolution is enabled by explicit operator policy. Never expose returned values to an untrusted model or log.' : 'Metadata only. Raw resolution is disabled by operator policy.' });
    }
    if (method === 'ping') return resultResponse(id, {});
    if (!ready) return errorResponse(id, -32002, 'Session not initialized');
    if (method === 'tools/list') return resultResponse(id, { tools: allowRawResolve ? [listTool, resolveTool] : [listTool] });
    if (method !== 'tools/call' || !isObject(params) || typeof params.name !== 'string') return errorResponse(id, -32601, 'Method not found');
    const args = params.arguments === undefined ? {} : params.arguments;
    try {
      if (params.name === 'enigmagent_list') {
        if (!isObject(args) || Object.keys(args).length !== 0) throw new TypeError('invalid_arguments');
        return resultResponse(id, toolResult(JSON.stringify(vault.list())));
      }
      if (params.name === 'enigmagent_resolve') {
        if (!allowRawResolve) return resultResponse(id, toolResult('raw_resolve_disabled', true));
        const validated = validateResolveArgs(args);
        return resultResponse(id, toolResult(await vault.resolve(validated.placeholder, validated.origin)));
      }
      return errorResponse(id, -32602, 'Unknown or disabled tool');
    } catch (error) {
      return resultResponse(id, toolResult(publicError(error), true));
    }
  };
}

async function send(output, message) {
  if (!message) return;
  const line = `${JSON.stringify(message)}\n`;
  if (!output.write(line)) await once(output, 'drain');
}

export async function serveMcpStdio({ input, output, handler, maxMessageBytes = MAX_MESSAGE_BYTES }) {
  if (!input || !output || typeof handler !== 'function') throw new TypeError('input, output and handler are required');
  let frame = Buffer.alloc(0);
  for await (const chunk of input) {
    frame = Buffer.concat([frame, Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)]);
    if (frame.length > maxMessageBytes && !frame.includes(10)) {
      await send(output, errorResponse(null, -32600, 'Message too large'));
      return false;
    }
    let newline;
    while ((newline = frame.indexOf(10)) >= 0) {
      const line = frame.subarray(0, newline);
      frame = frame.subarray(newline + 1);
      if (line.length > maxMessageBytes) {
        await send(output, errorResponse(null, -32600, 'Message too large'));
        continue;
      }
      let request;
      try { request = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(line)); }
      catch { await send(output, errorResponse(null, -32700, 'Parse error')); continue; }
      await send(output, await handler(request));
    }
  }
  if (frame.length) await send(output, errorResponse(null, -32700, 'Incomplete message'));
  return frame.length === 0;
}
