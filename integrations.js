/** Configuration adapters for popular MCP-capable clients.
 *
 * These are maintained examples and validation helpers, not upstream plugins
 * or endorsements. They all connect through the standard MCP stdio transport.
 */

export const INTEGRATIONS = Object.freeze({
  claude_desktop: { displayName: 'Claude Desktop', configKey: 'mcpServers', docs: 'https://modelcontextprotocol.io/quickstart/user' },
  cursor: { displayName: 'Cursor', configKey: 'mcpServers', docs: 'https://docs.cursor.com/context/mcp' },
  continue: { displayName: 'Continue', configKey: 'mcpServers', docs: 'https://docs.continue.dev/customize/deep-dives/mcp' },
  cline: { displayName: 'Cline', configKey: 'mcpServers', docs: 'https://github.com/cline/cline' },
  open_webui: { displayName: 'Open WebUI', configKey: 'mcpServers', docs: 'https://docs.openwebui.com/' },
  anythingllm: { displayName: 'AnythingLLM', configKey: 'mcpServers', docs: 'https://docs.anythingllm.com/' },
  lm_studio: { displayName: 'LM Studio', configKey: 'mcpServers', docs: 'https://lmstudio.ai/docs' },
  zed: { displayName: 'Zed', configKey: 'context_servers', docs: 'https://zed.dev/docs/assistant/context-servers' },
  goose: { displayName: 'Goose', configKey: 'extensions', docs: 'https://block.github.io/goose/docs/getting-started/using-extensions/' },
  windsurf: { displayName: 'Windsurf', configKey: 'mcpServers', docs: 'https://docs.windsurf.com/windsurf/cascade/mcp' },
});

function command(vaultPath) {
  if (typeof vaultPath !== 'string' || vaultPath.length === 0 || vaultPath.includes('\0')) throw new TypeError('vaultPath is required');
  return { command: 'npx', args: ['-y', 'enigmagent-mcp@2.0.0', '--vault', vaultPath] };
}

export function buildClientConfig(client, vaultPath) {
  if (!Object.hasOwn(INTEGRATIONS, client)) throw new RangeError(`Unknown integration: ${client}`);
  const spec = command(vaultPath);
  if (client === 'zed') return { context_servers: { enigmagent: { source: 'custom', command: spec.command, args: spec.args } } };
  if (client === 'goose') return { extensions: { enigmagent: { bundled: false, type: 'streamable_http', name: 'EnigmAgent', uri: 'stdio://enigmagent', enabled: true, description: 'Use the MCP stdio command from this adapter.', command: spec.command, args: spec.args } } };
  return { [INTEGRATIONS[client].configKey]: { enigmagent: spec } };
}

export function integrationManifest(vaultPath = './my.vault.json') {
  return Object.entries(INTEGRATIONS).map(([id, info]) => ({ id, displayName: info.displayName, configKey: info.configKey, documentation: info.docs, config: buildClientConfig(id, vaultPath) }));
}
