// Settings for the Okta MCP Bridge agent app. Everything lives in the shared .env at the repo root.
import { env, trimSlash } from '../../agent/src/env.js';

const port = Number(env('AGENT_BRIDGE_PORT', '3300'));
const bridgeUrl = trimSlash(env('BRIDGE_URL', ''));

export const bridgeCfg = {
  agentName: env('AGENT_BRIDGE_NAME', 'Ops Agent (Bridge)'),
  port,
  baseUrl: trimSlash(env('AGENT_BRIDGE_BASE_URL', `http://localhost:${port}`)),
  sessionSecret: env('SESSION_SECRET', 'dev-only-change-me'),

  /** The Okta MCP Bridge: it is both the OAuth server (sign-in) and the MCP server (/mcp). */
  url: bridgeUrl,
  mcpUrl: trimSlash(env('BRIDGE_MCP_URL', bridgeUrl ? `${bridgeUrl}/mcp` : '')),
  /** The agent's client id at the Bridge (the Okta AI agent's client id) and, in Standard mode, the Bridge's "client secret proxy" value. */
  clientId: env('BRIDGE_CLIENT_ID', ''),
  clientSecret: env('BRIDGE_CLIENT_SECRET', ''),
  /** The agent's id in the Bridge (Agents page). The Bridge serves one virtual MCP per agent at /mcp/<agent id>. */
  agentId: env('BRIDGE_AGENT_ID', 'retail-ops-agent-bridge'),
  /** The name of the resource in the Bridge (Resources page). The Bridge may address a resource by this name or its slug; used to find the MCP path. */
  resourceName: env('BRIDGE_RESOURCE_NAME', 'HPE Order Portal MCP v4'),
  /** How the secret is sent to the token endpoint: post | basic. */
  authMethod: env('BRIDGE_AUTH_METHOD', 'post').toLowerCase() === 'basic' ? ('basic' as const) : ('post' as const),
  scopes: env('BRIDGE_SCOPES', 'openid offline_access'),
  /** RFC 8707 resource indicator sent on the authorization and token requests. Empty = do not send. */
  resource: env('BRIDGE_RESOURCE', bridgeUrl),

  /**
   * Optional: send THIS app's LLM calls through the Kong AI Gateway instead of straight to Bedrock. Empty = unchanged.
   * The gateway holds the real Bedrock key, so the app only needs a placeholder. Base URL = the gateway's model base path
   * (the Anthropic SDK adds /v1/messages), e.g. http://18.216.235.230:8000/ai . Model = the model alias set in Kong.
   */
  llmBaseUrl: trimSlash(env('BRIDGE_LLM_BASE_URL', '')),
  llmModel: env('BRIDGE_LLM_MODEL', ''),
  llmApiKey: env('BRIDGE_LLM_API_KEY', ''),
};

export function missingConfig(): string[] {
  const need: [string, string][] = [
    ['BRIDGE_URL', 'the Okta MCP Bridge base URL, e.g. https://hpe-poc.bridge.oktaproserv.com'],
    ['BRIDGE_CLIENT_ID', "the agent's client id in the Bridge (Okta AI agent client id)"],
  ];
  return need.filter(([k]) => !process.env[k]?.trim()).map(([k, what]) => `${k}  (${what})`);
}
