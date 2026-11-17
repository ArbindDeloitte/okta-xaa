// Okta Agent Gateway test mode. Instead of doing the XAA exchange itself, the agent signs the user in to the
// gateway's Okta authorization server (authorization code + PKCE, with the SAME Okta app and redirect URI as the
// normal login) and then talks to the gateway's MCP URL. The gateway swaps that token for the portal credential
// (brokered consent) and calls the portal for us.
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import * as oidc from 'openid-client';
import { cfg } from './config.js';
import { agentSigningKey } from './xaa.js';

export const gatewayEnabled = () => Boolean(cfg.gateway.mcpUrl);

/** Which authorization server issues gateway tokens: read from the gateway's protected-resource metadata (RFC 9728). */
export async function gatewayAuthIssuer(): Promise<{ issuer: string; scopes: string[] }> {
  if (cfg.gateway.authIssuer) return { issuer: cfg.gateway.authIssuer, scopes: ['openid', 'offline_access'] };
  const u = new URL(cfg.gateway.mcpUrl);
  const url = `${u.origin}/.well-known/oauth-protected-resource${u.pathname.replace(/\/+$/, '')}`;
  const r = await fetch(url, { signal: AbortSignal.timeout(10_000) });
  if (!r.ok) throw new Error(`Gateway metadata ${url} answered HTTP ${r.status}`);
  const meta = (await r.json()) as { authorization_servers?: string[]; scopes_supported?: string[] };
  const issuer = meta.authorization_servers?.[0];
  if (!issuer) throw new Error(`Gateway metadata at ${url} lists no authorization server`);
  return { issuer, scopes: meta.scopes_supported?.length ? meta.scopes_supported : ['openid', 'offline_access'] };
}

let cached: { config: oidc.Configuration; scopes: string[] } | undefined;
export async function gatewayOidc() {
  if (cached) return cached;
  const { issuer, scopes } = await gatewayAuthIssuer();
  const issuerUrl = new URL(issuer);
  const metaRes = await fetch(`${issuerUrl.href.replace(/\/$/, '')}/.well-known/openid-configuration`, { signal: AbortSignal.timeout(10_000) });
  if (!metaRes.ok) throw new Error(`Discovery for the gateway authorization server failed: HTTP ${metaRes.status}`);
  const tokenEndpoint = ((await metaRes.json()) as { token_endpoint: string }).token_endpoint;
  const auth =
    cfg.okta.authMethod === 'private_key_jwt'
      ? oidc.PrivateKeyJwt({ key: await agentSigningKey(), kid: cfg.okta.privateJwk!.kid }, {
          [oidc.modifyAssertion]: (_h, payload) => {
            payload.aud = tokenEndpoint; // Okta expects the token endpoint URL as the assertion audience
          },
        })
      : undefined;
  const config = await oidc.discovery(issuerUrl, cfg.okta.clientId, cfg.okta.clientSecret, auth);
  return (cached = { config, scopes: scopes.filter((s) => ['openid', 'profile', 'email', 'offline_access'].includes(s)) });
}

export type GatewayTokens = { accessToken: string; refreshToken?: string; expiresAt: number };

export const gatewayTokensFrom = (t: oidc.TokenEndpointResponse, previousRefresh?: string): GatewayTokens => ({
  accessToken: t.access_token,
  refreshToken: t.refresh_token ?? previousRefresh,
  expiresAt: Date.now() + (t.expires_in ?? 3600) * 1000,
});

/** Use the gateway session's refresh token (requested with offline_access) so the user is not sent back to Okta every hour. */
export async function refreshGatewayTokens(refreshToken: string): Promise<GatewayTokens> {
  const { config } = await gatewayOidc();
  return gatewayTokensFrom(await oidc.refreshTokenGrant(config, refreshToken), refreshToken);
}

async function connect(accessToken: string): Promise<Client> {
  const client = new Client({ name: 'retail-agent-gateway-test', version: '1.0.0' });
  const transport = new StreamableHTTPClientTransport(new URL(cfg.gateway.mcpUrl), { requestInit: { headers: { Authorization: `Bearer ${accessToken}` } } });
  await client.connect(transport);
  return client;
}

export type GatewayTestResult = { gatewayUrl: string; tools: string[]; call?: { name: string; isError: boolean; preview: string } };

/** List the tools the gateway exposes, then call one read-only tool to prove the whole chain works. */
export async function testGateway(accessToken: string): Promise<GatewayTestResult> {
  const mcp = await connect(accessToken);
  try {
    const { tools } = await mcp.listTools();
    const names = tools.map((t) => t.name);
    const result: GatewayTestResult = { gatewayUrl: cfg.gateway.mcpUrl, tools: names };
    // names may carry a prefix added by the gateway, so match on the suffix
    const target = names.find((n) => n === 'list_orders' || n.endsWith('list_orders') || n.endsWith('__list_orders'));
    if (target) {
      const r = await mcp.callTool({ name: target, arguments: { status: 'processing', limit: 3 } });
      const text = (r.content as { text?: string }[]).map((c) => c.text ?? '').join('');
      result.call = { name: target, isError: Boolean(r.isError), preview: text.slice(0, 600) };
    }
    return result;
  } finally {
    await mcp.close();
  }
}
