// Tests the Okta MCP Bridge agent app end to end against a MOCK Bridge (OAuth server + MCP endpoint):
//   browser -> bridge agent -> (authorization code + PKCE) mock Bridge -> (MCP over HTTP, Bearer token) mock Bridge
// The agent app is the real code; a mock Groq plays the LLM. It does not talk to Okta or the real Bridge.
// Run: npm run test:bridge
import { spawn, type ChildProcess } from 'node:child_process';
import crypto from 'node:crypto';
import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { z } from 'zod';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const BRIDGE_PORT = 14041;
const GROQ_PORT = 14051;
const AGENT_PORT = 13241;
const BRIDGE = `http://localhost:${BRIDGE_PORT}`;
const AGENT = `http://localhost:${AGENT_PORT}`;
const CLIENT_ID = 'wlpTESTAGENT';
const CLIENT_SECRET = 'oapxy_' + crypto.randomUUID();
const b64u = (b: Buffer) => b.toString('base64url');
const readBody = (req: http.IncomingMessage) => new Promise<string>((r) => { let s = ''; req.on('data', (d) => (s += d)); req.on('end', () => r(s)); });

// ---- mock Bridge ---------------------------------------------------------------------------
const seen: { authorizeUrl?: URL; tokenForm?: URLSearchParams; mcpAuth: string[]; mcpCalls: string[]; refreshes: number } = { mcpAuth: [], mcpCalls: [], refreshes: 0 };
const codes = new Map<string, { challenge: string; redirectUri: string }>();
const tokens = new Map<string, number>(); // access token -> expiry ms
let accessTtl = 3600;
let namedPathOnly = false; // true: only /mcp/<agent id> works, like the real Bridge
let tokenFails400 = false; // the real Bridge answers some errors with its own JSON shape, not an OAuth error
const refreshTokens = new Set<string>();

const metadata = {
  issuer: BRIDGE,
  authorization_endpoint: `${BRIDGE}/oauth/authorize`,
  token_endpoint: `${BRIDGE}/oauth2/v1/token`,
  registration_endpoint: `${BRIDGE}/oauth/register`,
  jwks_uri: `${BRIDGE}/oauth2/v1/keys`,
  scopes_supported: ['offline_access', 'openid'],
  response_types_supported: ['code'],
  grant_types_supported: ['authorization_code', 'refresh_token'],
  token_endpoint_auth_methods_supported: ['none', 'client_secret_basic', 'client_secret_post', 'private_key_jwt'],
  code_challenge_methods_supported: ['S256'],
  subject_types_supported: ['public'],
  id_token_signing_alg_values_supported: ['RS256'],
};

function newAccessToken() {
  const t = 'bridge-at-' + crypto.randomUUID();
  tokens.set(t, Date.now() + accessTtl * 1000);
  return t;
}

const bridge = http.createServer(async (req, res) => {
  const url = new URL(req.url!, BRIDGE);
  const json = (o: unknown, status = 200, headers: Record<string, string> = {}) => { res.writeHead(status, { 'Content-Type': 'application/json', ...headers }); res.end(JSON.stringify(o)); };
  if (url.pathname === '/.well-known/openid-configuration' || url.pathname === '/.well-known/oauth-authorization-server') return json(metadata);
  if (url.pathname === '/oauth/authorize') {
    seen.authorizeUrl = url;
    const code = 'code-' + crypto.randomUUID();
    codes.set(code, { challenge: url.searchParams.get('code_challenge')!, redirectUri: url.searchParams.get('redirect_uri')! });
    const back = new URL(url.searchParams.get('redirect_uri')!);
    back.searchParams.set('code', code);
    back.searchParams.set('state', url.searchParams.get('state')!);
    res.writeHead(302, { Location: back.href });
    return void res.end();
  }
  if (url.pathname === '/oauth2/v1/token' && req.method === 'POST') {
    const form = new URLSearchParams(await readBody(req));
    seen.tokenForm = form;
    const grant = form.get('grant_type');
    if (tokenFails400) return json({ detail: 'redirect_uri is not registered for this agent' }, 400);
    if (form.get('client_id') !== CLIENT_ID || form.get('client_secret') !== CLIENT_SECRET) return json({ error: 'invalid_client' }, 401);
    if (grant === 'authorization_code') {
      const rec = codes.get(form.get('code')!);
      codes.delete(form.get('code')!);
      if (!rec || form.get('redirect_uri') !== rec.redirectUri) return json({ error: 'invalid_grant' }, 400);
      if (b64u(crypto.createHash('sha256').update(form.get('code_verifier') ?? '').digest()) !== rec.challenge) return json({ error: 'invalid_grant', error_description: 'PKCE' }, 400);
      const refresh = 'bridge-rt-' + crypto.randomUUID();
      refreshTokens.add(refresh);
      return json({ token_type: 'Bearer', access_token: newAccessToken(), expires_in: accessTtl, refresh_token: refresh, scope: 'openid offline_access' });
    }
    if (grant === 'refresh_token') {
      const rt = form.get('refresh_token')!;
      if (!refreshTokens.has(rt)) return json({ error: 'invalid_grant' }, 400);
      refreshTokens.delete(rt);
      seen.refreshes++;
      const next = 'bridge-rt-' + crypto.randomUUID();
      refreshTokens.add(next);
      return json({ token_type: 'Bearer', access_token: newAccessToken(), expires_in: 3600, refresh_token: next, scope: 'openid offline_access' });
    }
    return json({ error: 'unsupported_grant_type' }, 400);
  }
  // The real Bridge serves one virtual MCP per agent at /mcp/<agent id>; "/mcp" alone answers "No resource configured for path '/mcp'".
  if (namedPathOnly && url.pathname === '/mcp' && req.method === 'POST') {
    await readBody(req);
    return json({ jsonrpc: '2.0', id: 0, error: { code: -32500, message: "No resource configured for path '/mcp'", data: 'resource_not_found' } }, 404);
  }
  if (((url.pathname === '/mcp' && !namedPathOnly) || (namedPathOnly && url.pathname === '/mcp/retail-ops-agent-bridge')) && req.method === 'POST') {
    const auth = req.headers.authorization ?? '';
    const t = auth.replace(/^Bearer /, '');
    seen.mcpAuth.push(t);
    const exp = tokens.get(t);
    if (!exp || exp < Date.now()) {
      return json({ jsonrpc: '2.0', id: null, error: { code: -32401, message: 'Authorization header required' } }, 401, { 'WWW-Authenticate': `Bearer resource_metadata="${BRIDGE}/.well-known/oauth-protected-resource/mcp", error="invalid_token"` });
    }
    const body = JSON.parse((await readBody(req)) || '{}');
    const server = new McpServer({ name: 'mock-bridge', version: '1.0.0' });
    // The Bridge prefixes tool names with the resource name.
    server.registerTool('hpe-order-portal-mcp-v4__list_orders', { description: 'List orders', inputSchema: { status: z.string().optional() } }, async (args: unknown) => {
      seen.mcpCalls.push('list_orders ' + JSON.stringify(args));
      return { content: [{ type: 'text' as const, text: JSON.stringify([{ id: 'SO-10003', status: 'processing' }]) }] };
    });
    server.registerTool('hpe-order-portal-mcp-v4__check_inventory', { description: 'Check stock', inputSchema: { sku: z.string() } }, async () => ({ content: [{ type: 'text' as const, text: '{"onHand":3}' }] }));
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
    res.on('close', () => { transport.close(); server.close(); });
    await server.connect(transport);
    return void (await transport.handleRequest(req, res, body));
  }
  res.writeHead(404); res.end();
});
await new Promise<void>((r) => bridge.listen(BRIDGE_PORT, r));

// ---- mock Groq: one queued tool call, then a final text -------------------------------------
let queued: { name: string; args: Record<string, unknown> } | undefined;
let offeredTools: string[] = [];
const groq = http.createServer(async (req, res) => {
  const body = JSON.parse((await readBody(req)) || '{}');
  offeredTools = (body.tools ?? []).map((t: { function: { name: string } }) => t.function.name);
  const last = body.messages[body.messages.length - 1];
  const reply = (message: unknown, finish: string) => { res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ choices: [{ message, finish_reason: finish }] })); };
  if (last.role === 'tool' || !queued) return reply({ role: 'assistant', content: last.role === 'tool' ? `Done: ${String(last.content).slice(0, 80)}` : 'Hello' }, 'stop');
  const call = queued;
  queued = undefined;
  reply({ role: 'assistant', content: null, tool_calls: [{ id: 'c1', type: 'function', function: { name: call.name, arguments: JSON.stringify(call.args) } }] }, 'tool_calls');
});
await new Promise<void>((r) => groq.listen(GROQ_PORT, r));

// ---- the real agent app ----------------------------------------------------------------------
const agentEnv = {
  ...process.env,
  AGENT_BRIDGE_PORT: String(AGENT_PORT), AGENT_BRIDGE_BASE_URL: AGENT,
  BRIDGE_URL: BRIDGE, BRIDGE_CLIENT_ID: CLIENT_ID, BRIDGE_CLIENT_SECRET: CLIENT_SECRET, BRIDGE_SCOPES: 'openid offline_access', BRIDGE_RESOURCE: BRIDGE,
  OKTA_ISSUER: BRIDGE, AGENT_CLIENT_ID: 'unused', AGENT_AUTH_METHOD: 'client_secret', AGENT_CLIENT_SECRET: 'unused',
  LLM_PROVIDER: 'groq', GROQ_API_KEY: 'test', GROQ_BASE_URL: `http://localhost:${GROQ_PORT}`, GROQ_MODEL: 'test-model',
};
const agentProc: ChildProcess = spawn(process.execPath, ['--import', 'tsx', path.join(root, 'packages/agent-bridge/src/index.ts')], { env: agentEnv, stdio: ['ignore', 'ignore', 'pipe'] });
agentProc.stderr!.on('data', (d) => process.stderr.write(`[bridge-agent] ${d}`));
const cleanup = () => { agentProc.kill(); bridge.close(); groq.close(); };

let failed = 0;
const check = (name: string, cond: boolean, extra?: unknown) => {
  console.log(`${cond ? '  ✔' : '  ✘'} ${name}${cond ? '' : ` -> ${JSON.stringify(extra)}`}`);
  if (!cond) failed++;
};
const wait = async (url: string) => {
  for (let i = 0; i < 120; i++) { try { if ((await fetch(url)).ok) return; } catch { /* retry */ } await new Promise((r) => setTimeout(r, 250)); }
  throw new Error(`${url} did not start`);
};

function browser() {
  let cookie = '';
  const go = async (url: string, init: RequestInit = {}) => {
    const r = await fetch(url, { ...init, redirect: 'manual', headers: { ...(init.headers as Record<string, string>), ...(cookie ? { Cookie: cookie } : {}) } });
    const set = r.headers.getSetCookie().map((c) => c.split(';')[0]);
    if (set.length) cookie = [...new Map([...cookie.split('; ').filter(Boolean), ...set].map((c) => [c.split('=')[0], c])).values()].join('; ');
    return r;
  };
  const post = (p: string, body: unknown) => go(`${AGENT}${p}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  const signIn = async () => {
    const a = await go(`${AGENT}/login`);
    const b = await go(a.headers.get('location')!);
    const c = await go(b.headers.get('location')!);
    return c.headers.get('location');
  };
  return { go, post, signIn, get: (p: string) => go(`${AGENT}${p}`) };
}

try {
  await wait(`${AGENT}/api/me`);

  console.log('1. Sign-in at the Bridge (authorization code + PKCE)');
  const b = browser();
  const me0 = await (await b.get('/api/me')).json() as any;
  check('not signed in yet', me0.authenticated === false);
  check('page wording switches to the Bridge', me0.ui?.connectPath === '/api/bridge/connect' && /bridge/i.test(me0.ui?.subtitle), me0.ui);
  check('chat is refused before sign-in', (await b.post('/api/chat', { message: 'hi' })).status === 401);
  check('signs in and lands on /', (await b.signIn()) === '/');
  const au = seen.authorizeUrl!;
  check('PKCE S256 used', au.searchParams.get('code_challenge_method') === 'S256');
  check('agent client id sent', au.searchParams.get('client_id') === CLIENT_ID);
  check('redirect uri is the app callback', au.searchParams.get('redirect_uri') === `${AGENT}/callback`);
  check('scope requested', au.searchParams.get('scope') === 'openid offline_access');
  check('resource indicator sent on authorize', au.searchParams.get('resource') === BRIDGE);
  check('token request carried the client secret and resource', seen.tokenForm?.get('client_secret') === CLIENT_SECRET && seen.tokenForm?.get('resource') === BRIDGE, [...(seen.tokenForm?.keys() ?? [])]);
  const me1 = await (await b.get('/api/me')).json() as any;
  check('signed in', me1.authenticated === true && me1.retail?.scope?.includes('openid'), me1.retail);

  console.log('2. Calling the Bridge MCP endpoint');
  const connect = await (await b.post('/api/bridge/connect', {})).json() as any;
  check('connect succeeds with 2 tools', connect.tools?.length === 2, connect);
  check('tool names are shown without the Bridge prefix', connect.tools?.map((t: any) => t.name).sort().join() === 'check_inventory,list_orders', connect.tools);
  check('trace has sign-in and MCP steps', connect.trace?.length === 2 && connect.trace.every((s: any) => s.status === 'ok'), connect.trace);
  check('Bridge saw the bearer token it issued', seen.mcpAuth.length > 0 && seen.mcpAuth.every((t) => tokens.has(t)), seen.mcpAuth);

  console.log('3. Chat through the Bridge');
  queued = { name: 'hpe-order-portal-mcp-v4__list_orders', args: { status: 'processing' } };
  const chat = await (await b.post('/api/chat', { message: 'Which orders are processing?' })).json() as any;
  check('tool call went through the Bridge and the reply uses its result', chat.toolCalls?.[0]?.name === 'list_orders' && /SO-10003/.test(chat.reply ?? ''), chat);
  check('Bridge MCP handler received the call', seen.mcpCalls.some((c) => c.startsWith('list_orders')), seen.mcpCalls);
  check('model was offered both tools', offeredTools.length === 2, offeredTools);

  console.log('4. Refresh and failure cases');
  // expire the access token on the Bridge side: the agent must use its refresh token
  for (const t of tokens.keys()) tokens.set(t, Date.now() - 1000);
  const b2 = browser();
  accessTtl = 20; // issue a short-lived token so the agent's 30s margin triggers a refresh
  await b2.signIn();
  const c2 = await (await b2.post('/api/bridge/connect', {})).json() as any;
  check('short-lived token is renewed with the refresh token', seen.refreshes >= 1 && c2.tools?.length === 2, { refreshes: seen.refreshes, c2 });
  accessTtl = 3600;
  // the Bridge revokes everything and the refresh token no longer works
  refreshTokens.clear();
  for (const t of tokens.keys()) tokens.set(t, Date.now() - 1000);
  const dead = await b.post('/api/bridge/connect', {});
  const deadJ = await dead.json() as any;
  check('rejected token gives a clear 401', dead.status === 401 && /sign in again|rejected|expired/i.test(deadJ.message ?? ''), { status: dead.status, deadJ });
  // the Bridge answers a token request with a 400 in its own JSON shape: the sign-in page must show the reason
  tokenFails400 = true;
  const b3 = browser();
  const l1 = await b3.go(`${AGENT}/login`);
  const l2 = await b3.go(l1.headers.get('location')!);
  const l3 = await b3.go(l2.headers.get('location')!);
  const l3Text = await l3.text();
  check('a 400 in the Bridge\'s own JSON shape shows its message on the sign-in page', l3.status === 400 && /HTTP 400/.test(l3Text) && /redirect_uri is not registered/.test(l3Text), l3Text.slice(0, 300));
  tokenFails400 = false;

  console.log('5. The Bridge serves MCP per agent at /mcp/<agent id>');
  namedPathOnly = true;
  const b4 = browser();
  await b4.signIn();
  const c4 = await (await b4.post('/api/bridge/connect', {})).json() as any;
  check('plain /mcp is refused, the per-agent path is found and used', c4.tools?.length === 2 && c4.trace?.some((s: any) => /Found the Bridge MCP path/.test(s.title) && /\/mcp\/retail-ops-agent-bridge/.test(s.detail)), c4);
  queued = { name: 'hpe-order-portal-mcp-v4__list_orders', args: {} };
  const chat4 = await (await b4.post('/api/chat', { message: 'orders?' })).json() as any;
  check('chat uses the found path', /SO-10003/.test(chat4.reply ?? ''), chat4);
  namedPathOnly = false;
} finally {
  cleanup();
}
console.log(failed ? `\n${failed} check(s) failed` : '\nAll Bridge-agent checks passed');
process.exit(failed ? 1 : 0);
