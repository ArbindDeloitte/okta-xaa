// Agent app #3: the same HPE Ops Agent, but it reaches the HPE Order Portal THROUGH the Okta MCP Bridge.
// The Bridge is an OAuth-protected MCP server: the user signs in at the Bridge (authorization code + PKCE), the agent
// calls the Bridge's /mcp endpoint with the Bridge's access token, and the Bridge performs the cross-app exchange with
// Okta for the portal on its own. The first call is also what makes the Bridge discover the portal's tools.
import express, { type NextFunction, type Request, type Response } from 'express';
import session from 'express-session';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import * as oidc from 'openid-client';
import { decodeJwt } from 'jose';
import { cfg } from '../../agent/src/config.js';
import { ConsentRequiredError, listRetailTools, McpAuthError, runAgent, type ChatMessage, type ToolInfo } from '../../agent/src/agent.js';
import type { TraceStep } from '../../agent/src/xaa.js';
import { bridgeCfg, missingConfig } from './config.js';

declare module 'express-session' {
  interface SessionData {
    login?: { verifier: string; state: string };
    bridge?: { accessToken: string; refreshToken?: string; expiresAt: number; scope: string[] };
    user?: { sub?: string; name?: string; email?: string };
    tools?: ToolInfo[];
    mcpUrl?: string;
    history?: ChatMessage[];
  }
}

const missing = missingConfig();
if (missing.length) {
  console.error('The Bridge agent needs these settings in .env:\n  ' + missing.join('\n  '));
  process.exit(1);
}

// ---- LLM through the Kong AI Gateway (optional) -----------------------------------------------------
// Each app is its own process, so setting these here affects only this app. The Anthropic client is created on the first
// chat request, after this runs. The real Bedrock key lives in the gateway; the SDK just needs some key value.
if (bridgeCfg.llmBaseUrl && cfg.llm.provider === 'anthropic') {
  process.env.ANTHROPIC_BASE_URL = bridgeCfg.llmBaseUrl;
  process.env.ANTHROPIC_API_KEY = bridgeCfg.llmApiKey || 'held-by-the-kong-gateway';
  if (bridgeCfg.llmModel) cfg.llm.model = bridgeCfg.llmModel;
  cfg.llm.serverFallbacks = false; // an Anthropic-API-only feature; not available behind a gateway
}

// ---- OAuth client for the Bridge ---------------------------------------------------------------
// Only the Bridge's metadata is discovered with the OAuth library (endpoints). The token requests are made by hand below:
// the Bridge relays Okta's ID token (issuer = the Okta org, not the Bridge), which a strict OIDC client would refuse,
// and its error bodies come in several shapes. We only need the access token, which the Bridge itself validates.
let discovered: Promise<oidc.Configuration> | undefined;
function bridgeOAuth(): Promise<oidc.Configuration> {
  discovered ??= oidc
    .discovery(new URL(bridgeCfg.url), bridgeCfg.clientId, undefined, oidc.None(), bridgeCfg.url.startsWith('http://') ? { execute: [oidc.allowInsecureRequests] } : undefined)
    .catch((e) => {
      discovered = undefined; // try again next time
      throw e;
    });
  return discovered;
}

type TokenResponse = { access_token: string; token_type?: string; expires_in?: number; refresh_token?: string; scope?: string; id_token?: string };

class TokenEndpointError extends Error {
  constructor(public status: number, public said: string) {
    super(`the Bridge's token endpoint answered HTTP ${status}${said ? ` (${said})` : ''}`);
  }
}

/** One request to the Bridge's token endpoint, with the client authentication the Bridge expects. */
async function tokenRequest(form: Record<string, string>): Promise<TokenResponse> {
  const endpoint = (await bridgeOAuth()).serverMetadata().token_endpoint!;
  const body = new URLSearchParams({ ...form, client_id: bridgeCfg.clientId });
  const headers: Record<string, string> = { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' };
  if (bridgeCfg.resource) body.set('resource', bridgeCfg.resource);
  if (bridgeCfg.clientSecret) {
    if (bridgeCfg.authMethod === 'basic') {
      headers.Authorization = 'Basic ' + Buffer.from(`${encodeURIComponent(bridgeCfg.clientId)}:${encodeURIComponent(bridgeCfg.clientSecret)}`).toString('base64');
      body.delete('client_id');
    } else {
      body.set('client_secret', bridgeCfg.clientSecret);
    }
  }
  const res = await fetch(endpoint, { method: 'POST', headers, body, signal: AbortSignal.timeout(20_000) });
  const text = await res.text();
  if (!res.ok) {
    let said = text.slice(0, 200);
    try {
      // OAuth shape, Okta's own shape (the Bridge relays Okta's answer), or a FastAPI "detail"
      const j = JSON.parse(text) as { error?: string; error_description?: string; errorCode?: string; errorSummary?: string; detail?: unknown; message?: string };
      said = [j.error ?? j.errorCode, j.error_description ?? j.errorSummary ?? j.message, typeof j.detail === 'string' ? j.detail : j.detail ? JSON.stringify(j.detail) : ''].filter(Boolean).join(': ') || said;
    } catch {
      /* not JSON: keep the raw text */
    }
    throw new TokenEndpointError(res.status, said);
  }
  const json = JSON.parse(text) as TokenResponse;
  if (!json.access_token) throw new Error("the Bridge's token response has no access_token");
  return json;
}

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(express.json({ limit: '100kb' }));
app.use(
  session({
    name: `agent-bridge.${bridgeCfg.port}.sid`,
    secret: bridgeCfg.sessionSecret,
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, sameSite: 'lax', secure: bridgeCfg.baseUrl.startsWith('https://'), maxAge: 8 * 3600_000 },
  }),
);

const esc = (s: string) => s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);
const requireLogin = (req: Request, res: Response, next: NextFunction) =>
  req.session.bridge ? next() : void res.status(401).json({ error: 'not_authenticated' });

class BridgeError extends Error {
  constructor(message: string, public code: string, public step: number) {
    super(message);
  }
}

// ---- sign in / out -----------------------------------------------------------------------------
app.get('/login', async (req, res, next) => {
  try {
    const config = await bridgeOAuth();
    const verifier = oidc.randomPKCECodeVerifier();
    const state = oidc.randomState();
    req.session.login = { verifier, state };
    const params: Record<string, string> = {
      redirect_uri: `${bridgeCfg.baseUrl}/callback`,
      scope: bridgeCfg.scopes,
      code_challenge: await oidc.calculatePKCECodeChallenge(verifier),
      code_challenge_method: 'S256',
      state,
    };
    if (bridgeCfg.resource) params.resource = bridgeCfg.resource;
    const url = oidc.buildAuthorizationUrl(config, params);
    req.session.save(() => res.redirect(url.href));
  } catch (e) {
    next(e);
  }
});

app.get('/callback', async (req, res) => {
  const login = req.session.login;
  if (!login) return void res.status(400).send('Login session missing or expired. <a href="/login">Try again</a>.');
  try {
    const params = new URL(`${bridgeCfg.baseUrl}${req.originalUrl}`).searchParams;
    if (params.get('error')) throw new Error(`${params.get('error')}${params.get('error_description') ? ': ' + params.get('error_description') : ''}`);
    if (params.get('state') !== login.state) throw new Error('the sign-in response does not match this browser session (state mismatch)');
    const code = params.get('code');
    if (!code) throw new Error('the sign-in response has no authorization code');
    const tokens = await tokenRequest({ grant_type: 'authorization_code', code, redirect_uri: `${bridgeCfg.baseUrl}/callback`, code_verifier: login.verifier });
    const claims = readClaims(tokens);
    const scope = (tokens.scope ?? bridgeCfg.scopes).split(/\s+/).filter(Boolean);
    req.session.regenerate((err) => {
      if (err) return void res.status(500).send('Session error');
      req.session.bridge = { accessToken: tokens.access_token, refreshToken: tokens.refresh_token, expiresAt: Date.now() + (tokens.expires_in ?? 3600) * 1000, scope };
      req.session.user = claims;
      req.session.history = [];
      req.session.save(() => res.redirect('/'));
    });
  } catch (e) {
    const why = describeSignInError(e);
    console.error(`Bridge sign-in failed: ${why}`);
    res.status(400).send(`Sign-in failed: ${esc(why)}. <a href="/login">Try again</a>.`);
  }
});

/** The error text for the sign-in page, with a hint for the usual causes. */
function describeSignInError(e: unknown): string {
  if (e instanceof TokenEndpointError) {
    if (e.status === 401) {
      return bridgeCfg.clientSecret
        ? `${e.message}. Check that BRIDGE_CLIENT_SECRET is the current Client Secret Proxy value for this agent (it changes when rotated), or try BRIDGE_AUTH_METHOD=basic. If the message names Okta, the real client secret saved in the Bridge (Manual Configuration) is wrong or not activated in Okta`
        : `${e.message}. It requires this agent's Client Secret Proxy value: set BRIDGE_CLIENT_SECRET in .env (copy it from the agent's settings in the Bridge) and restart the app`;
    }
    if (e.status >= 500) return `${e.message}. The agent's own setup in the Bridge is incomplete (Agents > this agent > Configuration > Manual Configuration), or see the Bridge's Event Log`;
    return e.message;
  }
  return (e as Error).message;
}

/** Who signed in, for display only: from the ID token if the Bridge sent one, else from the access token when it is a JWT. These claims are NOT verified here; the Bridge validates its own tokens. */
function readClaims(tokens: TokenResponse): { sub?: string; name?: string; email?: string } {
  let c: Record<string, unknown> | undefined;
  for (const t of [tokens.id_token, tokens.access_token]) {
    if (!t) continue;
    try {
      c = decodeJwt(t) as Record<string, unknown>;
      break;
    } catch {
      /* not a JWT (opaque token) */
    }
  }
  return { sub: c?.sub as string | undefined, name: c?.name as string | undefined, email: (c?.email ?? c?.preferred_username) as string | undefined };
}

app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.clearCookie(`agent-bridge.${bridgeCfg.port}.sid`);
    res.redirect('/');
  });
});

// ---- the Bridge call ---------------------------------------------------------------------------
/** The Bridge access token, renewed with the refresh token when it is about to expire. */
async function ensureToken(req: Request): Promise<string> {
  const s = req.session.bridge!;
  if (s.expiresAt - Date.now() > 30_000) return s.accessToken;
  if (s.refreshToken) {
    try {
      const t = await tokenRequest({ grant_type: 'refresh_token', refresh_token: s.refreshToken });
      req.session.bridge = {
        accessToken: t.access_token,
        refreshToken: t.refresh_token ?? s.refreshToken,
        expiresAt: Date.now() + (t.expires_in ?? 3600) * 1000,
        scope: t.scope ? t.scope.split(/\s+/) : s.scope,
      };
      return t.access_token;
    } catch (e) {
      console.warn('Bridge token refresh failed:', (e as Error).message);
    }
  }
  throw new BridgeError('Your Bridge session expired. Sign in again.', 'token_expired', 1);
}

/** The URL the Bridge serves the portal's MCP on. The Bridge routes by resource, so the plain "/mcp" is often not it. */
function mcpCandidates(): string[] {
  const names = [bridgeCfg.resourceName, bridgeCfg.resourceName.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '')];
  // The Bridge's own design: one virtual MCP per agent at /mcp/<agent id>. Then the configured URL, then guesses by resource name.
  const agentIds = [...new Set([bridgeCfg.agentId, bridgeCfg.clientId])]; // the Bridge may key an agent by its slug or by its Okta client id
  const out = [...agentIds.map((a) => `${bridgeCfg.url}/mcp/${encodeURIComponent(a)}`), bridgeCfg.mcpUrl];
  for (const n of [...new Set(names)].filter(Boolean)) {
    const e = encodeURIComponent(n);
    out.push(`${bridgeCfg.url}/${e}/mcp`, `${bridgeCfg.url}/${e}`, `${bridgeCfg.url}/mcp/${e}`);
  }
  return [...new Set(out)];
}

/** An MCP initialize request, to see whether this URL is a working endpoint for this token. */
async function tryInitialize(url: string, token: string): Promise<{ ok: boolean; status: number; said: string }> {
  try {
    const r = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream', Authorization: `Bearer ${token}` },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'bridge-agent-probe', version: '1' } } }),
      signal: AbortSignal.timeout(15_000),
    });
    const text = (await r.text()).replace(/\s+/g, ' ');
    return { ok: r.ok && /"result"/.test(text), status: r.status, said: text.slice(0, 160) };
  } catch (e) {
    return { ok: false, status: 0, said: (e as Error).message };
  }
}

/** The MCP URL to use for this session: the first candidate that answers an initialize (remembered for the session). */
async function resolveMcpUrl(req: Request, token: string, trace: TraceStep[]): Promise<string> {
  if (req.session.mcpUrl) return req.session.mcpUrl;
  const tried: string[] = [];
  for (const url of mcpCandidates()) {
    const t0 = Date.now();
    const r = await tryInitialize(url, token);
    tried.push(`${url} -> ${r.status || 'no answer'}${r.ok ? ' OK' : ' ' + r.said.slice(0, 90)}`);
    if (r.ok) {
      req.session.mcpUrl = url;
      if (url !== bridgeCfg.mcpUrl) trace.push({ step: 0, title: 'Found the Bridge MCP path for this resource', status: 'ok', ms: Date.now() - t0, detail: `${url} (set BRIDGE_MCP_URL to this to skip the search)` });
      return url;
    }
  }
  trace.push({ step: 0, title: 'No working Bridge MCP path found', status: 'error', detail: tried.join(' | ') });
  throw new BridgeError(`The Bridge has no MCP endpoint I can use for "${bridgeCfg.resourceName}". Tried: ${tried.join(' | ')}`, 'bridge_no_resource', 2);
}

/** Call the Bridge's MCP endpoint once: this lists the tools and makes the Bridge fetch the portal's tools. */
async function bridgeConnect(req: Request, trace: TraceStep[]): Promise<ToolInfo[]> {
  const token = await ensureToken(req);
  const b = req.session.bridge!;
  trace.push({
    step: 1,
    title: 'Signed in at the Okta MCP Bridge',
    status: 'ok',
    detail: `authorization code + PKCE at ${bridgeCfg.url} · scope: ${b.scope.join(' ') || '–'} · valid for another ${Math.max(0, Math.round((b.expiresAt - Date.now()) / 1000))}s`,
  });
  const t0 = Date.now();
  try {
    const mcpUrl = await resolveMcpUrl(req, token, trace);
    const tools = await listRetailTools(token, mcpUrl);
    trace.push({
      step: 2,
      title: 'Bridge MCP endpoint answered',
      status: 'ok',
      ms: Date.now() - t0,
      detail: `${mcpUrl}: ${tools.length} tool(s)${tools.length ? ' — ' + tools.map((t) => t.name).join(', ') : ' (none yet: link the Okta connection to the resource in the Bridge)'}`,
    });
    req.session.tools = tools;
    return tools;
  } catch (e) {
    const msg = (e as Error).message;
    trace.push({ step: 2, title: 'Bridge MCP endpoint failed', status: 'error', ms: Date.now() - t0, detail: msg });
    if (e instanceof McpAuthError) throw new BridgeError(`The Bridge rejected the token (${msg}).`, 'bridge_rejected', 2);
    if (e instanceof BridgeError) throw e;
    throw new BridgeError(`Cannot use the Bridge MCP endpoint ${req.session.mcpUrl ?? bridgeCfg.mcpUrl}: ${msg}`, 'bridge_unreachable', 2);
  }
}

const errorBody = (e: unknown) => {
  if (e instanceof ConsentRequiredError) return { error: 'consent_required', message: e.message, consentUrl: e.url };
  if (e instanceof BridgeError) return { error: e.code, message: e.message, step: e.step };
  return { error: 'agent_error', message: (e as Error).message };
};
const errorStatus = (e: unknown) => (e instanceof BridgeError && (e.code === 'token_expired' || e.code === 'bridge_rejected') ? 401 : e instanceof ConsentRequiredError ? 409 : 502);

// ---- API (same shape as the other agents, so the same web page works) ----------------------------
app.get('/api/me', (req, res) => {
  const s = req.session;
  res.json({
    authenticated: Boolean(s.bridge),
    user: s.user,
    retail: s.bridge ? { scope: s.bridge.scope, role: undefined, expiresAt: s.bridge.expiresAt } : null,
    tools: s.tools ?? [],
    model: cfg.llm.model,
    agentName: bridgeCfg.agentName,
    gateway: { enabled: false, signedIn: false },
    llmConfigured: cfg.llm.provider === 'groq' ? Boolean(cfg.llm.groq.apiKey) : Boolean(process.env.ANTHROPIC_API_KEY || process.env.ANTHROPIC_AUTH_TOKEN || process.env.BEDROCK_API_KEY),
    provider: cfg.llm.provider,
    ui: {
      subtitle: 'Okta MCP Bridge demo',
      heroText: 'Sign in at the <strong>Okta MCP Bridge</strong>. The agent then calls the Bridge\'s MCP endpoint, and the Bridge reaches the HPE Order Portal for you with Cross App Access.',
      cardTitle: 'Okta MCP Bridge',
      connectLabel: 'Call the Bridge',
      connectPath: '/api/bridge/connect',
      scopesHead: 'Scopes of the Bridge token',
      traceHint: 'The sign-in → Bridge MCP call steps appear here.',
      welcome: 'Signed in at the Bridge. Ask a question — the agent will call the portal through the Okta MCP Bridge.',
    },
  });
});

app.post('/api/bridge/connect', requireLogin, async (req, res) => {
  const trace: TraceStep[] = [];
  try {
    const tools = await bridgeConnect(req, trace);
    const b = req.session.bridge!;
    res.json({ trace, scope: b.scope, role: undefined, expiresAt: b.expiresAt, tools });
  } catch (e) {
    res.status(errorStatus(e)).json({ ...errorBody(e), trace });
  }
});

app.post('/api/chat', requireLogin, async (req, res) => {
  const message = typeof req.body?.message === 'string' ? req.body.message.trim() : '';
  if (!message || message.length > 4000) return void res.status(400).json({ error: 'invalid_message' });
  const trace: TraceStep[] = [];
  const history = req.session.history ?? [];
  const userLabel = req.session.user?.email ?? req.session.user?.name ?? req.session.user?.sub ?? 'the signed-in user';
  try {
    const token = await ensureToken(req);
    const b = req.session.bridge!;
    const mcpUrl = await resolveMcpUrl(req, token, trace);
    const out = await runAgent({ accessToken: token, userLabel, history, message, mcpUrl });
    trace.push({ step: 1, title: 'Agent called the Okta MCP Bridge', status: 'ok', detail: `${out.toolCalls.length} tool call(s) via ${mcpUrl}; the Bridge exchanged the user's identity with Okta for the portal.` });
    req.session.history = [...history, { role: 'user' as const, content: message }, { role: 'assistant' as const, content: out.reply }].slice(-30);
    req.session.tools = out.tools;
    res.json({ reply: out.reply, toolCalls: out.toolCalls, trace, scope: b.scope, role: undefined, tools: out.tools, expiresAt: b.expiresAt });
  } catch (e) {
    const err = e instanceof McpAuthError ? new BridgeError(`The Bridge rejected the token (${e.message}). Sign in again.`, 'bridge_rejected', 2) : e;
    console.error('chat error:', (err as Error).message);
    res.status(errorStatus(err)).json({ ...errorBody(err), trace });
  }
});

app.post('/api/chat/reset', requireLogin, (req, res) => {
  req.session.history = [];
  res.json({ ok: true });
});

// The web page is shared with the XAA agent (it adapts its wording to /api/me -> ui).
app.use(express.static(path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../agent/public')));

const server = app.listen(bridgeCfg.port, () => {
  console.log(`Bridge agent app on ${bridgeCfg.baseUrl}`);
  console.log(`  Bridge       : ${bridgeCfg.url}  (MCP ${bridgeCfg.mcpUrl})`);
  console.log(`  Client id    : ${bridgeCfg.clientId}${bridgeCfg.clientSecret ? '  (with secret, ' + bridgeCfg.authMethod + ')' : '  (NO SECRET SET: the Bridge in Standard mode needs BRIDGE_CLIENT_SECRET)'}`);
  console.log(`  Redirect URI : ${bridgeCfg.baseUrl}/callback`);
  console.log(`  LLM          : ${cfg.llm.provider} / ${cfg.llm.model}${bridgeCfg.llmBaseUrl ? `  via Kong gateway ${bridgeCfg.llmBaseUrl}` : ''}`);
});
server.on('error', (e: NodeJS.ErrnoException) => {
  if (e.code === 'EADDRINUSE') {
    console.error(`Port ${bridgeCfg.port} is already in use by another program. Change AGENT_BRIDGE_PORT (and AGENT_BRIDGE_BASE_URL).`);
    process.exit(1);
  }
  throw e;
});
