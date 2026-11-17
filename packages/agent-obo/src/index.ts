// Agent app #2: the same HPE Ops Agent, but it reaches the HPE Order Portal with Okta's OAuth 2.0 on-behalf-of (OBO)
// token exchange instead of Cross App Access. Same portal, same data, same MCP tools; only the way the agent gets its
// token differs. Users sign in to an Okta custom authorization server (OIDC code + PKCE); an API Services app then
// exchanges the user's access token for a portal token that names the user (sub) and this agent (act).
import express, { type NextFunction, type Request, type Response } from 'express';
import session from 'express-session';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import * as oidc from 'openid-client';
import { cfg } from '../../agent/src/config.js';
import { listRetailTools, McpAuthError, runAgent, type ChatMessage, type ToolInfo } from '../../agent/src/agent.js';
import type { TraceStep } from '../../agent/src/xaa.js';
import { missingConfig, oboCfg } from './config.js';
import { OboError, performObo, type OboAccess } from './obo.js';

declare module 'express-session' {
  interface SessionData {
    login?: { verifier: string; state: string; nonce: string };
    subject?: { accessToken: string; refreshToken?: string; expiresAt: number };
    user?: { sub: string; name?: string; email?: string };
    obo?: OboAccess;
    tools?: ToolInfo[];
    history?: ChatMessage[];
  }
}

const missing = missingConfig();
if (missing.length) {
  console.error('The OBO agent needs these settings in .env (see docs/OBO_AGENT.md):\n  ' + missing.join('\n  '));
  process.exit(1);
}

// ---- Okta OIDC client for the custom authorization server -----------------------------------
// Users sign in at the login server; the exchange (see obo.ts) goes to the other server, OBO_ISSUER, when they differ.
const loginConfig = await oidc.discovery(
  new URL(oboCfg.loginIssuer),
  oboCfg.login.clientId,
  oboCfg.login.clientSecret || undefined,
  oboCfg.login.clientSecret ? undefined : oidc.None(), // public client (native app) + PKCE
  oboCfg.loginIssuer.startsWith('http://') ? { execute: [oidc.allowInsecureRequests] } : undefined, // plain http only for the local mock
);

const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '100kb' }));
app.use(
  session({
    name: `agent-obo.${oboCfg.port}.sid`,
    secret: oboCfg.sessionSecret,
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, sameSite: 'lax', secure: oboCfg.baseUrl.startsWith('https://'), maxAge: 8 * 3600_000 },
  }),
);

const esc = (s: string) => s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);
const requireLogin = (req: Request, res: Response, next: NextFunction) =>
  req.session.subject ? next() : void res.status(401).json({ error: 'not_authenticated' });

// ---- sign in / out --------------------------------------------------------------------------
app.get('/login', async (req, res, next) => {
  try {
    const verifier = oidc.randomPKCECodeVerifier();
    const state = oidc.randomState();
    const nonce = oidc.randomNonce();
    req.session.login = { verifier, state, nonce };
    const url = oidc.buildAuthorizationUrl(loginConfig, {
      redirect_uri: `${oboCfg.baseUrl}/callback`,
      scope: `openid profile email${oboCfg.offlineAccess ? ' offline_access' : ''}`,
      code_challenge: await oidc.calculatePKCECodeChallenge(verifier),
      code_challenge_method: 'S256',
      state,
      nonce,
    });
    req.session.save(() => res.redirect(url.href));
  } catch (e) {
    next(e);
  }
});

app.get('/callback', async (req, res) => {
  const login = req.session.login;
  if (!login) return void res.status(400).send('Login session missing or expired. <a href="/login">Try again</a>.');
  try {
    const tokens = await oidc.authorizationCodeGrant(loginConfig, new URL(`${oboCfg.baseUrl}${req.originalUrl}`), {
      pkceCodeVerifier: login.verifier,
      expectedState: login.state,
      expectedNonce: login.nonce,
      idTokenExpected: true,
    });
    const claims = tokens.claims()!;
    req.session.regenerate((err) => {
      if (err) return void res.status(500).send('Session error');
      req.session.subject = { accessToken: tokens.access_token, refreshToken: tokens.refresh_token, expiresAt: Date.now() + (tokens.expires_in ?? 3600) * 1000 };
      req.session.user = { sub: claims.sub, name: claims.name as string | undefined, email: claims.email as string | undefined };
      req.session.history = [];
      req.session.save(() => res.redirect('/'));
    });
  } catch (e) {
    console.error('Login failed', e);
    res.status(400).send(`Sign-in failed: ${esc((e as Error).message)}. <a href="/login">Try again</a>.`);
  }
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.clearCookie(`agent-obo.${oboCfg.port}.sid`);
    res.redirect('/');
  });
});

// ---- the OBO exchange -----------------------------------------------------------------------
/** The user's own access token, renewed with the refresh token when it is about to expire. */
async function ensureSubjectToken(req: Request): Promise<string> {
  const s = req.session.subject!;
  if (s.expiresAt - Date.now() > 30_000) return s.accessToken;
  if (s.refreshToken) {
    try {
      const t = await oidc.refreshTokenGrant(loginConfig, s.refreshToken);
      req.session.subject = { accessToken: t.access_token, refreshToken: t.refresh_token ?? s.refreshToken, expiresAt: Date.now() + (t.expires_in ?? 3600) * 1000 };
      return t.access_token;
    } catch (e) {
      console.warn('Subject token refresh failed:', (e as Error).message);
    }
  }
  throw new OboError('Your Okta session expired. Sign in again.', 'id_token_expired', 1);
}

/** Ask the portal what it makes of the token (role, effective scopes, acting agent): the last step of the trace. */
async function portalView(accessToken: string, trace: TraceStep[]): Promise<{ role?: string }> {
  const t0 = Date.now();
  try {
    const r = await fetch(new URL('/api/me', cfg.retail.mcpUrl), { headers: { Authorization: `Bearer ${accessToken}` }, signal: AbortSignal.timeout(10_000) });
    const j = (await r.json().catch(() => ({}))) as { role?: string; clientId?: string; actor?: string; effectiveScopes?: string[]; error_description?: string };
    if (!r.ok) {
      trace.push({ step: 3, title: 'HPE Order Portal rejected the token', status: 'error', ms: Date.now() - t0, detail: `HTTP ${r.status}: ${j.error_description ?? 'check OBO_ISSUER / OBO_AUDIENCE on the portal'}` });
      throw new OboError(`The portal rejected the OBO token (HTTP ${r.status}). Set OBO_ISSUER and OBO_AUDIENCE for the portal in .env and restart it.`, 'portal_rejected', 3);
    }
    trace.push({
      step: 3,
      title: 'HPE Order Portal verified the token against Okta\'s keys',
      status: 'ok',
      ms: Date.now() - t0,
      detail: `user role: ${j.role} · agent (act): ${j.actor ?? 'none'} · effective scopes: ${(j.effectiveScopes ?? []).join(' ')}`,
    });
    return { role: j.role };
  } catch (e) {
    if (e instanceof OboError) throw e;
    throw new OboError(`Cannot reach the portal at ${cfg.retail.mcpUrl}: ${(e as Error).message}`, 'portal_unreachable', 3);
  }
}

// One exchange at a time per browser session (cheap insurance against double clicks).
const inflight = new Map<string, Promise<OboAccess>>();

async function ensureAccess(req: Request, trace: TraceStep[], force = false): Promise<OboAccess> {
  const pending = inflight.get(req.sessionID);
  if (pending) return pending;
  const cached = req.session.obo;
  if (!force && cached && cached.expiresAt - Date.now() > 60_000) {
    trace.push({ step: 0, title: 'Reused cached Retail Portal access token', status: 'skipped', detail: `valid for another ${Math.round((cached.expiresAt - Date.now()) / 1000)}s` });
    return cached;
  }
  const run = (async () => {
    const access = await performObo(await ensureSubjectToken(req), trace);
    access.role = (await portalView(access.accessToken, trace)).role;
    req.session.obo = access;
    req.session.tools = await listRetailTools(access.accessToken);
    return access;
  })();
  inflight.set(req.sessionID, run);
  try {
    return await run;
  } finally {
    inflight.delete(req.sessionID);
  }
}

const errorBody = (e: unknown) =>
  e instanceof OboError ? { error: e.code, message: e.message, step: e.step } : { error: 'agent_error', message: (e as Error).message };
const errorStatus = (e: unknown) => (e instanceof OboError && e.code === 'id_token_expired' ? 401 : 502);

// ---- API (same shape as the XAA agent, so the same web page works) --------------------------
app.get('/api/me', (req, res) => {
  const s = req.session;
  res.json({
    authenticated: Boolean(s.subject),
    user: s.user,
    retail: s.obo ? { scope: s.obo.scope, role: s.obo.role, expiresAt: s.obo.expiresAt } : null,
    tools: s.tools ?? [],
    model: cfg.llm.model,
    agentName: oboCfg.agentName,
    gateway: { enabled: false, signedIn: false },
    llmConfigured: cfg.llm.provider === 'groq' ? Boolean(cfg.llm.groq.apiKey) : Boolean(process.env.ANTHROPIC_API_KEY || process.env.ANTHROPIC_AUTH_TOKEN || process.env.BEDROCK_API_KEY),
    provider: cfg.llm.provider,
    // Texts the shared page shows instead of its Cross App Access wording.
    ui: {
      subtitle: 'Okta on-behalf-of (OBO) demo',
      heroText: 'Sign in with Okta. The agent then exchanges your access token <strong>on your behalf (OAuth token exchange, RFC 8693)</strong> for an HPE Order Portal token that names both you and the agent.',
      cardTitle: 'On-Behalf-Of exchange',
      connectLabel: 'Run OBO exchange',
      connectPath: '/api/obo/connect',
      scopesHead: 'Scopes in the OBO token',
      traceHint: 'The sign-in → OBO exchange → portal steps appear here.',
      welcome: 'Signed in. Ask a question — the agent will exchange your Okta token (on-behalf-of) for an HPE Order Portal token.',
    },
  });
});

app.post('/api/obo/connect', requireLogin, async (req, res) => {
  const trace: TraceStep[] = [];
  try {
    const access = await ensureAccess(req, trace, true);
    res.json({ trace, scope: access.scope, role: access.role, expiresAt: access.expiresAt, tools: req.session.tools ?? [] });
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
    let access = await ensureAccess(req, trace);
    let out;
    try {
      out = await runAgent({ accessToken: access.accessToken, userLabel, history, message });
    } catch (e) {
      if (!(e instanceof McpAuthError)) throw e;
      access = await ensureAccess(req, trace, true); // token rejected by the portal: exchange once more
      out = await runAgent({ accessToken: access.accessToken, userLabel, history, message });
    }
    req.session.history = [...history, { role: 'user' as const, content: message }, { role: 'assistant' as const, content: out.reply }].slice(-30);
    req.session.tools = out.tools;
    res.json({ reply: out.reply, toolCalls: out.toolCalls, trace, scope: access.scope, role: access.role, tools: out.tools, expiresAt: access.expiresAt });
  } catch (e) {
    console.error('chat error:', (e as Error).message);
    res.status(errorStatus(e)).json({ ...errorBody(e), trace });
  }
});

app.post('/api/chat/reset', requireLogin, (req, res) => {
  req.session.history = [];
  res.json({ ok: true });
});

// The web page is shared with the XAA agent (it adapts its wording to /api/me -> ui).
app.use(express.static(path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../agent/public')));

const server = app.listen(oboCfg.port, () => {
  console.log(`OBO agent app on ${oboCfg.baseUrl}`);
  console.log(`  Sign-in at  : ${oboCfg.loginIssuer}`);
  console.log(`  OBO token by: ${oboCfg.issuer} (audience ${oboCfg.audience})${oboCfg.loginIssuer === oboCfg.issuer ? ' - one server for both' : ''}`);
  console.log(`  Portal MCP  : ${cfg.retail.mcpUrl}`);
  console.log(`  LLM         : ${cfg.llm.provider} / ${cfg.llm.model}`);
});
server.on('error', (e: NodeJS.ErrnoException) => {
  if (e.code === 'EADDRINUSE') {
    console.error(`Port ${oboCfg.port} is already in use by another program. Change AGENT_OBO_PORT (and AGENT_OBO_BASE_URL, and the redirect URI in Okta).`);
    process.exit(1);
  }
  throw e;
});
