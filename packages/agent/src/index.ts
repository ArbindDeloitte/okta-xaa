// Agent app: the XAA *requesting app*. Users sign in with Okta (OIDC + PKCE); the agent then uses
// Cross App Access to get a Retail Portal token on the user's behalf, and chats with Claude.
import express, { type NextFunction, type Request, type Response } from 'express';
import session from 'express-session';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import * as oidc from 'openid-client';
import { decodeJwt } from 'jose';
import { cfg } from './config.js';
import { ConsentRequiredError, listRetailTools, McpAuthError, runAgent, type ChatMessage, type ToolInfo } from './agent.js';
import { agentSigningKey, oktaTokenEndpoint, performXaa, XaaError, type RetailAccess, type TraceStep } from './xaa.js';
import { gatewayEnabled, gatewayOidc, gatewayTokensFrom, refreshGatewayTokens, testGateway } from './gateway.js';
import { callAgentOverA2a, hrAgentConfigured, performA2aExchange, HrAccessError, type HrAccess } from './a2a.js';

declare module 'express-session' {
  interface SessionData {
    login?: { verifier: string; state: string; nonce: string; gateway?: boolean; returnTo?: string };
    gateway?: { accessToken: string; refreshToken?: string; expiresAt: number };
    idToken?: string;
    refreshToken?: string;
    user?: { sub: string; name?: string; email?: string };
    retail?: RetailAccess;
    /** Direct A2A: a cached access token for the HPE HR Agent, from the same user session as `retail`. */
    hr?: HrAccess;
    tools?: ToolInfo[];
    history?: ChatMessage[];
  }
}

// ---- Okta OIDC client (discovery) -----------------------------------------------------------
const oktaConfig = await (async () => {
  const tokenEndpoint = await oktaTokenEndpoint();
  const auth =
    cfg.okta.authMethod === 'private_key_jwt'
      ? oidc.PrivateKeyJwt({ key: await agentSigningKey(), kid: cfg.okta.privateJwk!.kid }, {
          // Okta expects the client assertion's aud to be the token endpoint URL.
          [oidc.modifyAssertion]: (_h, payload) => {
            payload.aud = tokenEndpoint;
          },
        })
      : undefined;
  // openid-client enforces HTTPS; plain http:// issuers are only for local mock testing.
  const insecure = cfg.okta.issuer.startsWith('http://');
  return oidc.discovery(new URL(cfg.okta.issuer), cfg.okta.clientId, cfg.okta.clientSecret, auth, insecure ? { execute: [oidc.allowInsecureRequests] } : undefined);
})();

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1); // behind Caddy: without this the "secure" session cookie is never sent over the proxy's HTTP hop
app.use(express.json({ limit: '100kb' }));
app.use(
  session({
    name: `agent.${cfg.port}.sid`, // per-port so two agent instances on localhost do not overwrite each other's cookie
    secret: cfg.sessionSecret,
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, sameSite: 'lax', secure: cfg.baseUrl.startsWith('https://'), maxAge: 8 * 3600_000 },
  }),
);

const esc = (s: string) => s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);

const requireLogin = (req: Request, res: Response, next: NextFunction) =>
  req.session.idToken ? next() : void res.status(401).json({ error: 'not_authenticated' });

// ---- login / logout -------------------------------------------------------------------------
app.get('/login', async (req, res, next) => {
  try {
    const verifier = oidc.randomPKCECodeVerifier();
    const state = oidc.randomState();
    const nonce = oidc.randomNonce();
    req.session.login = { verifier, state, nonce };
    const url = oidc.buildAuthorizationUrl(oktaConfig, {
      redirect_uri: `${cfg.baseUrl}/callback`,
      scope: 'openid profile email offline_access',
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

// ---- Okta Agent Gateway test mode (optional) ------------------------------------------------
// Sign in to the gateway's authorization server (same Okta app + redirect URI as the normal login), then call the
// gateway's MCP URL instead of doing XAA ourselves. Page: /gateway.html
app.get('/gateway/login', requireLogin, async (req, res, next) => {
  try {
    if (!gatewayEnabled()) return void res.status(404).send('Set GATEWAY_MCP_URL in .env to enable the gateway test.');
    const { config, scopes } = await gatewayOidc();
    const verifier = oidc.randomPKCECodeVerifier();
    const state = oidc.randomState();
    const nonce = oidc.randomNonce();
    const returnTo = req.query.return === '/' ? '/' : '/gateway.html'; // fixed allow-list, never an arbitrary URL
    req.session.login = { verifier, state, nonce, gateway: true, returnTo };
    const url = oidc.buildAuthorizationUrl(config, {
      redirect_uri: `${cfg.baseUrl}/callback`,
      scope: scopes.join(' '),
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

class GatewaySignInRequired extends Error {}

/** A valid gateway access token for this browser session: reuse it, refresh it, or ask the user to sign in to the gateway. */
async function ensureGatewayToken(req: Request): Promise<string> {
  const g = req.session.gateway;
  if (g && g.expiresAt - Date.now() > 30_000) return g.accessToken;
  if (g?.refreshToken) {
    try {
      req.session.gateway = await refreshGatewayTokens(g.refreshToken);
      return req.session.gateway.accessToken;
    } catch (e) {
      console.warn('Gateway token refresh failed:', (e as Error).message);
    }
  }
  req.session.gateway = undefined;
  throw new GatewaySignInRequired();
}
const gatewayNeedsSignIn = { error: 'gateway_not_signed_in', message: 'Sign in to the Okta Agent Gateway first.', loginUrl: '/gateway/login?return=/' };

app.post('/api/gateway/test', requireLogin, async (req, res) => {
  try {
    res.json(await testGateway(await ensureGatewayToken(req)));
  } catch (e) {
    if (e instanceof GatewaySignInRequired) return void res.status(401).json(gatewayNeedsSignIn);
    res.status(502).json({ error: 'gateway_error', message: (e as Error).message });
  }
});

/** Gateway mode: list the tools the gateway exposes to this user (shown in the governance panel). */
app.post('/api/gateway/connect', requireLogin, async (req, res) => {
  if (!gatewayEnabled()) return void res.status(400).json({ error: 'gateway_disabled', message: 'Set GATEWAY_MCP_URL in .env to enable gateway mode.' });
  const t0 = Date.now();
  try {
    const token = await ensureGatewayToken(req);
    const tools = await listRetailTools(token, cfg.gateway.mcpUrl);
    res.json({ tools, expiresAt: req.session.gateway?.expiresAt, trace: gatewayTrace(tools.length, Date.now() - t0) });
  } catch (e) {
    if (e instanceof GatewaySignInRequired) return void res.status(401).json(gatewayNeedsSignIn);
    res.status(502).json({ error: 'gateway_error', message: (e as Error).message });
  }
});

const gatewayTrace = (toolCount: number, ms: number): TraceStep[] => [
  { step: 1, title: 'Agent holds an Okta token for the gateway', status: 'ok', detail: 'Authorization code + PKCE at the gateway\'s Okta authorization server (same Okta app as the sign-in).' },
  { step: 2, title: 'Agent calls the Okta Agent Gateway MCP URL', status: 'ok', ms, detail: `${cfg.gateway.mcpUrl}: ${toolCount} tools exposed` },
  { step: 3, title: 'Gateway adds the portal credential (brokered consent)', status: 'ok', detail: 'The agent never sees it. Our auth server still applies the user\'s role and scopes; the portal enforces them again.' },
];

app.get('/api/gateway/status', (req, res) => {
  const g = req.session.gateway;
  res.json({ enabled: gatewayEnabled(), url: cfg.gateway.mcpUrl || null, mainSignedIn: Boolean(req.session.idToken), gatewaySignedIn: Boolean(g && (g.expiresAt > Date.now() || g.refreshToken)) });
});

app.get('/callback', async (req, res) => {
  const login = req.session.login;
  if (!login) return void res.status(400).send('Login session missing or expired. <a href="/login">Try again</a>.');
  if (login.gateway) {
    try {
      const { config } = await gatewayOidc();
      const tokens = await oidc.authorizationCodeGrant(config, new URL(`${cfg.baseUrl}${req.originalUrl}`), {
        pkceCodeVerifier: login.verifier,
        expectedState: login.state,
        expectedNonce: login.nonce,
        idTokenExpected: true,
      });
      const returnTo = login.returnTo === '/' ? '/' : '/gateway.html';
      req.session.login = undefined;
      req.session.gateway = gatewayTokensFrom(tokens);
      return void req.session.save(() => res.redirect(returnTo));
    } catch (e) {
      console.error('Gateway sign-in failed', e);
      return void res.status(400).send(`Gateway sign-in failed: ${esc((e as Error).message)}. <a href="/gateway.html">Back</a>.`);
    }
  }
  try {
    const tokens = await oidc.authorizationCodeGrant(oktaConfig, new URL(`${cfg.baseUrl}${req.originalUrl}`), {
      pkceCodeVerifier: login.verifier,
      expectedState: login.state,
      expectedNonce: login.nonce,
      idTokenExpected: true,
    });
    const claims = tokens.claims()!;
    // Regenerate to avoid session fixation, then store the identity.
    req.session.regenerate((err) => {
      if (err) return void res.status(500).send('Session error');
      req.session.idToken = tokens.id_token;
      req.session.refreshToken = tokens.refresh_token;
      req.session.user = { sub: claims.sub, name: claims.name as string | undefined, email: claims.email as string | undefined };
      req.session.history = [];
      req.session.save(() => res.redirect('/'));
    });
  } catch (e) {
    console.error('Login failed', e);
    res.status(400).send(`Sign-in failed: ${(e as Error).message}. <a href="/login">Try again</a>.`);
  }
});

app.get('/logout', (req, res) => {
  const idToken = req.session.idToken;
  req.session.destroy(() => {
    res.clearCookie(`agent.${cfg.port}.sid`);
    if (process.env.AGENT_OKTA_LOGOUT === 'true' && idToken) {
      // Requires `${baseUrl}/` to be registered as a sign-out redirect URI in Okta.
      const url = oidc.buildEndSessionUrl(oktaConfig, { id_token_hint: idToken, post_logout_redirect_uri: `${cfg.baseUrl}/` });
      return void res.redirect(url.href);
    }
    res.redirect('/');
  });
});

// ---- XAA helpers ----------------------------------------------------------------------------
// One refresh-token-consuming exchange at a time per browser session: Okta ROTATES the refresh token on every
// use, so two concurrent exchanges (even of DIFFERENT kinds -- the portal XAA below and the HR Agent's own A2A
// exchange in a2a.ts both read/write req.session.refreshToken) would present the same now-stale token and one
// would fail. This single lock serializes every such exchange for a session, whichever kind it is.
const refreshInflight = new Map<string, Promise<unknown>>();
async function withRefreshLock<T>(sessionID: string, fn: () => Promise<T>): Promise<T> {
  const pending = refreshInflight.get(sessionID);
  if (pending) await pending.catch(() => {}); // let it settle (either way) before we touch the refresh token too
  const run = fn();
  refreshInflight.set(sessionID, run);
  try {
    return await run;
  } finally {
    if (refreshInflight.get(sessionID) === run) refreshInflight.delete(sessionID);
  }
}

async function ensureRetailAccess(req: Request, trace: TraceStep[], force = false): Promise<RetailAccess> {
  const cached = req.session.retail;
  if (!force && cached && cached.expiresAt - Date.now() > 60_000) {
    trace.push({ step: 0, title: 'Reused cached Retail Portal access token', status: 'skipped', detail: `valid for another ${Math.round((cached.expiresAt - Date.now()) / 1000)}s` });
    return cached;
  }
  return withRefreshLock(req.sessionID, async () => {
    // Re-check: another exchange for this session may have refreshed it while we waited for the lock.
    const fresh = req.session.retail;
    if (!force && fresh && fresh.expiresAt - Date.now() > 60_000) {
      trace.push({ step: 0, title: 'Reused cached Retail Portal access token', status: 'skipped', detail: `valid for another ${Math.round((fresh.expiresAt - Date.now()) / 1000)}s` });
      return fresh;
    }
    const tokens = { idToken: req.session.idToken!, refreshToken: req.session.refreshToken };
    const access = await performXaa(tokens, trace);
    req.session.refreshToken = tokens.refreshToken; // may have rotated
    req.session.retail = access;
    req.session.tools = await listRetailTools(access.accessToken);
    return access;
  });
}

// ---- Direct A2A helpers (the HPE HR Agent) --------------------------------------------------
/** Gets (and caches) an access token for the HR Agent, from the SAME user session as the portal token.
 * Returns undefined when HR_AGENT_URL / HR_AGENT_AUTH_ISSUER are not set, so the caller can degrade cleanly. */
async function ensureHrAccess(req: Request, trace: TraceStep[]): Promise<HrAccess | undefined> {
  if (!hrAgentConfigured()) return undefined;
  const cached = req.session.hr;
  if (cached && cached.expiresAt - Date.now() > 60_000) return cached;
  return withRefreshLock(req.sessionID, async () => {
    const fresh = req.session.hr;
    if (fresh && fresh.expiresAt - Date.now() > 60_000) return fresh;
    // Unlike the retail exchange, this always uses the ID token (see a2a.ts), which Okta does not rotate -- so
    // there is nothing to write back to the session here, just the resulting HR access token itself below.
    const access = await performA2aExchange({ idToken: req.session.idToken! }, trace);
    req.session.hr = access;
    return access;
  });
}

/** Builds the askHrAgent closure runAgent() calls when the model invokes the ask_hr_agent tool. Does the
 * exchange (and caches it) lazily, on first use, not on every chat turn -- an ID-JAG is single-use and Okta
 * limits XAA to a monthly quota per user per resource app. */
function hrAgentTool(req: Request, trace: TraceStep[]): ((task: string) => Promise<{ text: string; isError: boolean }>) | undefined {
  if (!hrAgentConfigured()) return undefined;
  return async (task: string) => {
    try {
      const access = await ensureHrAccess(req, trace);
      if (!access) return { text: 'The HR Agent is not configured on this server.', isError: true };
      const text = await callAgentOverA2a(cfg.hrAgent.url, task, () => access.accessToken);
      return { text, isError: false };
    } catch (e) {
      if (e instanceof HrAccessError) return { text: `HR Agent call failed: ${e.message}`, isError: true };
      return { text: `HR Agent call failed: ${(e as Error).message}`, isError: true };
    }
  };
}

const errorBody = (e: unknown) =>
  e instanceof XaaError
    ? { error: e.code, message: e.message, step: e.step }
    : e instanceof HrAccessError
      ? { error: e.code, message: e.message }
      : { error: 'agent_error', message: (e as Error).message };
const errorStatus = (e: unknown) => (e instanceof XaaError && (e.code === 'id_token_expired' || (e.code === 'invalid_grant' && e.step === 2)) ? 401 : 502);

// ---- API ------------------------------------------------------------------------------------
app.get('/api/me', (req, res) => {
  res.set('X-Retail-Agent', '1'); // used by the startup port self-check
  const s = req.session;
  res.json({
    authenticated: Boolean(s.idToken),
    user: s.user,
    retail: s.retail ? { scope: s.retail.scope, role: s.retail.role, expiresAt: s.retail.expiresAt } : null,
    tools: s.tools ?? [],
    model: cfg.llm.model,
    agentName: cfg.agentName,
    gateway: { enabled: gatewayEnabled(), signedIn: Boolean(s.gateway && (s.gateway.expiresAt > Date.now() || s.gateway.refreshToken)) },
    hrAgent: { enabled: hrAgentConfigured(), scope: s.hr?.scope ?? [], expiresAt: s.hr?.expiresAt },
    idTokenExpiresAt: s.idToken ? (decodeJwt(s.idToken).exp ?? 0) * 1000 : null,
    llmConfigured: cfg.llm.provider === 'groq' ? Boolean(cfg.llm.groq.apiKey) : Boolean(process.env.ANTHROPIC_API_KEY || process.env.ANTHROPIC_AUTH_TOKEN || process.env.BEDROCK_API_KEY),
    provider: cfg.llm.provider,
  });
});

/** Run (or re-run) the XAA exchange without chatting, to show the flow and granted tools. */
app.post('/api/xaa/connect', requireLogin, async (req, res) => {
  const trace: TraceStep[] = [];
  try {
    const access = await ensureRetailAccess(req, trace, true);
    res.json({ trace, scope: access.scope, role: access.role, expiresAt: access.expiresAt, tools: req.session.tools ?? [] });
  } catch (e) {
    res.status(errorStatus(e)).json({ ...errorBody(e), trace });
  }
});

/** Direct A2A: run the Cross App Access exchange with the HR Agent's own authorization server, without
 * chatting, so the trace (and any Okta error) can be inspected on its own -- same idea as /api/xaa/connect. */
app.post('/api/hr/connect', requireLogin, async (req, res) => {
  const trace: TraceStep[] = [];
  try {
    if (!hrAgentConfigured()) return void res.status(400).json({ error: 'hr_agent_not_configured', message: 'Set HR_AGENT_URL and HR_AGENT_AUTH_ISSUER in .env, then restart.', trace });
    req.session.hr = undefined; // force a fresh exchange, the same way /api/xaa/connect forces one
    const access = await ensureHrAccess(req, trace);
    res.json({ trace, scope: access?.scope ?? [], expiresAt: access?.expiresAt });
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

  if (req.body?.mode === 'gateway') {
    // Gateway mode: no XAA here. The agent talks to the Okta Agent Gateway with its Okta token; the gateway calls the portal.
    if (!gatewayEnabled()) return void res.status(400).json({ error: 'gateway_disabled', message: 'Set GATEWAY_MCP_URL in .env to enable gateway mode.' });
    const t0 = Date.now();
    try {
      const token = await ensureGatewayToken(req);
      const out = await runAgent({ accessToken: token, mcpUrl: cfg.gateway.mcpUrl, userLabel, history, message });
      req.session.history = [...history, { role: 'user' as const, content: message }, { role: 'assistant' as const, content: out.reply }].slice(-30);
      return void res.json({ reply: out.reply, toolCalls: out.toolCalls, trace: gatewayTrace(out.tools.length, Date.now() - t0), scope: [], tools: out.tools, expiresAt: req.session.gateway?.expiresAt, mode: 'gateway', hr: { scope: req.session.hr?.scope ?? [], expiresAt: req.session.hr?.expiresAt } });
    } catch (e) {
      if (e instanceof GatewaySignInRequired || e instanceof McpAuthError) {
        req.session.gateway = undefined;
        return void res.status(401).json(gatewayNeedsSignIn);
      }
      if (e instanceof ConsentRequiredError) return void res.status(409).json({ error: 'consent_required', message: e.message, consentUrl: e.url, trace });
      console.error('gateway chat error:', (e as Error).message);
      return void res.status(502).json({ error: 'gateway_error', message: (e as Error).message, trace });
    }
  }

  try {
    let access = await ensureRetailAccess(req, trace);
    const askHrAgent = hrAgentTool(req, trace);
    let out;
    try {
      out = await runAgent({ accessToken: access.accessToken, userLabel, history, message, askHrAgent });
    } catch (e) {
      if (!(e instanceof McpAuthError)) throw e;
      // Token rejected by the portal (e.g. portal restarted with new keys): redo XAA once.
      access = await ensureRetailAccess(req, trace, true);
      out = await runAgent({ accessToken: access.accessToken, userLabel, history, message, askHrAgent });
    }
    req.session.history = [...history, { role: 'user' as const, content: message }, { role: 'assistant' as const, content: out.reply }].slice(-30);
    req.session.tools = out.tools;
    res.json({ reply: out.reply, toolCalls: out.toolCalls, trace, scope: access.scope, role: access.role, tools: out.tools, expiresAt: access.expiresAt, hr: { scope: req.session.hr?.scope ?? [], expiresAt: req.session.hr?.expiresAt } });
  } catch (e) {
    console.error('chat error:', (e as Error).message);
    res.status(errorStatus(e)).json({ ...errorBody(e), trace });
  }
});

app.post('/api/chat/reset', requireLogin, (req, res) => {
  req.session.history = [];
  res.json({ ok: true });
});

app.use(express.static(path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../public')));

/** Warn if another program answers on this port over IPv4 or IPv6 (different processes can each hold one on Windows). */
async function selfCheck() {
  for (const host of ['127.0.0.1', '[::1]']) {
    try {
      const r = await fetch(`http://${host}:${cfg.port}/api/me`, { signal: AbortSignal.timeout(3000) });
      if (r.headers.get('x-retail-agent') !== '1') {
        console.warn(`\n!! Port ${cfg.port} is shared with ANOTHER program: http://${host}:${cfg.port} answered HTTP ${r.status}, not this app. Change AGENT_PORT and AGENT_BASE_URL (and the redirect URI in Okta).\n`);
      }
    } catch {
      /* that address family isn't bound here; fine */
    }
  }
}

const server = app.listen(cfg.port, () => {
  void selfCheck();
  console.log(`Agent app on ${cfg.baseUrl}`);
  console.log(`  Okta issuer : ${cfg.okta.issuer}  (client ${cfg.okta.clientId}, ${cfg.okta.authMethod})`);
  console.log(`  Retail MCP  : ${cfg.retail.mcpUrl}`);
  console.log(`  HR Agent    : ${hrAgentConfigured() ? `${cfg.hrAgent.url}  (direct A2A, trusts ${cfg.hrAgent.authIssuer})` : '(not configured: set HR_AGENT_URL and HR_AGENT_AUTH_ISSUER to enable ask_hr_agent)'}`);
  console.log(`  LLM         : ${cfg.llm.provider} / ${cfg.llm.model}${cfg.llm.provider === 'groq' ? (cfg.llm.groq.apiKey ? '' : '  (GROQ_API_KEY not set!)') : (process.env.ANTHROPIC_API_KEY || process.env.BEDROCK_API_KEY ? '' : '  (ANTHROPIC_API_KEY not set!)') + (process.env.ANTHROPIC_BASE_URL ? `  via ${process.env.ANTHROPIC_BASE_URL}` : '')}`);
});
server.on('error', (e: NodeJS.ErrnoException) => {
  if (e.code === 'EADDRINUSE') {
    console.error(`Port ${cfg.port} is already in use by another program. Change AGENT_PORT and AGENT_BASE_URL (and the redirect URI in Okta).`);
    process.exit(1);
  }
  throw e;
});
