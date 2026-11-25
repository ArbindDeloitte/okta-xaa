// Retail Portal: the XAA *resource app*. Exposes retail tools to AI agents via MCP (and REST),
// accepting only access tokens issued by the Retail Authorization Server in exchange for an
// Okta-issued ID-JAG.
import express, { type NextFunction, type Request, type Response } from 'express';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRemoteJWKSet, decodeJwt, errors as joseErrors, jwtVerify } from 'jose';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { env, trimSlash } from './env.js';
import { buildPrincipal, getAudit, listKnownUsers, recordAudit, ROLE_SCOPES, SCOPES, type Principal } from './governance.js';
import { tools, invokeTool } from './tools.js';
import { customers, inventory, orders, products, returns } from './data.js';

const PORT = Number(env('PORTAL_PORT', '3001'));
const RESOURCE = trimSlash(env('RETAIL_RESOURCE', `http://localhost:${PORT}`));
const AUTH_ISSUER = trimSlash(env('RETAIL_AUTH_ISSUER', 'http://localhost:5001'));
const jwks = createRemoteJWKSet(new URL(`${AUTH_ISSUER}/jwks.json`));

// Optional second token source: an Okta custom authorization server that mints tokens through the OAuth 2.0
// on-behalf-of exchange (RFC 8693). Those tokens are issued by Okta itself, so no retail auth server is involved;
// they name the user (sub/uid) and the agent that acted for them (act.sub). Off unless OBO_ISSUER is set.
// OBO_ISSUER stays ONE url (the OBO agent app uses the same variable as its exchange server). Further Okta servers the portal
// should trust, e.g. the one behind the Okta MCP Bridge, go in OBO_EXTRA_ISSUERS (comma-separated).
const OBO_ISSUERS = [...new Set([env('OBO_ISSUER', ''), ...env('OBO_EXTRA_ISSUERS', '').split(',')].map((v) => trimSlash(v.trim())).filter(Boolean))];
const OBO_AUDIENCE = env('OBO_AUDIENCE', RESOURCE);
const oboJwks = new Map(OBO_ISSUERS.map((iss) => [iss, createRemoteJWKSet(new URL(`${iss}/v1/keys`))]));

/** "sub" of the outermost actor in an RFC 8693 `act` claim (the app that performed the exchange). */
const actorOf = (act: unknown): string | undefined =>
  act && typeof act === 'object' && typeof (act as { sub?: unknown }).sub === 'string' ? (act as { sub: string }).sub : undefined;

declare global {
  namespace Express {
    interface Request {
      principal?: Principal;
    }
  }
}

const app = express();
app.disable('x-powered-by');

// The MCP endpoint is the resource identifier itself when that has a path (e.g. https://host/mcp, the convention
// used by GitHub/Slack MCP and what Okta Agent Gateway calls); a bare base URL keeps the older "<base>/mcp" layout.
const RESOURCE_PATH = new URL(RESOURCE).pathname.replace(/\/+$/, '');
const MCP_PATH = RESOURCE_PATH || '/mcp';

// ---- OAuth protected resource metadata (RFC 9728) -------------------------------------------
// Served at the root well-known URL and, for a resource with a path, at the path-inserted URL
// (/.well-known/oauth-protected-resource/mcp) that RFC 9728 clients such as Okta fetch.
const METADATA_URL = `${new URL(RESOURCE).origin}/.well-known/oauth-protected-resource${RESOURCE_PATH}`;
app.get(['/.well-known/oauth-protected-resource', `/.well-known/oauth-protected-resource${RESOURCE_PATH}`], (_req, res) => {
  res.set('X-Retail-Portal', '1'); // lets the startup self-check tell this server apart from another program on the port
  res.json({
    resource: RESOURCE,
    authorization_servers: [AUTH_ISSUER],
    scopes_supported: Object.keys(SCOPES),
    bearer_methods_supported: ['header'],
    resource_name: 'Retail Portal MCP',
  });
});

// ---- bearer token validation ----------------------------------------------------------------
async function requireBearer(req: Request, res: Response, next: NextFunction) {
  const challenge = (error: string, desc: string) => {
    res
      .status(401)
      .set('WWW-Authenticate', `Bearer error="${error}", error_description="${desc}", resource_metadata="${METADATA_URL}"`)
      .json({ error, error_description: desc });
  };
  const m = /^Bearer (.+)$/i.exec(req.headers.authorization ?? '');
  if (!m) return challenge('invalid_request', 'Missing bearer token');
  try {
    let issuer: unknown;
    try { issuer = decodeJwt(m[1]).iss; } catch { /* not a JWT: the verification below rejects it */ }
    const keysOfIssuer = typeof issuer === 'string' ? oboJwks.get(trimSlash(issuer)) : undefined;
    if (keysOfIssuer) {
      // Okta on-behalf-of token: verified against Okta's keys. Okta access tokens carry the user as `sub` (login, usually an
      // email) and `uid` (the 00u… id), the calling app as `cid`, and scopes as the array `scp`.
      const { payload } = await jwtVerify(m[1], keysOfIssuer, { issuer: trimSlash(issuer as string), audience: OBO_AUDIENCE, algorithms: ['RS256'] });
      const login = String(payload.sub);
      req.principal = buildPrincipal({
        sub: typeof payload.uid === 'string' ? payload.uid : login,
        email: typeof payload.email === 'string' ? payload.email : login.includes('@') ? login : undefined,
        client_id: String(payload.cid ?? payload.azp ?? 'unknown'),
        actor: actorOf(payload.act),
        jti: payload.jti,
        scope: Array.isArray(payload.scp) ? payload.scp.join(' ') : typeof payload.scp === 'string' ? payload.scp : '',
        // no role claim: Okta does not know our roles, so the portal applies PORTAL_USER_ROLES / the default itself
      });
      return next();
    }
    const { payload } = await jwtVerify(m[1], jwks, {
      issuer: AUTH_ISSUER,
      audience: RESOURCE,
      typ: 'at+jwt',
      algorithms: ['RS256'],
    });
    req.principal = buildPrincipal({
      sub: String(payload.sub),
      email: typeof payload.email === 'string' ? payload.email : undefined,
      client_id: String(payload.client_id),
      jti: payload.jti,
      scope: typeof payload.scope === 'string' ? payload.scope : '',
      role: payload.role, // set by the auth server (PORTAL_USER_ROLES entry or the default)
    });
    next();
  } catch (e) {
    const desc = e instanceof joseErrors.JWTExpired ? 'Token expired' : 'Invalid token';
    let iss = '';
    try { iss = String(decodeJwt(m[1]).iss ?? ''); } catch { /* not a JWT */ }
    recordAudit({ via: 'auth', user: 'unknown', tool: 'bearer-validation', decision: 'deny', reason: `${desc}: ${(e as Error).message}${iss ? ` (iss ${iss})` : ''}` });
    challenge('invalid_token', desc);
  }
}

// ---- MCP endpoint (stateless Streamable HTTP; one server instance per request) --------------
app.post(MCP_PATH, requireBearer, express.json(), async (req, res) => {
  const p = req.principal!;
  const server = new McpServer({ name: 'retail-portal', version: '1.0.0' });

  // The agent only *sees* tools its signed-in user may use (token scopes granted by Okta AND the user's role).
  for (const def of tools.filter((t) => p.effectiveScopes.includes(t.scope))) {
    server.registerTool(def.name, { description: def.description, inputSchema: def.input }, async (args: unknown) => {
      const r = invokeTool(def, args, p, 'mcp');
      return {
        content: [{ type: 'text' as const, text: JSON.stringify(r.ok ? r.data : { error: r.code, message: r.error }, null, 2) }],
        isError: !r.ok,
      };
    });
  }

  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
  res.on('close', () => {
    transport.close();
    server.close();
  });
  try {
    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  } catch (e) {
    console.error('MCP error', e);
    if (!res.headersSent) res.status(500).json({ jsonrpc: '2.0', error: { code: -32603, message: 'Internal error' }, id: null });
  }
});
const methodNotAllowed = (_req: Request, res: Response) =>
  res.status(405).json({ jsonrpc: '2.0', error: { code: -32000, message: 'Method not allowed (stateless server)' }, id: null });
app.get(MCP_PATH, methodNotAllowed);
app.delete(MCP_PATH, methodNotAllowed);

// ---- REST API (same tools, same governance) -------------------------------------------------
app.get('/api/me', requireBearer, (req, res) => {
  const p = req.principal!;
  res.json({ sub: p.sub, email: p.email, role: p.role, clientId: p.clientId, actor: p.actor, tokenScopes: p.tokenScopes, effectiveScopes: p.effectiveScopes });
});
app.post('/api/tools/:name', requireBearer, express.json(), (req, res) => {
  const def = tools.find((t) => t.name === req.params.name);
  if (!def) return void res.status(404).json({ error: 'unknown_tool' });
  const r = invokeTool(def, req.body, req.principal!, 'rest');
  if (r.ok) return void res.json(r.data);
  const status = r.code === 'insufficient_scope' || r.code === 'forbidden_for_role' ? 403 : r.code === 'not_found' ? 404 : 400;
  res.status(status).json({ error: r.code, message: r.error });
});

// ---- admin console (demo; loopback only unless PORTAL_CONSOLE_PUBLIC=true) ------------------
const isLoopback = (a?: string) => !!a && ['127.0.0.1', '::1', '::ffff:127.0.0.1'].includes(a);
const consoleGuard = (req: Request, res: Response, next: NextFunction) => {
  if (env('PORTAL_CONSOLE_PUBLIC', 'false') === 'true' || isLoopback(req.socket.remoteAddress)) return next();
  res.status(403).send('The portal console is only available on localhost.');
};
app.get('/admin/api/state', consoleGuard, (_req, res) => {
  res.json({
    orders: [...orders].sort((a, b) => b.placedAt.localeCompare(a.placedAt)).map((o) => ({ ...o, customer: customers.find((c) => c.id === o.customerId)?.name })),
    returns,
    inventory: products.map((p) => ({ sku: p.sku, name: p.name, price: p.price, stock: inventory[p.sku] })),
    users: listKnownUsers(),
    roles: ROLE_SCOPES,
    scopes: SCOPES,
  });
});
app.get('/admin/api/audit', consoleGuard, (req, res) => res.json(getAudit(Number(req.query.since ?? 0))));

const here = path.dirname(fileURLToPath(import.meta.url));
app.use('/', consoleGuard, express.static(path.resolve(here, '../public')));

/** Warn if another program answers on this port over IPv4 or IPv6 (different processes can each hold one on Windows). */
async function selfCheck() {
  for (const host of ['127.0.0.1', '[::1]']) {
    try {
      const r = await fetch(`http://${host}:${PORT}/.well-known/oauth-protected-resource`, { signal: AbortSignal.timeout(3000) });
      if (r.headers.get('x-retail-portal') !== '1') {
        console.warn(`\n!! Port ${PORT} is shared with ANOTHER program: http://${host}:${PORT} answered HTTP ${r.status}, not this server.`);
        console.warn(`!! Requests to "localhost" may reach it instead. Stop it or change PORTAL_PORT and RETAIL_RESOURCE (and the Resource indicator in Okta).\n`);
      }
    } catch {
      /* that address family isn't bound here; fine */
    }
  }
}

const server = app.listen(PORT, () => {
  void selfCheck();
  console.log(`Retail Portal (resource server + MCP) on ${RESOURCE}`);
  console.log(`  MCP endpoint : ${RESOURCE}/mcp`);
  console.log(`  Console      : ${RESOURCE}/`);
  console.log(`  Trusts AS    : ${AUTH_ISSUER}`);
  for (const iss of OBO_ISSUERS) console.log(`  Also trusts  : ${iss} (Okta tokens, audience ${OBO_AUDIENCE})`);
});
server.on('error', (e: NodeJS.ErrnoException) => {
  if (e.code === 'EADDRINUSE') {
    console.error(`Port ${PORT} is already in use by another program. Change PORTAL_PORT and RETAIL_RESOURCE (and the Resource indicator in Okta).`);
    process.exit(1);
  }
  throw e;
});
