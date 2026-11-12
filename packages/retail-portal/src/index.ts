// Retail Portal: the XAA *resource app*. Exposes retail tools to AI agents via MCP (and REST),
// accepting only access tokens issued by the Retail Authorization Server in exchange for an
// Okta-issued ID-JAG.
import express, { type NextFunction, type Request, type Response } from 'express';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRemoteJWKSet, errors as joseErrors, jwtVerify } from 'jose';
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

declare global {
  namespace Express {
    interface Request {
      principal?: Principal;
    }
  }
}

const app = express();
app.disable('x-powered-by');

// ---- OAuth protected resource metadata (RFC 9728) -------------------------------------------
app.get('/.well-known/oauth-protected-resource', (_req, res) => {
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
      .set('WWW-Authenticate', `Bearer error="${error}", error_description="${desc}", resource_metadata="${RESOURCE}/.well-known/oauth-protected-resource"`)
      .json({ error, error_description: desc });
  };
  const m = /^Bearer (.+)$/i.exec(req.headers.authorization ?? '');
  if (!m) return challenge('invalid_request', 'Missing bearer token');
  try {
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
    recordAudit({ via: 'auth', user: 'unknown', tool: 'bearer-validation', decision: 'deny', reason: `${desc}: ${(e as Error).message}` });
    challenge('invalid_token', desc);
  }
}

// ---- MCP endpoint (stateless Streamable HTTP; one server instance per request) --------------
app.post('/mcp', requireBearer, express.json(), async (req, res) => {
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
app.get('/mcp', methodNotAllowed);
app.delete('/mcp', methodNotAllowed);

// ---- REST API (same tools, same governance) -------------------------------------------------
app.get('/api/me', requireBearer, (req, res) => {
  const p = req.principal!;
  res.json({ sub: p.sub, email: p.email, role: p.role, clientId: p.clientId, tokenScopes: p.tokenScopes, effectiveScopes: p.effectiveScopes });
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
});
server.on('error', (e: NodeJS.ErrnoException) => {
  if (e.code === 'EADDRINUSE') {
    console.error(`Port ${PORT} is already in use by another program. Change PORTAL_PORT and RETAIL_RESOURCE (and the Resource indicator in Okta).`);
    process.exit(1);
  }
  throw e;
});
