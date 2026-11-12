// Retail Authorization Server: the *resource app's* OAuth server in the XAA flow.
//
// It accepts the JWT bearer grant (RFC 7523) whose assertion is an Okta-issued ID-JAG
// (Identity Assertion JWT Authorization Grant, typ "oauth-id-jag+jwt"), validates it, and mints a
// short-lived access token for the Retail Portal. No user interaction/consent happens here: the
// enterprise IdP (Okta) already decided, centrally, that this agent may act for this user.
import crypto from 'node:crypto';
import express, { type Request, type Response } from 'express';
import { createRemoteJWKSet, exportJWK, generateKeyPair, jwtVerify, SignJWT, errors as joseErrors, type JWTPayload } from 'jose';
import { env, trimSlash } from './env.js';
import { ROLE_SCOPES, roleFor } from '../../shared/roles.js';

const PORT = Number(env('AUTH_PORT', '5001'));
const ISSUER = trimSlash(env('RETAIL_AUTH_ISSUER', `http://localhost:${PORT}`));
const RESOURCE = trimSlash(env('RETAIL_RESOURCE', 'http://localhost:3001'));
const OKTA_ISSUER = trimSlash(env('OKTA_ISSUER')); // the trusted enterprise IdP that issues ID-JAGs
const CLIENT_ID = env('RETAIL_AGENT_CLIENT_ID', 'agent-at-retail');
const CLIENT_SECRET = env('RETAIL_AGENT_CLIENT_SECRET', 'change-me-retail-secret');
// Additional agents (each registered in Okta with its own client id): RETAIL_AGENT_CLIENTS="id2:secret2,id3:secret3"
const clients = new Map<string, string>([[CLIENT_ID, CLIENT_SECRET]]);
for (const pair of (process.env.RETAIL_AGENT_CLIENTS ?? '').split(',')) {
  const k = pair.indexOf(':');
  if (k > 0) clients.set(pair.slice(0, k).trim(), pair.slice(k + 1).trim());
}
const TOKEN_TTL = Number(env('ACCESS_TOKEN_TTL_SECONDS', '600'));
const ALLOWED_SCOPES = new Set(
  env('RETAIL_ALLOWED_SCOPES', 'products:read inventory:read orders:read customers:read orders:write returns:read returns:write').split(/\s+/),
);

// ---- signing key (in-memory; regenerated on restart, the portal refetches the JWKS) ---------
const { publicKey, privateKey } = await generateKeyPair('RS256', { extractable: true });
const kid = crypto.randomUUID();
const publicJwk = { ...(await exportJWK(publicKey)), kid, alg: 'RS256', use: 'sig' };

// ---- Okta JWKS (discovered lazily) ----------------------------------------------------------
let oktaJwks: ReturnType<typeof createRemoteJWKSet> | undefined;
async function getOktaJwks() {
  if (!oktaJwks) {
    const r = await fetch(`${OKTA_ISSUER}/.well-known/openid-configuration`);
    if (!r.ok) throw new Error(`Okta discovery failed: HTTP ${r.status}`);
    const meta = (await r.json()) as { jwks_uri: string };
    oktaJwks = createRemoteJWKSet(new URL(meta.jwks_uri));
  }
  return oktaJwks;
}

// ---- ID-JAG replay protection (an ID-JAG is single use) -------------------------------------
const seenJti = new Map<string, number>();
function markUsed(jti: string, exp: number): boolean {
  const now = Date.now();
  for (const [k, v] of seenJti) if (v < now) seenJti.delete(k);
  if (seenJti.has(jti)) return false;
  seenJti.set(jti, exp * 1000 + 60_000);
  return true;
}

class OAuthError extends Error {
  constructor(public error: string, description: string, public status = 400) {
    super(description);
  }
}

const safeEqual = (a: string, b: string) => {
  const ha = crypto.createHash('sha256').update(a).digest();
  const hb = crypto.createHash('sha256').update(b).digest();
  return crypto.timingSafeEqual(ha, hb);
};

function authenticateClient(req: Request): string {
  let id = req.body.client_id as string | undefined;
  let secret = req.body.client_secret as string | undefined;
  const basic = /^Basic (.+)$/i.exec(req.headers.authorization ?? '');
  if (basic) {
    const [u, ...rest] = Buffer.from(basic[1], 'base64').toString().split(':');
    id = decodeURIComponent(u);
    secret = decodeURIComponent(rest.join(':'));
  }
  const expected = id ? clients.get(id) : undefined;
  if (!id || !secret || expected === undefined || !safeEqual(secret, expected)) {
    throw new OAuthError('invalid_client', 'Client authentication failed', 401);
  }
  return id;
}

const JWT_BEARER = 'urn:ietf:params:oauth:grant-type:jwt-bearer';

async function handleJwtBearer(req: Request, clientId: string) {
  const assertion = req.body.assertion as string | undefined;
  if (!assertion) throw new OAuthError('invalid_request', 'Missing assertion');

  let payload: JWTPayload & { client_id?: string; scope?: string; email?: string; resource?: string };
  try {
    ({ payload } = await jwtVerify(assertion, await getOktaJwks(), {
      issuer: OKTA_ISSUER, // iss must be our trusted IdP
      audience: ISSUER, // aud must be THIS authorization server
      typ: 'oauth-id-jag+jwt', // reject ordinary ID/access tokens used as assertions
      algorithms: ['RS256', 'ES256'],
      clockTolerance: 30,
    }));
  } catch (e) {
    if (e instanceof joseErrors.JWTExpired) throw new OAuthError('invalid_grant', 'ID-JAG has expired');
    console.warn('[auth] ID-JAG rejected:', (e as Error).message);
    throw new OAuthError('invalid_grant', `ID-JAG validation failed: ${(e as Error).message}`);
  }

  if (!payload.sub) throw new OAuthError('invalid_grant', 'ID-JAG has no sub');
  if (payload.client_id !== clientId) {
    throw new OAuthError('invalid_grant', 'ID-JAG client_id does not match the authenticated client');
  }
  if (payload.resource && trimSlash(payload.resource) !== RESOURCE) {
    throw new OAuthError('invalid_target', `ID-JAG resource "${payload.resource}" does not match this portal ("${RESOURCE}", from RETAIL_RESOURCE). They must be identical: check the connection's Resource indicator in Okta and restart the services after editing .env`);
  }
  if (!payload.jti || !payload.exp || !markUsed(payload.jti, payload.exp)) {
    throw new OAuthError('invalid_grant', 'ID-JAG has no jti or was already used');
  }

  // Scope = requested ∩ granted-by-Okta (claims.scope) ∩ what this AS is willing to issue.
  const granted = (payload.scope ?? '').split(/\s+/).filter(Boolean);
  const requested: string[] = typeof req.body.scope === 'string' && req.body.scope.trim() ? req.body.scope.trim().split(/\s+/) : granted;
  const afterOkta = requested.filter((s) => granted.includes(s) && ALLOWED_SCOPES.has(s));
  // Per-user reduction: this user's role decides which of those scopes they actually get.
  const role = roleFor(payload.sub, payload.email);
  console.log(`[auth] role "${role}" for ${payload.email ?? payload.sub}`);
  const roleAllows = new Set<string>(ROLE_SCOPES[role]);
  const scopes = afterOkta.filter((s) => roleAllows.has(s));
  const dropped = afterOkta.filter((s) => !roleAllows.has(s));
  if (dropped.length) console.log(`[auth] role "${role}" reduced scopes for ${payload.email ?? payload.sub}: dropped ${dropped.join(' ')}`);
  if (afterOkta.length > 0 && scopes.length === 0) {
    throw new OAuthError('invalid_scope', `This user's role "${role}" may not use any of the requested scopes`);
  }
  if (scopes.length === 0) {
    throw new OAuthError('invalid_scope', `None of the requested scopes were authorized by the IdP (IdP granted: "${granted.join(' ')}")`);
  }

  const accessToken = await new SignJWT({
    scope: scopes.join(' '),
    client_id: clientId,
    ...(payload.email ? { email: payload.email } : {}),
    idp: OKTA_ISSUER,
    role,
  })
    .setProtectedHeader({ alg: 'RS256', typ: 'at+jwt', kid })
    .setIssuer(ISSUER)
    .setAudience(RESOURCE)
    .setSubject(payload.sub)
    .setJti(crypto.randomUUID())
    .setIssuedAt()
    .setExpirationTime(`${TOKEN_TTL}s`)
    .sign(privateKey);

  console.log(`[auth] issued access token sub=${payload.sub} scope="${scopes.join(' ')}" ttl=${TOKEN_TTL}s`);
  return { access_token: accessToken, token_type: 'Bearer', expires_in: TOKEN_TTL, scope: scopes.join(' '), role };
}

const app = express();
app.disable('x-powered-by');

app.get(['/.well-known/oauth-authorization-server', '/.well-known/openid-configuration'], (_req, res) => {
  res.set('X-Retail-Auth', '1'); // lets the startup self-check tell this server apart from another program on the port
  res.json({
    issuer: ISSUER,
    token_endpoint: `${ISSUER}/oauth/token`,
    jwks_uri: `${ISSUER}/jwks.json`,
    grant_types_supported: [JWT_BEARER],
    token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post'],
    scopes_supported: [...ALLOWED_SCOPES],
    // Identity Assertion Authorization Grant: assertion types this server accepts
    identity_assertion_types_supported: ['urn:ietf:params:oauth:token-type:id-jag'],
  });
});
app.get('/jwks.json', (_req, res) => res.json({ keys: [publicJwk] }));

app.post('/oauth/token', express.urlencoded({ extended: false }), async (req: Request, res: Response) => {
  res.set({ 'Cache-Control': 'no-store', Pragma: 'no-cache' });
  try {
    const clientId = authenticateClient(req);
    if (req.body.grant_type !== JWT_BEARER) {
      throw new OAuthError('unsupported_grant_type', `Only ${JWT_BEARER} is supported`);
    }
    res.json(await handleJwtBearer(req, clientId));
  } catch (e) {
    if (e instanceof OAuthError) {
      if (e.status === 401) res.set('WWW-Authenticate', 'Basic realm="retail-auth"');
      return void res.status(e.status).json({ error: e.error, error_description: e.message });
    }
    console.error(e);
    res.status(500).json({ error: 'server_error' });
  }
});

/** Warn if another program answers on the same port over IPv4 or IPv6 (both can be bound by different processes on Windows). */
async function selfCheck() {
  for (const host of ['127.0.0.1', '[::1]']) {
    try {
      const r = await fetch(`http://${host}:${PORT}/.well-known/oauth-authorization-server`, { signal: AbortSignal.timeout(3000) });
      if (r.headers.get('x-retail-auth') !== '1') {
        console.warn(`\n!! Port ${PORT} is shared with ANOTHER program: http://${host}:${PORT} answered HTTP ${r.status} (${r.headers.get('content-type')}), not this server.`);
        console.warn(`!! Requests to "localhost" may reach it instead. Stop that program or change AUTH_PORT and RETAIL_AUTH_ISSUER (and the Issuer URL in Okta).\n`);
      }
    } catch {
      /* that address family isn't bound here; fine */
    }
  }
}

app.listen(PORT, () => {
  void selfCheck();
  console.log(`Retail Authorization Server on ${ISSUER}`);
  console.log(`  Token endpoint : ${ISSUER}/oauth/token  (grant: jwt-bearer / ID-JAG)`);
  console.log(`  Trusted IdP    : ${OKTA_ISSUER}`);
  console.log(`  Issues tokens for: ${RESOURCE}`);
});
