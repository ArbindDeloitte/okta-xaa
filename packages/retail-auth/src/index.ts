// Retail Authorization Server: the *resource app's* OAuth server in the XAA flow.
//
// It accepts the JWT bearer grant (RFC 7523) whose assertion is an Okta-issued ID-JAG
// (Identity Assertion JWT Authorization Grant, typ "oauth-id-jag+jwt"), validates it, and mints a
// short-lived access token for the Retail Portal. No user interaction/consent happens here: the
// enterprise IdP (Okta) already decided, centrally, that this agent may act for this user.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import express, { type Request, type Response } from 'express';
import { createRemoteJWKSet, exportJWK, generateKeyPair, importJWK, jwtVerify, SignJWT, errors as joseErrors, type JWK, type JWTPayload, type KeyLike } from 'jose';
import { env, trimSlash } from './env.js';
import { defaultRole, knownUsers, ROLE_SCOPES, roleFor, type Role } from '../../shared/roles.js';
import { finishOktaLogin, LOGIN_MODE, startOktaLogin } from './okta-login.js';

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

// ---- signing key + refresh tokens: persisted in .keys/ (git-ignored) ------------------------------
// Okta Agent Gateway keeps the tokens it got for a long time, so a restart of this server must NOT invalidate them:
// the signing key and the refresh tokens (stored hashed) survive restarts. Delete the files to reset.
const STATE_DIR = path.resolve(env('RETAIL_AUTH_STATE_DIR', path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../../.keys')));
const KEY_FILE = path.join(STATE_DIR, 'retail-auth-signing.jwk.json');
const REFRESH_FILE = path.join(STATE_DIR, 'retail-auth-refresh.json');
fs.mkdirSync(STATE_DIR, { recursive: true });

let privateKey: KeyLike;
let kid: string;
let publicJwk: JWK;
{
  let stored: { jwk: JWK; kid: string } | undefined;
  try {
    stored = JSON.parse(fs.readFileSync(KEY_FILE, 'utf8'));
  } catch {
    /* first run (or unreadable): generate below */
  }
  if (stored) {
    privateKey = (await importJWK(stored.jwk, 'RS256')) as KeyLike;
    kid = stored.kid;
    const { n, e, kty } = stored.jwk;
    publicJwk = { kty, n, e, kid, alg: 'RS256', use: 'sig' };
  } else {
    const pair = await generateKeyPair('RS256', { extractable: true });
    privateKey = pair.privateKey;
    kid = crypto.randomUUID();
    publicJwk = { ...(await exportJWK(pair.publicKey)), kid, alg: 'RS256', use: 'sig' };
    fs.writeFileSync(KEY_FILE, JSON.stringify({ jwk: await exportJWK(pair.privateKey), kid }), { mode: 0o600 });
    console.log(`[auth] generated a new signing key (kid ${kid}) in ${KEY_FILE}`);
  }
}

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

function authenticateClient(req: Request, registry: Map<string, string> = clients): string {
  let id = req.body.client_id as string | undefined;
  let secret = req.body.client_secret as string | undefined;
  const basic = /^Basic (.+)$/i.exec(req.headers.authorization ?? '');
  if (basic) {
    const [u, ...rest] = Buffer.from(basic[1], 'base64').toString().split(':');
    id = decodeURIComponent(u);
    secret = decodeURIComponent(rest.join(':'));
  }
  const expected = id ? registry.get(id) : undefined;
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

  const accessToken = await mintAccessToken({ sub: payload.sub, email: payload.email, clientId, scopes, role, idp: OKTA_ISSUER });
  console.log(`[auth] issued access token sub=${payload.sub} scope="${scopes.join(' ')}" ttl=${TOKEN_TTL}s`);
  return { access_token: accessToken, token_type: 'Bearer', expires_in: TOKEN_TTL, scope: scopes.join(' '), role };
}

/** The portal access token (RS256 at+jwt), identical whichever grant produced it. */
async function mintAccessToken(a: { sub: string; email?: string; clientId: string; scopes: string[]; role: Role; idp: string }) {
  return new SignJWT({
    scope: a.scopes.join(' '),
    client_id: a.clientId,
    ...(a.email ? { email: a.email } : {}),
    idp: a.idp,
    role: a.role,
  })
    .setProtectedHeader({ alg: 'RS256', typ: 'at+jwt', kid })
    .setIssuer(ISSUER)
    .setAudience(RESOURCE)
    .setSubject(a.sub)
    .setJti(crypto.randomUUID())
    .setIssuedAt()
    .setExpirationTime(`${TOKEN_TTL}s`)
    .sign(privateKey);
}

// ---- Authorization-code flow (for Okta Agent Gateway "brokered consent") ---------------------
// The gateway sends a person here once; they pick who they are and approve; the gateway gets a code,
// swaps it for tokens and keeps the refresh token. The role in PORTAL_USER_ROLES still caps the scopes.
// DEMO sign-in: a picker, not real authentication. Enabled only when RETAIL_GATEWAY_CLIENT_SECRET is set.
const GW_CLIENT_ID = env('RETAIL_GATEWAY_CLIENT_ID', 'okta-gateway-test');
const GW_CLIENT_SECRET = (process.env.RETAIL_GATEWAY_CLIENT_SECRET ?? '').trim();
const GW_REDIRECT_URIS = new Set((process.env.RETAIL_GATEWAY_REDIRECT_URIS ?? '').split(/[\s,]+/).filter(Boolean));
const gatewayClients = new Map<string, string>(GW_CLIENT_SECRET ? [[GW_CLIENT_ID, GW_CLIENT_SECRET]] : []);
const REFRESH_TTL_MS = Number(env('REFRESH_TOKEN_TTL_SECONDS', String(8 * 3600))) * 1000;
const txKey = crypto.randomBytes(32); // signs the consent form so it cannot be forged or replayed after 10 minutes

type CodeRecord = { clientId: string; redirectUri: string; challenge: string; sub: string; email: string; scopes: string[]; exp: number };
// `scopes` is what the gateway ASKED for, not what the role allowed at consent time: the role caps it each time a token is
// issued, so a role change (up or down) applies to the next refresh. v: 2 marks records stored that way.
type RefreshRecord = { clientId: string; sub: string; email: string; scopes: string[]; exp: number; v?: number };
const codes = new Map<string, CodeRecord>();
// Keyed by sha256(refresh token): the file never holds a usable token.
const refreshTokens = new Map<string, RefreshRecord>();
const hashToken = (t: string) => crypto.createHash('sha256').update(t).digest('hex');
try {
  const now = Date.now();
  for (const [k, v] of Object.entries(JSON.parse(fs.readFileSync(REFRESH_FILE, 'utf8')) as Record<string, RefreshRecord>)) {
    // older records kept only the role-capped scopes and could never widen: drop them so Okta asks the user to consent again
    if (v.exp > now && v.v === 2) refreshTokens.set(k, v);
  }
  if (refreshTokens.size) console.log(`[auth] restored ${refreshTokens.size} gateway refresh token(s)`);
} catch {
  /* none stored yet */
}
const saveRefresh = () => fs.writeFileSync(REFRESH_FILE, JSON.stringify(Object.fromEntries(refreshTokens)), { mode: 0o600 });
const sweep = () => {
  const now = Date.now();
  for (const [k, v] of codes) if (v.exp < now) codes.delete(k);
  for (const [k, v] of refreshTokens) if (v.exp < now) refreshTokens.delete(k);
};

const b64u = (b: Buffer) => b.toString('base64url');
const esc = (s: string) => s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);
const signTx = (data: object) => {
  const body = b64u(Buffer.from(JSON.stringify({ ...data, exp: Date.now() + 600_000 })));
  return `${body}.${b64u(crypto.createHmac('sha256', txKey).update(body).digest())}`;
};
function readTx(tx: unknown): AuthRequest | undefined {
  if (typeof tx !== 'string') return undefined;
  const [body, sig] = tx.split('.');
  if (!body || !sig) return undefined;
  const good = b64u(crypto.createHmac('sha256', txKey).update(body).digest());
  if (!safeEqual(sig, good)) return undefined;
  const data = JSON.parse(Buffer.from(body, 'base64url').toString()) as AuthRequest & { exp: number };
  return data.exp > Date.now() ? data : undefined;
}

/** `identity` is set once Okta has signed the person in (RETAIL_LOGIN_MODE=okta); the demo picker leaves it unset. */
type AuthRequest = { redirectUri: string; state?: string; challenge: string; scopes: string[]; identity?: { sub: string; email?: string } };

// Okta sign-in in progress, keyed by the OIDC `state` we sent to Okta (short-lived, in memory).
const pendingLogins = new Map<string, { request: AuthRequest; verifier: string; nonce: string; exp: number }>();
const callbackUrl = () => `${ISSUER}/authorize/callback`;

/** Scopes this person may have: requested ∩ what this AS issues ∩ what their role allows. */
function scopesForUser(requested: string[], role: Role): string[] {
  const roleAllows = new Set<string>(ROLE_SCOPES[role]);
  return requested.filter((s) => ALLOWED_SCOPES.has(s) && roleAllows.has(s));
}

function redirectWith(redirectUri: string, params: Record<string, string | undefined>) {
  const u = new URL(redirectUri);
  for (const [k, v] of Object.entries(params)) if (v !== undefined) u.searchParams.set(k, v);
  return u.href;
}

function page(title: string, body: string) {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)}</title>
<style>body{font:15px system-ui,sans-serif;background:#f4f5f7;margin:0;display:grid;place-items:center;min-height:100vh}main{background:#fff;max-width:520px;width:calc(100% - 32px);padding:28px;border-radius:10px;box-shadow:0 2px 12px #0002}
h1{font-size:20px;margin:0 0 4px}.mark{background:#01a982;color:#fff;font-weight:700;padding:2px 8px;border-radius:4px;margin-right:6px}.muted{color:#667}label{display:block;padding:8px 10px;border:1px solid #d5d8dd;border-radius:6px;margin:6px 0}
code{background:#eef0f3;padding:1px 5px;border-radius:4px}.row{display:flex;gap:10px;margin-top:18px}button{font:inherit;padding:9px 18px;border-radius:6px;border:1px solid #bbb;background:#fff;cursor:pointer}button.p{background:#01a982;border-color:#01a982;color:#fff}input[type=text]{font:inherit;width:100%;box-sizing:border-box;margin-top:6px;padding:6px}</style></head><body><main>${body}</main></body></html>`;
}
const sendPage = (res: Response, status: number, title: string, body: string) =>
  void res.status(status).set({ 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store', 'X-Frame-Options': 'DENY', 'Content-Security-Policy': "frame-ancestors 'none'" }).send(page(title, body));

async function handleAuthorizeGet(req: Request, res: Response) {
  if (gatewayClients.size === 0) return sendPage(res, 503, 'Not enabled', '<h1>Authorization-code sign-in is not enabled</h1><p class="muted">Set <code>RETAIL_GATEWAY_CLIENT_SECRET</code> (and <code>RETAIL_GATEWAY_REDIRECT_URIS</code>) in .env and restart.</p>');
  const q = req.query as Record<string, string | undefined>;
  // Problems with client_id / redirect_uri must NOT redirect (the target is unverified).
  if (q.client_id !== GW_CLIENT_ID) return sendPage(res, 400, 'Error', '<h1>Unknown client</h1><p class="muted">client_id is not registered.</p>');
  if (!q.redirect_uri || !GW_REDIRECT_URIS.has(q.redirect_uri)) {
    return sendPage(res, 400, 'Error', `<h1>redirect_uri not allowed</h1><p class="muted">Add <code>${esc(q.redirect_uri ?? '(missing)')}</code> to <code>RETAIL_GATEWAY_REDIRECT_URIS</code> in .env and restart.</p>`);
  }
  const fail = (error: string, description: string) => void res.redirect(redirectWith(q.redirect_uri!, { error, error_description: description, state: q.state, iss: ISSUER }));
  if (q.response_type !== 'code') return fail('unsupported_response_type', 'Only response_type=code is supported');
  if (!q.code_challenge || q.code_challenge_method !== 'S256') return fail('invalid_request', 'PKCE with code_challenge_method=S256 is required');
  if (q.resource && trimSlash(q.resource) !== RESOURCE) return fail('invalid_target', `resource must be ${RESOURCE}`);
  const requested = (q.scope ?? '').split(/\s+/).filter(Boolean);
  const scopes = (requested.length ? requested : [...ALLOWED_SCOPES]).filter((s) => ALLOWED_SCOPES.has(s));
  if (scopes.length === 0) return fail('invalid_scope', 'No supported scopes requested');

  if (LOGIN_MODE === 'okta') {
    // Real sign-in: hand the person to Okta; the callback shows the consent screen for the verified identity.
    try {
      const login = await startOktaLogin(callbackUrl());
      const now = Date.now();
      for (const [k, v] of pendingLogins) if (v.exp < now) pendingLogins.delete(k);
      pendingLogins.set(login.state, { request: { redirectUri: q.redirect_uri, state: q.state, challenge: q.code_challenge, scopes }, verifier: login.verifier, nonce: login.nonce, exp: now + 600_000 });
      return void res.redirect(login.url);
    } catch (e) {
      console.error('[auth] could not start the Okta sign-in:', (e as Error).message);
      return sendPage(res, 502, 'Error', `<h1>Could not start the Okta sign-in</h1><p class="muted">${esc((e as Error).message)}</p>`);
    }
  }

  const tx = signTx({ redirectUri: q.redirect_uri, state: q.state, challenge: q.code_challenge, scopes } satisfies AuthRequest);
  const users = knownUsers();
  const userRows = users
    .map((u, i) => `<label><input type="radio" name="user" value="${esc(u.id)}"${i === 0 ? ' checked' : ''}> <strong>${esc(u.id)}</strong> <span class="muted">role ${esc(u.role)}, ${scopesForUser(scopes, u.role).length} of ${scopes.length} scopes</span></label>`)
    .join('');
  sendPage(
    res,
    200,
    'Sign in',
    `<h1><span class="mark">HPE</span>Order Portal</h1>
<p class="muted">Okta Agent Gateway is asking to access the HPE Order Portal on your behalf.</p>
<p>Requested: ${scopes.map((s) => `<code>${esc(s)}</code>`).join(' ')}</p>
<form method="post" action="/authorize/decision"><input type="hidden" name="tx" value="${esc(tx)}">
<p><strong>Who are you?</strong> <span class="muted">(demo sign-in; your role decides which of these you actually get)</span></p>
${userRows}
<label><input type="radio" name="user" value="__other"${users.length === 0 ? ' checked' : ''}> Someone else (default role <strong>${esc(defaultRole())}</strong>)<input type="text" name="other_email" placeholder="name@company.com" maxlength="254"></label>
<div class="row"><button class="p" name="decision" value="approve">Approve</button><button name="decision" value="deny">Deny</button></div></form>`,
  );
}

/** Okta sent the person back: verify who they are, then show the consent screen (no identity choice any more). */
async function handleAuthorizeCallback(req: Request, res: Response) {
  const q = req.query as Record<string, string | undefined>;
  const pending = q.state ? pendingLogins.get(q.state) : undefined;
  if (q.state) pendingLogins.delete(q.state); // single use
  if (!pending || pending.exp < Date.now()) return sendPage(res, 400, 'Expired', '<h1>This sign-in expired</h1><p class="muted">Start again from Okta.</p>');
  const { request } = pending;
  const back = (params: Record<string, string>) => void res.redirect(redirectWith(request.redirectUri, { ...params, state: request.state, iss: ISSUER }));
  if (q.error) return back({ error: q.error === 'access_denied' ? 'access_denied' : 'server_error', error_description: `Okta sign-in: ${q.error_description ?? q.error}` });
  if (!q.code) return back({ error: 'invalid_request', error_description: 'Okta returned no code' });

  let who;
  try {
    who = await finishOktaLogin({ code: q.code, callbackUrl: callbackUrl(), verifier: pending.verifier, nonce: pending.nonce });
  } catch (e) {
    console.error('[auth] Okta sign-in failed:', (e as Error).message);
    return back({ error: 'access_denied', error_description: 'Okta sign-in failed' });
  }
  const role = roleFor(who.sub, who.email);
  const scopes = scopesForUser(request.scopes, role);
  console.log(`[auth] Okta sign-in for ${who.email ?? who.sub} (sub ${who.sub}), role "${role}"`);
  if (scopes.length === 0) return back({ error: 'access_denied', error_description: `Role "${role}" may not use any requested scope` });

  const tx = signTx({ ...request, identity: { sub: who.sub, email: who.email } } satisfies AuthRequest);
  sendPage(
    res,
    200,
    'Approve access',
    `<h1><span class="mark">HPE</span>Order Portal</h1>
<p class="muted">Okta Agent Gateway is asking to access the HPE Order Portal on your behalf.</p>
<p>Signed in as <strong>${esc(who.name ?? who.email ?? who.sub)}</strong>${who.email && who.name ? ` <span class="muted">(${esc(who.email)})</span>` : ''}<br>
Your portal role is <strong>${esc(role)}</strong>, so the gateway can get: ${scopes.map((s) => `<code>${esc(s)}</code>`).join(' ')}</p>
${scopes.length < request.scopes.length ? `<p class="muted">Not allowed for your role: ${request.scopes.filter((s) => !scopes.includes(s)).map((s) => `<code>${esc(s)}</code>`).join(' ')}</p>` : ''}
<form method="post" action="/authorize/decision"><input type="hidden" name="tx" value="${esc(tx)}">
<div class="row"><button class="p" name="decision" value="approve">Approve</button><button name="decision" value="deny">Deny</button></div></form>`,
  );
}

function handleAuthorizeDecision(req: Request, res: Response) {
  const tx = readTx(req.body.tx);
  if (!tx) return sendPage(res, 400, 'Expired', '<h1>This sign-in request expired</h1><p class="muted">Start again from Okta.</p>');
  const back = (params: Record<string, string>) => void res.redirect(redirectWith(tx.redirectUri, { ...params, state: tx.state, iss: ISSUER }));
  if (req.body.decision !== 'approve') return back({ error: 'access_denied', error_description: 'The user denied the request' });

  let sub: string;
  let email: string;
  if (tx.identity) {
    // Verified by Okta (the signed tx carries it, so it cannot be changed by the browser).
    sub = tx.identity.sub;
    email = tx.identity.email ?? '';
  } else {
    if (LOGIN_MODE === 'okta') return sendPage(res, 400, 'Error', '<h1>Sign in with Okta first</h1><p class="muted">Start again from Okta.</p>');
    // Demo picker (RETAIL_LOGIN_MODE=picker): the person chooses who they are. NOT real authentication.
    let who = typeof req.body.user === 'string' ? req.body.user : '';
    if (who === '__other') who = typeof req.body.other_email === 'string' ? req.body.other_email.trim() : '';
    who = who.toLowerCase();
    if (!/^[^\s@]+@[^\s@]+$/.test(who) || who.length > 254) {
      // ids in PORTAL_USER_ROLES that are not emails (Okta ids) are still valid sub values
      if (!knownUsers().some((u) => u.id === who)) return sendPage(res, 400, 'Error', '<h1>Enter a valid email address</h1><p class="muted">Go back and try again.</p>');
    }
    sub = who;
    email = who;
  }
  const role = roleFor(sub, email);
  const scopes = scopesForUser(tx.scopes, role);
  if (scopes.length === 0) return back({ error: 'access_denied', error_description: `Role "${role}" may not use any requested scope` });

  sweep();
  const code = b64u(crypto.randomBytes(32));
  codes.set(code, { clientId: GW_CLIENT_ID, redirectUri: tx.redirectUri, challenge: tx.challenge, sub, email, scopes: tx.scopes, exp: Date.now() + 60_000 });
  console.log(`[auth] authorization code issued to ${email || sub} (role "${role}", ${scopes.length} scopes)`);
  back({ code });
}

async function issueGatewayTokens(clientId: string, sub: string, email: string, scopes: string[]) {
  const role = roleFor(sub, email);
  const granted = scopesForUser(scopes, role); // the role may have changed since consent, in either direction
  if (granted.length === 0) throw new OAuthError('invalid_scope', `Role "${role}" may not use any of the granted scopes`);
  const refresh = b64u(crypto.randomBytes(32));
  sweep();
  refreshTokens.set(hashToken(refresh), { clientId, sub, email, scopes, exp: Date.now() + REFRESH_TTL_MS, v: 2 });
  saveRefresh();
  const accessToken = await mintAccessToken({ sub, email, clientId, scopes: granted, role, idp: 'retail-auth-demo-login' });
  console.log(`[auth] issued gateway tokens sub=${sub} role="${role}" scope="${granted.join(' ')}"`);
  return { access_token: accessToken, token_type: 'Bearer', expires_in: TOKEN_TTL, scope: granted.join(' '), refresh_token: refresh, role };
}

async function handleAuthCode(req: Request, clientId: string) {
  const code = typeof req.body.code === 'string' ? req.body.code : '';
  const rec = codes.get(code);
  codes.delete(code); // single use, even if the checks below fail
  if (!rec || rec.exp < Date.now()) throw new OAuthError('invalid_grant', 'Authorization code is invalid, expired or already used');
  if (rec.clientId !== clientId) throw new OAuthError('invalid_grant', 'Code was issued to a different client');
  if (req.body.redirect_uri !== rec.redirectUri) throw new OAuthError('invalid_grant', 'redirect_uri does not match the authorization request');
  const verifier = typeof req.body.code_verifier === 'string' ? req.body.code_verifier : '';
  const challenge = b64u(crypto.createHash('sha256').update(verifier).digest());
  if (verifier.length < 43 || verifier.length > 128 || !safeEqual(challenge, rec.challenge)) {
    throw new OAuthError('invalid_grant', 'PKCE code_verifier does not match');
  }
  return issueGatewayTokens(clientId, rec.sub, rec.email, rec.scopes);
}

async function handleRefresh(req: Request, clientId: string) {
  const token = typeof req.body.refresh_token === 'string' ? req.body.refresh_token : '';
  const rec = refreshTokens.get(hashToken(token));
  refreshTokens.delete(hashToken(token)); // rotation: every refresh token is single use
  saveRefresh();
  if (!rec || rec.exp < Date.now() || rec.clientId !== clientId) throw new OAuthError('invalid_grant', 'Refresh token is invalid or expired');
  const narrower = typeof req.body.scope === 'string' ? req.body.scope.split(/\s+/).filter(Boolean) : [];
  const scopes = narrower.length ? rec.scopes.filter((s) => narrower.includes(s)) : rec.scopes;
  if (scopes.length === 0) throw new OAuthError('invalid_scope', 'Requested scope is outside the original grant');
  return issueGatewayTokens(clientId, rec.sub, rec.email, scopes);
}

const app = express();
app.disable('x-powered-by');

app.get(['/.well-known/oauth-authorization-server', '/.well-known/openid-configuration'], (_req, res) => {
  res.set('X-Retail-Auth', '1'); // lets the startup self-check tell this server apart from another program on the port
  res.json({
    issuer: ISSUER,
    token_endpoint: `${ISSUER}/oauth/token`,
    jwks_uri: `${ISSUER}/jwks.json`,
    ...(gatewayClients.size ? { authorization_endpoint: `${ISSUER}/authorize`, response_types_supported: ['code'], code_challenge_methods_supported: ['S256'] } : {}),
    grant_types_supported: gatewayClients.size ? [JWT_BEARER, 'authorization_code', 'refresh_token'] : [JWT_BEARER],
    token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post'],
    scopes_supported: [...ALLOWED_SCOPES],
    // Identity Assertion Authorization Grant: assertion types this server accepts
    identity_assertion_types_supported: ['urn:ietf:params:oauth:token-type:id-jag'],
  });
});
app.get('/jwks.json', (_req, res) => res.json({ keys: [publicJwk] }));

app.get('/authorize', handleAuthorizeGet);
app.get('/authorize/callback', handleAuthorizeCallback);
app.post('/authorize/decision', express.urlencoded({ extended: false, limit: '8kb' }), handleAuthorizeDecision);

app.post('/oauth/token', express.urlencoded({ extended: false }), async (req: Request, res: Response) => {
  res.set({ 'Cache-Control': 'no-store', Pragma: 'no-cache' });
  try {
    const grant = req.body.grant_type;
    if (grant === JWT_BEARER) {
      res.json(await handleJwtBearer(req, authenticateClient(req)));
    } else if (grant === 'authorization_code' && gatewayClients.size) {
      res.json(await handleAuthCode(req, authenticateClient(req, gatewayClients)));
    } else if (grant === 'refresh_token' && gatewayClients.size) {
      res.json(await handleRefresh(req, authenticateClient(req, gatewayClients)));
    } else {
      throw new OAuthError('unsupported_grant_type', `Supported: ${JWT_BEARER}${gatewayClients.size ? ', authorization_code, refresh_token' : ''}`);
    }
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
  console.log(
    gatewayClients.size
      ? `  Gateway sign-in: ${ISSUER}/authorize  (client ${GW_CLIENT_ID}, ${GW_REDIRECT_URIS.size} redirect URI(s)${GW_REDIRECT_URIS.size ? '' : ' !! set RETAIL_GATEWAY_REDIRECT_URIS'}); user sign-in: ${LOGIN_MODE === 'okta' ? `Okta (add ${callbackUrl()} to the Okta app's Sign-in redirect URIs)` : 'demo picker (set RETAIL_LOGIN_MODE=okta for real sign-in)'}`
      : '  Gateway sign-in: off (set RETAIL_GATEWAY_CLIENT_SECRET to enable the authorization-code flow)',
  );
  console.log(`  Issues tokens for: ${RESOURCE}`);
});
