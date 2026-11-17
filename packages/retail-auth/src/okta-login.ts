// Real user sign-in for the authorization-code (gateway) flow: instead of the demo picker, send the person to Okta
// (OIDC authorization code + PKCE) and read WHO they are from the verified ID token.
//
// Which Okta app: RETAIL_LOGIN_CLIENT_ID (defaults to the agent's own app, AGENT_CLIENT_ID, so no extra app is needed for a demo).
// Its redirect URI "<RETAIL_AUTH_ISSUER>/authorize/callback" must be added to that app's Sign-in redirect URIs.
// Client authentication: RETAIL_LOGIN_CLIENT_SECRET if set, otherwise the agent's private key (.keys/agent-private.jwk.json),
// i.e. private_key_jwt exactly like the agent does it.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRemoteJWKSet, importJWK, jwtVerify, SignJWT, type JWK } from 'jose';
import { env, trimSlash } from './env.js';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const mode = env('RETAIL_LOGIN_MODE', 'picker');
if (mode !== 'picker' && mode !== 'okta') throw new Error('RETAIL_LOGIN_MODE must be "picker" or "okta"');
export const LOGIN_MODE: 'picker' | 'okta' = mode;

const b64u = (b: Buffer) => b.toString('base64url');

type Discovery = { authorization_endpoint: string; token_endpoint: string; jwks_uri: string; issuer: string };
let discovery: Promise<{ meta: Discovery; jwks: ReturnType<typeof createRemoteJWKSet> }> | undefined;
function discover() {
  discovery ??= (async () => {
    const issuer = trimSlash(env('OKTA_ISSUER'));
    const r = await fetch(`${issuer}/.well-known/openid-configuration`, { signal: AbortSignal.timeout(10_000) });
    if (!r.ok) throw new Error(`Okta discovery failed: HTTP ${r.status}`);
    const meta = (await r.json()) as Discovery;
    return { meta, jwks: createRemoteJWKSet(new URL(meta.jwks_uri)) };
  })();
  discovery.catch(() => (discovery = undefined)); // retry next time if Okta was unreachable
  return discovery;
}

const clientId = () => env('RETAIL_LOGIN_CLIENT_ID', env('AGENT_CLIENT_ID'));

async function privateKey(): Promise<{ key: CryptoKey; kid?: string }> {
  const file = path.resolve(repoRoot, env('AGENT_PRIVATE_KEY_FILE', '.keys/agent-private.jwk.json'));
  if (!fs.existsSync(file)) {
    throw new Error(`Okta sign-in needs RETAIL_LOGIN_CLIENT_SECRET, or the agent's private key at ${file} (not found)`);
  }
  const jwk = JSON.parse(fs.readFileSync(file, 'utf8')) as JWK;
  const kid = process.env.AGENT_KEY_ID?.trim() || jwk.kid;
  return { key: (await importJWK(jwk, 'RS256')) as CryptoKey, kid };
}

async function clientAuth(tokenEndpoint: string): Promise<Record<string, string>> {
  const secret = process.env.RETAIL_LOGIN_CLIENT_SECRET?.trim();
  if (secret) return { client_id: clientId(), client_secret: secret };
  const { key, kid } = await privateKey();
  const assertion = await new SignJWT({})
    .setProtectedHeader({ alg: 'RS256', ...(kid ? { kid } : {}) })
    .setIssuer(clientId())
    .setSubject(clientId())
    .setAudience(tokenEndpoint) // Okta wants the token endpoint URL as the assertion audience
    .setJti(crypto.randomUUID())
    .setIssuedAt()
    .setExpirationTime('60s')
    .sign(key);
  return { client_id: clientId(), client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer', client_assertion: assertion };
}

export type OktaLoginStart = { url: string; state: string; verifier: string; nonce: string };

export async function startOktaLogin(callbackUrl: string): Promise<OktaLoginStart> {
  const { meta } = await discover();
  const verifier = b64u(crypto.randomBytes(48));
  const state = b64u(crypto.randomBytes(24));
  const nonce = b64u(crypto.randomBytes(24));
  const u = new URL(meta.authorization_endpoint);
  u.search = new URLSearchParams({
    client_id: clientId(),
    response_type: 'code',
    scope: 'openid profile email',
    redirect_uri: callbackUrl,
    state,
    nonce,
    code_challenge: b64u(crypto.createHash('sha256').update(verifier).digest()),
    code_challenge_method: 'S256',
  }).toString();
  return { url: u.href, state, verifier, nonce };
}

export type OktaIdentity = { sub: string; email?: string; name?: string };

/** Exchange the code at Okta and return the verified identity. Throws with a readable message on any failure. */
export async function finishOktaLogin(a: { code: string; callbackUrl: string; verifier: string; nonce: string }): Promise<OktaIdentity> {
  const { meta, jwks } = await discover();
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code: a.code,
    redirect_uri: a.callbackUrl,
    code_verifier: a.verifier,
    ...(await clientAuth(meta.token_endpoint)),
  });
  const r = await fetch(meta.token_endpoint, { method: 'POST', body, headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, signal: AbortSignal.timeout(15_000) });
  const json = (await r.json().catch(() => ({}))) as { id_token?: string; error?: string; error_description?: string };
  if (!r.ok || !json.id_token) throw new Error(`Okta token endpoint: ${json.error ?? r.status}${json.error_description ? ` (${json.error_description})` : ''}`);

  const { payload } = await jwtVerify(json.id_token, jwks, {
    issuer: meta.issuer,
    audience: clientId(),
    algorithms: ['RS256', 'ES256'],
    clockTolerance: 30,
  });
  if (payload.nonce !== a.nonce) throw new Error('ID token nonce does not match this sign-in');
  if (!payload.sub) throw new Error('ID token has no sub');
  return {
    sub: String(payload.sub),
    email: typeof payload.email === 'string' ? payload.email.toLowerCase() : undefined,
    name: typeof payload.name === 'string' ? payload.name : undefined,
  };
}
