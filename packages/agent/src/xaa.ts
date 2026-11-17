// Cross App Access (XAA) client flow, per the Identity Assertion JWT Authorization Grant draft:
//
//   1. Token Exchange (RFC 8693) at the ENTERPRISE IdP (Okta): trade the user's ID token for an
//      ID-JAG scoped to the Retail authorization server. Okta evaluates the XAA policy centrally
//      (is this agent allowed to reach the Retail Portal for this user, with which scopes?).
//   2. JWT Bearer grant (RFC 7523) at the RETAIL authorization server: trade the ID-JAG for an
//      access token for the Retail Portal. No browser redirect, no consent screen.
import crypto from 'node:crypto';
import { decodeJwt, decodeProtectedHeader, SignJWT } from 'jose';
import { cfg } from './config.js';

const TOKEN_EXCHANGE = 'urn:ietf:params:oauth:grant-type:token-exchange';
const JWT_BEARER = 'urn:ietf:params:oauth:grant-type:jwt-bearer';
const ID_JAG = 'urn:ietf:params:oauth:token-type:id-jag';
const ID_TOKEN = 'urn:ietf:params:oauth:token-type:id_token';
const REFRESH_TOKEN = 'urn:ietf:params:oauth:token-type:refresh_token';
const CLIENT_ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';

export type TraceStep = {
  step: number;
  title: string;
  status: 'ok' | 'error' | 'skipped';
  ms?: number;
  detail?: string;
  data?: unknown;
};

export class XaaError extends Error {
  constructor(message: string, public code: string, public step: number) {
    super(message);
  }
}

export type RetailAccess = {
  accessToken: string;
  scope: string[];
  /** Portal role the auth server applied to this user (it decides which scopes the user gets). */
  role?: string;
  expiresAt: number;
  claims: Record<string, unknown>;
};

// ---- endpoint discovery (cached) ------------------------------------------------------------
const cache: { oktaToken?: string; retailToken?: string } = {};

export async function oktaTokenEndpoint(): Promise<string> {
  if (!cache.oktaToken) {
    const r = await fetch(`${cfg.okta.issuer}/.well-known/openid-configuration`);
    if (!r.ok) throw new Error(`Okta discovery failed (HTTP ${r.status}) for ${cfg.okta.issuer}`);
    cache.oktaToken = ((await r.json()) as { token_endpoint: string }).token_endpoint;
  }
  return cache.oktaToken;
}

async function retailTokenEndpoint(): Promise<string> {
  if (!cache.retailToken) {
    const url = `${cfg.retail.authIssuer}/.well-known/oauth-authorization-server`;
    const r = await fetch(url, { signal: AbortSignal.timeout(10_000) });
    const type = r.headers.get('content-type') ?? '';
    const meta = type.includes('json') ? ((await r.json().catch(() => ({}))) as { token_endpoint?: string }) : undefined;
    if (!r.ok || !meta?.token_endpoint) {
      // Don't guess a token URL: whatever answered here isn't the retail authorization server.
      throw new Error(
        `${url} returned HTTP ${r.status} (${type || 'no content type'}) instead of OAuth metadata. ` +
          'Is the retail-auth service running, and is another program using that port? Check RETAIL_AUTH_ISSUER / AUTH_PORT.',
      );
    }
    cache.retailToken = meta.token_endpoint;
  }
  return cache.retailToken;
}

// ---- Okta client authentication -------------------------------------------------------------
let signingKey: Promise<CryptoKey> | undefined;
export function agentSigningKey(): Promise<CryptoKey> {
  const jwk = cfg.okta.privateJwk;
  if (!jwk) throw new Error('No private key configured');
  signingKey ??= crypto.webcrypto.subtle.importKey(
    'jwk',
    jwk as crypto.webcrypto.JsonWebKey,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    true,
    ['sign'],
  );
  return signingKey;
}

async function oktaClientAuth(tokenEndpoint: string): Promise<Record<string, string>> {
  if (cfg.okta.authMethod === 'client_secret') {
    return { client_id: cfg.okta.clientId, client_secret: cfg.okta.clientSecret! };
  }
  const assertion = await new SignJWT({})
    .setProtectedHeader({ alg: 'RS256', kid: cfg.okta.privateJwk!.kid })
    .setIssuer(cfg.okta.clientId)
    .setSubject(cfg.okta.clientId)
    .setAudience(tokenEndpoint)
    .setJti(crypto.randomUUID())
    .setIssuedAt()
    .setExpirationTime('60s')
    .sign(await agentSigningKey());
  return { client_id: cfg.okta.clientId, client_assertion_type: CLIENT_ASSERTION_TYPE, client_assertion: assertion };
}

async function postForm(url: string, body: Record<string, string | undefined>) {
  const form = new URLSearchParams();
  for (const [k, v] of Object.entries(body)) if (v !== undefined) form.set(k, v);
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
    body: form,
  });
  const text = await res.text();
  let json: any;
  try {
    json = JSON.parse(text);
  } catch {
    const type = res.headers.get('content-type') ?? 'unknown type';
    json = {
      error: 'invalid_response',
      error_description: `HTTP ${res.status} (${type}), not a JSON OAuth response${type.includes('html') ? ': another program may be answering at that URL' : `: ${text.slice(0, 200)}`}`,
    };
  }
  return { ok: res.ok, status: res.status, json };
}

/** Okta's invalid_scope text: "The following scopes are not allowed for this request: [a, b, c]." -> ['a','b','c'] */
export function rejectedScopes(description: string): string[] {
  const m = /\[([^\]]*)\]/.exec(description);
  return m ? m[1].split(/[\s,]+/).filter(Boolean) : [];
}

const hint = (code: string | undefined, step: 2 | 3) => {
  if (step === 2) {
    switch (code) {
      case 'invalid_target':
      case 'invalid_resource':
        return 'Okta compares `audience` with the Retail Portal app\'s Issuer URL (its XAA card) and `resource` with the connection\'s Resource indicator, and needs an ENABLED connection from this agent to that app. Check all three match what was sent.';
      case 'unauthorized_client':
      case 'access_denied':
        return 'Okta policy denied this agent for this user. Check the XAA connection between the agent and the Retail Portal app, and that the user is assigned to both apps.';
      case 'invalid_client':
        return 'Okta rejected the agent\'s client authentication (client secret / private key JWT).';
      case 'invalid_scope':
        return 'A requested scope is not allowed on the Okta XAA connection.';
      case 'invalid_grant':
        return 'The refresh token / ID token was rejected (expired, revoked, or issued to a different client). Sign in again.';
      case 'unsupported_grant_type':
        return 'Token exchange / XAA is not enabled for the agent app in Okta.';
    }
  }
  return undefined;
};

/** Run the full XAA flow for the signed-in user. Appends human-readable steps to `trace`. */
export async function performXaa(tokens: { idToken: string; refreshToken?: string }, trace: TraceStep[]): Promise<RetailAccess> {
  const { idToken } = tokens;
  const useRefresh = cfg.okta.subjectToken === 'refresh_token';
  if (useRefresh && !tokens.refreshToken) {
    trace.push({ step: 1, title: 'User refresh token', status: 'error', detail: 'Okta did not return a refresh token at sign-in' });
    throw new XaaError(
      'Okta did not issue a refresh token. Enable the "Refresh Token" grant on the agent\'s app in Okta (and sign in again), or set XAA_SUBJECT_TOKEN=id_token.',
      'no_refresh_token',
      1,
    );
  }
  // Step 1: the user's identity from Okta login. The ID token only gates the exchange in id_token
  // mode; in refresh_token mode Okta validates the refresh token itself (and tells us if it's dead).
  const idClaims = decodeJwt(idToken);
  if (!useRefresh && idClaims.exp && idClaims.exp * 1000 < Date.now()) {
    trace.push({ step: 1, title: 'User ID token', status: 'error', detail: 'ID token expired' });
    throw new XaaError('Your Okta session has expired. Please sign in again.', 'id_token_expired', 1);
  }
  trace.push({
    step: 1,
    title: useRefresh ? 'User session (refresh token + ID token from Okta login)' : 'User ID token (from Okta login)',
    status: 'ok',
    detail: `sub=${idClaims.sub}${idClaims.email ? ` · ${idClaims.email}` : ''}`,
    data: { header: decodeProtectedHeader(idToken), claims: idClaims },
  });

  // Step 2: Okta token exchange -> ID-JAG
  let idJag: string;
  const t2 = Date.now();
  const t2Title = useRefresh ? 'Okta: refresh token → ID-JAG' : 'Okta: ID token → ID-JAG';
  // What we send to Okta (no secrets); shown in the trace so mismatches with the Okta config are easy to spot.
  // Okta rejects the WHOLE request if any scope is not allowed on the connection. When that happens we drop the
  // refused scopes and retry once, so narrowing the connection in Okta narrows what the agent gets instead of breaking it.
  let scopes = [...cfg.retail.scopes];
  const sent = {
    audience: cfg.retail.authIssuer,
    resource: cfg.okta.sendResource ? cfg.retail.resource : '(not sent)',
    scope: scopes.join(' '),
    subject_token_type: useRefresh ? REFRESH_TOKEN : ID_TOKEN,
    client_id: cfg.okta.clientId,
  };
  try {
    const endpoint = await oktaTokenEndpoint();
    const exchange = async (wanted: string[]) =>
      postForm(endpoint, {
        grant_type: TOKEN_EXCHANGE,
        requested_token_type: ID_JAG,
        subject_token: useRefresh ? tokens.refreshToken : idToken,
        subject_token_type: useRefresh ? REFRESH_TOKEN : ID_TOKEN,
        audience: cfg.retail.authIssuer,
        resource: cfg.okta.sendResource ? cfg.retail.resource : undefined,
        scope: wanted.join(' '),
        ...(await oktaClientAuth(endpoint)),
      });
    let r = await exchange(scopes);
    if (!r.ok && r.json.error === 'invalid_scope') {
      const rejected = rejectedScopes(String(r.json.error_description ?? ''));
      const kept = scopes.filter((s) => !rejected.includes(s));
      if (rejected.length && kept.length) {
        trace.push({ step: 0, title: 'Okta narrowed the scopes on this connection', status: 'skipped', detail: `Not allowed: ${rejected.join(' ')}. Retrying with: ${kept.join(' ')}` });
        scopes = kept;
        sent.scope = kept.join(' ');
        r = await exchange(kept);
      }
    }
    if (!r.ok) {
      const msg = `${r.json.error ?? 'error'}: ${r.json.error_description ?? `HTTP ${r.status}`}`;
      trace.push({ step: 2, title: t2Title, status: 'error', ms: Date.now() - t2, detail: msg, data: { hint: hint(r.json.error, 2), sent_to_okta: sent, response: r.json } });
      throw new XaaError(`Okta refused the cross-app token exchange (${msg}). ${hint(r.json.error, 2) ?? ''} [sent audience=${sent.audience} resource=${sent.resource}]`.trim(), r.json.error ?? 'okta_error', 2);
    }
    if (r.json.issued_token_type !== ID_JAG || typeof r.json.access_token !== 'string') {
      throw new XaaError(`Unexpected response from Okta (issued_token_type=${r.json.issued_token_type})`, 'bad_okta_response', 2);
    }
    idJag = r.json.access_token;
    // If the Okta app rotates refresh tokens, a new one may come back; keep it for the next exchange.
    if (useRefresh && typeof r.json.refresh_token === 'string' && r.json.refresh_token) {
      tokens.refreshToken = r.json.refresh_token;
    }
    const jagClaims = decodeJwt(idJag);
    trace.push({
      step: 2,
      title: `${t2Title} (identity assertion)`,
      status: 'ok',
      ms: Date.now() - t2,
      detail: `granted scope: ${jagClaims.scope ?? '(none)'}`,
      data: { header: decodeProtectedHeader(idJag), claims: jagClaims },
    });
  } catch (e) {
    if (e instanceof XaaError) throw e;
    trace.push({ step: 2, title: t2Title, status: 'error', ms: Date.now() - t2, detail: (e as Error).message });
    throw new XaaError(`Could not reach Okta: ${(e as Error).message}`, 'okta_unreachable', 2);
  }

  // Step 3: Retail AS jwt-bearer grant -> access token
  const t3 = Date.now();
  try {
    const endpoint = await retailTokenEndpoint();
    const r = await postForm(endpoint, {
      grant_type: JWT_BEARER,
      assertion: idJag,
      scope: scopes.join(' '),
      client_id: cfg.retail.clientId,
      client_secret: cfg.retail.clientSecret,
    });
    if (!r.ok) {
      const msg = `${r.json.error ?? 'error'}: ${r.json.error_description ?? `HTTP ${r.status}`}`;
      trace.push({ step: 3, title: 'Retail AS: ID-JAG → access token', status: 'error', ms: Date.now() - t3, detail: msg });
      throw new XaaError(`The Retail authorization server rejected the ID-JAG (${msg})`, r.json.error ?? 'retail_as_error', 3);
    }
    const claims = decodeJwt(r.json.access_token);
    trace.push({
      step: 3,
      title: 'Retail authorization server: ID-JAG → access token',
      status: 'ok',
      ms: Date.now() - t3,
      detail: `scope: ${r.json.scope}${r.json.role ? ` · user role: ${r.json.role}` : ''} · expires in ${r.json.expires_in}s`,
      data: { header: decodeProtectedHeader(r.json.access_token), claims },
    });
    return {
      accessToken: r.json.access_token,
      scope: String(r.json.scope ?? '').split(/\s+/).filter(Boolean),
      role: typeof r.json.role === 'string' ? r.json.role : undefined,
      expiresAt: Date.now() + Number(r.json.expires_in ?? 300) * 1000,
      claims: claims as Record<string, unknown>,
    };
  } catch (e) {
    if (e instanceof XaaError) throw e;
    trace.push({ step: 3, title: 'Retail AS: ID-JAG → access token', status: 'error', ms: Date.now() - t3, detail: (e as Error).message });
    throw new XaaError(`Could not reach the Retail authorization server: ${(e as Error).message}`, 'retail_as_unreachable', 3);
  }
}
