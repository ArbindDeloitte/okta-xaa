// Okta on-behalf-of (OBO) token exchange, RFC 8693: the user's access token (issued by an Okta custom authorization
// server) is swapped, by a service app, for a new access token for the HPE Order Portal. The new token names the user
// (sub) and the agent that acted for them (act). No ID-JAG and no retail authorization server are involved.
import { decodeJwt } from 'jose';
import { rejectedScopes, type TraceStep } from '../../agent/src/xaa.js';
import { oboCfg } from './config.js';

export class OboError extends Error {
  constructor(message: string, public code: string, public step: number) {
    super(message);
  }
}

export type OboAccess = {
  accessToken: string;
  scope: string[];
  expiresAt: number;
  claims: Record<string, unknown>;
  /** Filled in once the portal has looked at the token. */
  role?: string;
};

const form = (o: Record<string, string>) => new URLSearchParams(o).toString();
// client_secret_basic: id and secret are form-urlencoded first (RFC 6749 §2.3.1), then base64'd.
const basic = () => `Basic ${Buffer.from(`${encodeURIComponent(oboCfg.service.clientId)}:${encodeURIComponent(oboCfg.service.clientSecret)}`).toString('base64')}`;

async function exchange(subjectToken: string, scopes: string[]) {
  const r = await fetch(`${oboCfg.issuer}/v1/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json', Authorization: basic() },
    body: form({
      grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
      subject_token: subjectToken,
      subject_token_type: 'urn:ietf:params:oauth:token-type:access_token',
      scope: scopes.join(' '),
      audience: oboCfg.audience,
    }),
    signal: AbortSignal.timeout(15_000),
  });
  const json = (await r.json().catch(() => ({}))) as Record<string, unknown>;
  return { ok: r.ok, status: r.status, json };
}

const claimsOf = (jwt: string): Record<string, unknown> => {
  try { return decodeJwt(jwt) as Record<string, unknown>; } catch { return {}; }
};

const HINT =
  'On the exchange server (OBO_ISSUER): define these scopes, allow the service app in an access policy rule with the ' +
  'Token Exchange grant, and check OBO_AUDIENCE matches its audience. Or narrow OBO_SCOPES to what the rule allows. ' +
  'If users sign in at a different server (OBO_LOGIN_ISSUER), the exchange server must list it under Settings > Trusted servers.';

/** Exchange the signed-in user's access token for a portal token. Adds the trace steps as it goes. */
export async function performObo(subjectToken: string, trace: TraceStep[]): Promise<OboAccess> {
  const subject = claimsOf(subjectToken);
  trace.push({
    step: 1,
    title: 'User signed in at the Okta sign-in authorization server',
    status: 'ok',
    detail: `issued by ${String(subject.iss ?? '?')} · sub=${String(subject.sub ?? '?')} · aud=${String(subject.aud ?? '?')}`,
    data: { claims: subject },
  });

  let scopes = [...oboCfg.scopes];
  const t0 = Date.now();
  let r = await exchange(subjectToken, scopes);
  if (!r.ok && r.json.error === 'invalid_scope') {
    // Like the XAA connection, the policy may allow only some scopes; Okta then names the ones it refused.
    const rejected = rejectedScopes(String(r.json.error_description ?? ''));
    const kept = scopes.filter((s) => !rejected.includes(s));
    if (rejected.length && kept.length) {
      trace.push({ step: 0, title: 'Okta narrowed the scopes in this policy', status: 'skipped', detail: `Not allowed: ${rejected.join(' ')}. Retrying with: ${kept.join(' ')}` });
      scopes = kept;
      r = await exchange(subjectToken, kept);
    }
  }
  const ms = Date.now() - t0;
  const accessToken = r.json.access_token;
  if (!r.ok || typeof accessToken !== 'string') {
    const code = String(r.json.error ?? `http_${r.status}`);
    const desc = String(r.json.error_description ?? 'Token exchange failed');
    trace.push({ step: 2, title: 'Okta: on-behalf-of token exchange', status: 'error', ms, detail: `${code}: ${desc}`, data: { sent_to_okta: { grant_type: 'token-exchange', audience: oboCfg.audience, scope: scopes.join(' ') }, response: r.json } });
    throw new OboError(`${code}: ${desc}. ${HINT}`, code, 2);
  }

  const claims = claimsOf(accessToken);
  const scp = Array.isArray(claims.scp) ? claims.scp.map(String) : String(r.json.scope ?? '').split(/\s+/).filter(Boolean);
  const act = claims.act as { sub?: unknown } | undefined;
  trace.push({
    step: 2,
    title: 'Okta: user access token → on-behalf-of access token (RFC 8693)',
    status: 'ok',
    ms,
    detail: `scope: ${scp.join(' ') || '(none)'} · acting user=${String(claims.uid ?? claims.sub ?? '?')} · agent (act.sub)=${act?.sub ? String(act.sub) : 'MISSING: no act claim'}`,
    data: { claims },
  });
  if (oboCfg.logToken) {
    console.log(`[obo] exchanged token claims:\n${JSON.stringify(claims, null, 2)}`);
    if (oboCfg.logToken === 'full') console.log(`[obo] RAW OBO ACCESS TOKEN (debug, treat as a password): ${accessToken}`);
  }
  const exp = typeof claims.exp === 'number' ? claims.exp * 1000 : Date.now() + Number(r.json.expires_in ?? 3600) * 1000;
  return { accessToken, scope: scp, expiresAt: exp, claims };
}
