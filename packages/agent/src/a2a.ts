// Direct A2A (Agent2Agent protocol) client: calls a SECOND agent (the HPE HR Agent), secured by the same Okta
// Cross App Access mechanism as xaa.ts -- just retargeted at that agent's own custom authorization server instead
// of the Retail authorization server. See docs/A2A_AGENT_TO_AGENT.md for the full design and the Okta console
// setup this depends on.
//
//   1. Token Exchange (RFC 8693) at Okta's ORG authorization server (same as ordinary XAA): trade the user's
//      refresh/ID token for an ID-JAG, audience = the HR Agent's own custom authorization server.
//   2. JWT Bearer grant (RFC 7523) at the HR AGENT'S authorization server: trade the ID-JAG for an access token
//      for the HR Agent. No browser redirect, no consent screen -- identical shape to xaa.ts's step 3.
//
// `callAgentOverA2a` is the generic part (not Okta-specific): it is also used by packages/agent-bridge, which
// gets its token a different way (through the Bridge) but calls the SAME agent over the SAME wire protocol.
import crypto from 'node:crypto';
import { decodeJwt } from 'jose';
import {
  ClientFactory,
  ClientFactoryOptions,
  JsonRpcTransportFactory,
  DefaultAgentCardResolver,
  createAuthenticatingFetchWithRetry,
  type Client,
} from '@a2a-js/sdk/client';
import { Role, type SendMessageResult } from '@a2a-js/sdk';
import { cfg } from './config.js';
import { oktaClientAuth, oktaTokenEndpoint, rejectedScopes, type TraceStep } from './xaa.js';

const TOKEN_EXCHANGE = 'urn:ietf:params:oauth:grant-type:token-exchange';
const JWT_BEARER = 'urn:ietf:params:oauth:grant-type:jwt-bearer';
const ID_JAG = 'urn:ietf:params:oauth:token-type:id-jag';
const ID_TOKEN = 'urn:ietf:params:oauth:token-type:id_token';

export class HrAccessError extends Error {
  constructor(message: string, public code: string) {
    super(message);
  }
}

export type HrAccess = { accessToken: string; scope: string[]; expiresAt: number };

async function postForm(url: string, body: Record<string, string | undefined>) {
  const form = new URLSearchParams();
  for (const [k, v] of Object.entries(body)) if (v !== undefined) form.set(k, v);
  const res = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' }, body: form });
  const text = await res.text();
  let json: any;
  try {
    json = JSON.parse(text);
  } catch {
    json = { error: 'invalid_response', error_description: `HTTP ${res.status}, not a JSON OAuth response: ${text.slice(0, 200)}` };
  }
  return { ok: res.ok, status: res.status, json };
}

/** Whether the HR Agent direct path is configured at all (both the agent's own URL and its authorization server). */
export const hrAgentConfigured = () => Boolean(cfg.hrAgent.url && cfg.hrAgent.authIssuer);

/** Step 1 (Okta org AS) + step 2 (the HR Agent's own authorization server): the same shape as performXaa() in
 * xaa.ts, retargeted at the HR Agent. Mutates `tokens.refreshToken` if Okta rotates it, same as performXaa(). */
export async function performA2aExchange(tokens: { idToken: string; refreshToken?: string }, trace: TraceStep[]): Promise<HrAccess> {
  if (!hrAgentConfigured()) {
    throw new HrAccessError('HR_AGENT_AUTH_ISSUER / HR_AGENT_URL are not set in .env.', 'hr_agent_not_configured');
  }
  // Unlike ordinary XAA's performXaa() (which honours XAA_SUBJECT_TOKEN and defaults to refresh_token), the
  // agent-to-agent token exchange documented at developer.okta.com/docs/guides/ai-agent-token-exchange/authserver
  // lists ONLY id_token or access_token as valid subject_token_type values -- refresh_token is not one of them.
  // Sending a refresh token here was rejected live with invalid_target (Okta's error message for this is
  // non-specific). So this always uses the ID token, which means -- unlike the retail flow -- a long-idle
  // browser session needs a fresh sign-in before this exchange can run again.
  if (tokens.idToken) {
    const idClaims = decodeJwt(tokens.idToken);
    if (idClaims.exp && idClaims.exp * 1000 < Date.now()) {
      trace.push({ step: 0, title: 'User ID token (for the HR Agent exchange)', status: 'error', detail: 'ID token expired' });
      throw new HrAccessError('Your Okta session has expired. Please sign in again to use the HR Agent.', 'id_token_expired');
    }
  }

  // Step 1: Okta org AS, token-exchange -> ID-JAG, audience = the HR Agent's own authorization server.
  // `resource` is set to that SAME value, not the HR Agent's own URL: confirmed from a live Okta Event Log
  // entry ("OAuth 2.0 Identity Assertion Authorization Grant is granted") that this exact shape -- audience and
  // resource both equal to the custom AS's own issuer URL -- is the one the "Connect to another AI Agent"
  // delegation link actually expects (its console screen shows only one combined "Audience/resource URL"
  // field, which this matches). HR_AGENT_URL still matters -- it is what agent-hr's auth.ts checks as `aud` on
  // the FINAL access token, which Okta's custom AS sets from its own Default Audience setting in step 2.
  //
  // Like ordinary XAA, Okta rejects the WHOLE request if any requested scope is not allowed on the delegation
  // link; drop the refused ones and retry once (see performXaa() in xaa.ts, which this mirrors).
  const t1 = Date.now();
  const orgTokenEndpoint = await oktaTokenEndpoint();
  let scopes = [...cfg.hrAgent.scopes];
  const exchange = async (wanted: string[]) =>
    postForm(orgTokenEndpoint, {
      grant_type: TOKEN_EXCHANGE,
      requested_token_type: ID_JAG,
      subject_token: tokens.idToken,
      subject_token_type: ID_TOKEN,
      audience: cfg.hrAgent.authIssuer,
      resource: cfg.hrAgent.authIssuer,
      scope: wanted.join(' '),
      ...(await oktaClientAuth(orgTokenEndpoint)),
    });
  let r1 = await exchange(scopes);
  if (!r1.ok && r1.json.error === 'invalid_scope') {
    const rejected = rejectedScopes(String(r1.json.error_description ?? ''));
    const kept = scopes.filter((s) => !rejected.includes(s));
    if (rejected.length && kept.length) {
      trace.push({ step: 0, title: 'Okta narrowed the scopes on this delegation link', status: 'skipped', detail: `Not allowed: ${rejected.join(' ')}. Retrying with: ${kept.join(' ')}` });
      scopes = kept;
      r1 = await exchange(kept);
    }
  }
  if (!r1.ok || typeof r1.json.access_token !== 'string') {
    const msg = `${r1.json.error ?? 'error'}: ${r1.json.error_description ?? `HTTP ${r1.status}`}`;
    trace.push({ step: 0, title: 'Okta: token exchange -> ID-JAG (audience: HR Agent)', status: 'error', ms: Date.now() - t1, detail: msg });
    throw new HrAccessError(`Okta refused the agent-to-agent token exchange (${msg}). [sent audience=${cfg.hrAgent.authIssuer}]`, r1.json.error ?? 'okta_error');
  }
  const idJag = r1.json.access_token as string;
  const jagClaims = decodeJwt(idJag);
  trace.push({
    step: 0,
    title: 'Okta: token exchange -> ID-JAG (audience: HR Agent)',
    status: 'ok',
    ms: Date.now() - t1,
    detail: `granted scope: ${jagClaims.scope ?? '(none)'}`,
    data: { claims: jagClaims },
  });

  // Step 2: the HR Agent's own authorization server, jwt-bearer -> access token. Endpoint convention is the
  // same one OBO already relies on directly (an Okta custom AS's token endpoint is always <issuer>/v1/token).
  const t2 = Date.now();
  const hrTokenEndpoint = `${cfg.hrAgent.authIssuer}/v1/token`;
  const r2 = await postForm(hrTokenEndpoint, { grant_type: JWT_BEARER, assertion: idJag, ...(await oktaClientAuth(hrTokenEndpoint)) });
  if (!r2.ok || typeof r2.json.access_token !== 'string') {
    const msg = `${r2.json.error ?? 'error'}: ${r2.json.error_description ?? `HTTP ${r2.status}`}`;
    trace.push({ step: 0, title: "HR Agent's authorization server: ID-JAG -> access token", status: 'error', ms: Date.now() - t2, detail: msg });
    throw new HrAccessError(
      `The HR Agent's authorization server rejected the ID-JAG (${msg}).${
        r2.json.error === 'access_denied' ? ' Check the access policy on the HR Agent\'s authorization server: its "Assigned to clients" must include the CALLING agent (e.g. Retail Ops Agent), not only the HR Agent itself.' : ''
      }`,
      r2.json.error ?? 'hr_as_error',
    );
  }
  const scope = String(r2.json.scope ?? '').split(/\s+/).filter(Boolean);
  const claims = decodeJwt(r2.json.access_token);
  trace.push({
    step: 0,
    title: "HR Agent's authorization server: ID-JAG -> access token",
    status: 'ok',
    ms: Date.now() - t2,
    detail: `scope: ${scope.join(' ') || '(none)'} · expires in ${r2.json.expires_in}s`,
    data: { claims },
  });
  return { accessToken: r2.json.access_token, scope, expiresAt: Date.now() + Number(r2.json.expires_in ?? 300) * 1000 };
}

// ---- generic A2A call (shared with packages/agent-bridge) -------------------------------------
// Cache only the (network-fetched) Agent Card per base URL -- NOT a Client. A Client bakes its `fetchImpl`
// (and so its Bearer token) in at construction time, so a client cached across calls would keep using
// whichever token was current the first time it was built: harmless for one caller, but wrong the moment two
// different sessions (different tokens) call the SAME agent, or a token is rotated and the old one is still
// baked into a long-lived client. Building a fresh, call-scoped Client from the cached card is cheap (no
// network I/O: createFromAgentCard does not re-fetch) and keeps every call's token fully isolated.
const cardCache = new Map<string, Promise<import('@a2a-js/sdk').AgentCard>>();

function authFetchFor(getToken: () => string): typeof fetch {
  return createAuthenticatingFetchWithRetry(fetch, {
    headers: async () => ({ Authorization: `Bearer ${getToken()}` }),
    shouldRetryWithHeaders: async () => undefined, // we manage expiry/refresh ourselves; no in-band retry
  });
}

async function agentCardFor(baseUrl: string, getToken: () => string): Promise<import('@a2a-js/sdk').AgentCard> {
  let p = cardCache.get(baseUrl);
  if (!p) {
    p = new DefaultAgentCardResolver({ fetchImpl: authFetchFor(getToken) }).resolve(baseUrl).catch((e) => {
      cardCache.delete(baseUrl); // don't cache a failure: a later call (e.g. after fixing config) can retry
      throw e;
    });
    cardCache.set(baseUrl, p);
  }
  return p;
}

const textPartOf = (parts: { content?: { $case: string; value: unknown } }[]): string | undefined => {
  const p = parts.find((p) => p.content?.$case === 'text');
  return typeof p?.content?.value === 'string' ? p.content.value : undefined;
};

/** Sends one A2A message/send call (not MCP) to another agent and returns its text reply. `getToken` is read
 * fresh for this call only -- see the cache note above. */
export async function callAgentOverA2a(baseUrl: string, task: string, getToken: () => string): Promise<string> {
  const card = await agentCardFor(baseUrl, getToken);
  const client: Client = await new ClientFactory(
    ClientFactoryOptions.createFrom(ClientFactoryOptions.default, { transports: [new JsonRpcTransportFactory({ fetchImpl: authFetchFor(getToken) })] }),
  ).createFromAgentCard(card);
  const result: SendMessageResult = await client.sendMessage({
    tenant: '',
    message: {
      messageId: crypto.randomUUID(),
      role: Role.ROLE_USER,
      parts: [{ content: { $case: 'text', value: task }, metadata: undefined, filename: '', mediaType: 'text/plain' }],
      taskId: '',
      contextId: '',
      extensions: [],
      metadata: {},
      referenceTaskIds: [],
    },
    configuration: undefined,
    metadata: {},
  });
  if ('parts' in result) return textPartOf(result.parts) ?? '(the agent replied with no text)';
  // This agent never creates a Task, so a Task result is unexpected; surface whatever text it carries anyway.
  const statusText = result.status?.message ? textPartOf(result.status.message.parts) : undefined;
  return statusText ?? `(unexpected: the agent returned a task in state ${result.status?.state})`;
}
