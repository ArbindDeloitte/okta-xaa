// Tests the on-behalf-of (OBO) agent app end to end against a mock Okta custom authorization server:
//   browser -> OBO agent -> (sign-in) mock Okta -> (RFC 8693 exchange) mock Okta -> real portal (verifies Okta's token) -> data
// The portal and the agent app are the real code; a mock Groq plays the LLM. Run: npm run test:obo
import { spawn, type ChildProcess } from 'node:child_process';
import crypto from 'node:crypto';
import http from 'node:http';
import { exportJWK, generateKeyPair, jwtVerify, SignJWT } from 'jose';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const OKTA_PORT = 14021;
const GROQ_PORT = 14031;
const PORTAL_PORT = 13121;
const AGENT_PORT = 13221;
const OKTA = `http://localhost:${OKTA_PORT}`;
// Two custom authorization servers: users sign in at one; the other (which trusts the first) mints the portal token.
const ISS_USER = `${OKTA}/oauth2/aus-users`;
const AUD_USER = 'api://hpe-users';
const ISS = `${OKTA}/oauth2/aus-hpe`;
const AUD = 'api://hpe-order-portal';
const PORTAL = `http://localhost:${PORTAL_PORT}`;
const MCP = `${PORTAL}/mcp`;
const AGENT = `http://localhost:${AGENT_PORT}`;
const LOGIN_APP = 'obo-login-app';
const SVC_ID = '0oaSERVICE';
const SVC_SECRET = 'svc-secret-' + crypto.randomUUID();
const ALL = ['products:read', 'inventory:read', 'orders:read', 'customers:read', 'orders:write', 'returns:read', 'returns:write'];
const b64u = (b: Buffer) => b.toString('base64url');

// ---- mock Okta custom authorization server ---------------------------------------------------
const pair = await generateKeyPair('RS256', { extractable: true });
const pub = { ...(await exportJWK(pair.publicKey)), kid: 'okta-kid', alg: 'RS256', use: 'sig' };
const USERS = {
  intern: { login: 'intern@corp.test', uid: '00uINTERN', name: 'Ian Intern' },
  boss: { login: 'boss@corp.test', uid: '00uBOSS', name: 'Bea Boss' },
};
let signInAs = USERS.intern;
let policy: 'all' | 'narrow' | 'deny' = 'all';
let subjectTtl = 3600;
let trustsUserServer = true; // the exchange server's "Trusted servers" setting
const NARROW_ALLOWED = ['products:read', 'inventory:read', 'orders:read'];
const codes = new Map<string, { nonce: string; challenge: string; redirectUri: string; user: typeof USERS.intern }>();
const seen: { basicOk?: boolean; audience?: string; subjectType?: string; scope?: string; authorizeUrl?: URL; exchanges: number; exchangePath?: string } = { exchanges: 0 };

const readBody = (req: http.IncomingMessage) => new Promise<string>((r) => { let d = ''; req.on('data', (c) => (d += c)); req.on('end', () => r(d)); });
const sign = (claims: Record<string, unknown>, aud: string, sub: string, ttl = '1h', iss = ISS) =>
  new SignJWT(claims).setProtectedHeader({ alg: 'RS256', kid: 'okta-kid', typ: 'JWT' }).setIssuer(iss).setAudience(aud).setSubject(sub).setJti(crypto.randomUUID()).setIssuedAt().setExpirationTime(ttl).sign(pair.privateKey);

const okta = http.createServer(async (req, res) => {
  const url = new URL(req.url!, OKTA);
  const json = (o: unknown, code = 200) => { res.writeHead(code, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(o)); };
  if (url.pathname === '/oauth2/aus-users/.well-known/openid-configuration') {
    // only the sign-in server is discovered by the app; it talks to the exchange server's /v1/token directly
    return json({
      issuer: ISS_USER, authorization_endpoint: `${ISS_USER}/v1/authorize`, token_endpoint: `${ISS_USER}/v1/token`, jwks_uri: `${ISS_USER}/v1/keys`,
      response_types_supported: ['code'], subject_types_supported: ['public'], id_token_signing_alg_values_supported: ['RS256'], code_challenge_methods_supported: ['S256'],
    });
  }
  if (url.pathname === '/oauth2/aus-users/v1/keys' || url.pathname === '/oauth2/aus-hpe/v1/keys') return json({ keys: [pub] });
  if (url.pathname === '/oauth2/aus-users/v1/authorize') {
    seen.authorizeUrl = url;
    const code = 'code-' + crypto.randomUUID();
    codes.set(code, { nonce: url.searchParams.get('nonce')!, challenge: url.searchParams.get('code_challenge')!, redirectUri: url.searchParams.get('redirect_uri')!, user: signInAs });
    const back = new URL(url.searchParams.get('redirect_uri')!);
    back.searchParams.set('code', code);
    back.searchParams.set('state', url.searchParams.get('state')!);
    res.writeHead(302, { Location: back.href });
    return void res.end();
  }
  if ((url.pathname === '/oauth2/aus-users/v1/token' || url.pathname === '/oauth2/aus-hpe/v1/token') && req.method === 'POST') {
    const form = new URLSearchParams(await readBody(req));
    const grant = form.get('grant_type');
    if (grant === 'authorization_code' && url.pathname.startsWith('/oauth2/aus-users/')) {
      // the user signs in: public client + PKCE
      const rec = codes.get(form.get('code')!);
      codes.delete(form.get('code')!);
      if (!rec || form.get('client_id') !== LOGIN_APP || form.get('redirect_uri') !== rec.redirectUri) return json({ error: 'invalid_grant' }, 400);
      if (b64u(crypto.createHash('sha256').update(form.get('code_verifier') ?? '').digest()) !== rec.challenge) return json({ error: 'invalid_grant', error_description: 'PKCE' }, 400);
      const idToken = await sign({ nonce: rec.nonce, email: rec.user.login, name: rec.user.name }, LOGIN_APP, rec.user.uid, '5m', ISS_USER);
      const accessToken = await sign({ ver: 1, uid: rec.user.uid, cid: LOGIN_APP, scp: ['openid', 'profile', 'email'] }, AUD_USER, rec.user.login, `${subjectTtl}s`, ISS_USER);
      return json({ token_type: 'Bearer', expires_in: subjectTtl, access_token: accessToken, id_token: idToken, scope: 'openid profile email' });
    }
    if (grant === 'urn:ietf:params:oauth:grant-type:token-exchange' && url.pathname.startsWith('/oauth2/aus-hpe/')) {
      seen.exchanges++;
      seen.exchangePath = url.pathname;
      seen.basicOk = req.headers.authorization === `Basic ${Buffer.from(`${SVC_ID}:${SVC_SECRET}`).toString('base64')}`;
      seen.audience = form.get('audience') ?? undefined;
      seen.subjectType = form.get('subject_token_type') ?? undefined;
      seen.scope = form.get('scope') ?? undefined;
      if (!seen.basicOk) return json({ error: 'invalid_client' }, 401);
      let subject;
      try {
        // the subject token must come from a server this one trusts
        if (!trustsUserServer) throw new Error('subject token issuer is not a trusted authorization server');
        subject = (await jwtVerify(form.get('subject_token')!, pair.publicKey, { issuer: ISS_USER, audience: AUD_USER })).payload;
      } catch (e) {
        return json({ error: 'invalid_request', error_description: `bad subject token: ${(e as Error).message}` }, 400);
      }
      if (form.get('audience') !== AUD) return json({ error: 'invalid_target', error_description: 'audience' }, 400);
      const asked = (form.get('scope') ?? '').split(' ').filter(Boolean);
      if (policy === 'deny') return json({ error: 'access_denied', error_description: 'Policy evaluation failed for this request, please check the policy configurations.' }, 400);
      if (policy === 'narrow') {
        const bad = asked.filter((s) => !NARROW_ALLOWED.includes(s));
        if (bad.length) return json({ error: 'invalid_scope', error_description: `The following scopes are not allowed for this request: [${bad.join(', ')}].` }, 400);
      }
      const at = await sign({ ver: 1, uid: subject.uid, cid: SVC_ID, scp: asked, act: { sub: SVC_ID, sub_profile: 'service' } }, AUD, String(subject.sub), '1h');
      return json({ token_type: 'Bearer', expires_in: 3600, access_token: at, scope: asked.join(' '), issued_token_type: 'urn:ietf:params:oauth:token-type:access_token' });
    }
    return json({ error: 'unsupported_grant_type' }, 400);
  }
  res.writeHead(404); res.end();
});
await new Promise<void>((r) => okta.listen(OKTA_PORT, r));

// ---- mock Groq: one tool call (whatever the test queued), then a final text ----------------
let queued: { name: string; args: Record<string, unknown> } | undefined;
let offeredTools: string[] = [];
const groq = http.createServer(async (req, res) => {
  const body = JSON.parse((await readBody(req)) || '{}');
  offeredTools = (body.tools ?? []).map((t: { function: { name: string } }) => t.function.name);
  const last = body.messages[body.messages.length - 1];
  const reply = (message: unknown, finish: string) => { res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ choices: [{ message, finish_reason: finish }] })); };
  if (last.role === 'tool' || !queued) return reply({ role: 'assistant', content: last.role === 'tool' ? `Done: ${String(last.content).slice(0, 80)}` : 'Hello' }, 'stop');
  const call = queued;
  queued = undefined;
  reply({ role: 'assistant', content: null, tool_calls: [{ id: 'c1', type: 'function', function: { name: call.name, arguments: JSON.stringify(call.args) } }] }, 'tool_calls');
});
await new Promise<void>((r) => groq.listen(GROQ_PORT, r));

// ---- the real portal and the real OBO agent app --------------------------------------------
const baseEnv = {
  ...process.env,
  PORTAL_PORT: String(PORTAL_PORT), RETAIL_RESOURCE: MCP, RETAIL_AUTH_ISSUER: 'http://localhost:15121', RETAIL_MCP_URL: MCP,
  OBO_ISSUER: ISS, OBO_AUDIENCE: AUD, OBO_LOGIN_ISSUER: ISS_USER,
  PORTAL_USER_ROLES: '00uINTERN=viewer,00uBOSS=manager', PORTAL_DEFAULT_ROLE: 'support',
};
const portalEnv = baseEnv;
const agentEnv = {
  ...baseEnv,
  AGENT_OBO_PORT: String(AGENT_PORT), AGENT_OBO_BASE_URL: AGENT,
  OBO_LOGIN_CLIENT_ID: LOGIN_APP, OBO_LOGIN_CLIENT_SECRET: '', OBO_SERVICE_CLIENT_ID: SVC_ID, OBO_SERVICE_CLIENT_SECRET: SVC_SECRET, OBO_SCOPES: ALL.join(' '), OBO_OFFLINE_ACCESS: 'false',
  // settings the shared agent code insists on (unused by the OBO flow)
  OKTA_ISSUER: OKTA, AGENT_CLIENT_ID: 'unused', AGENT_AUTH_METHOD: 'client_secret', AGENT_CLIENT_SECRET: 'unused',
  LLM_PROVIDER: 'groq', GROQ_API_KEY: 'test', GROQ_BASE_URL: `http://localhost:${GROQ_PORT}`, GROQ_MODEL: 'test-model',
};
const run = (file: string, env: NodeJS.ProcessEnv, tag: string): ChildProcess => {
  const p = spawn(process.execPath, ['--import', 'tsx', path.join(root, file)], { env, stdio: ['ignore', 'ignore', 'pipe'] });
  p.stderr!.on('data', (d) => process.stderr.write(`[${tag}] ${d}`));
  return p;
};
const procs = [run('packages/retail-portal/src/index.ts', portalEnv, 'portal'), run('packages/agent-obo/src/index.ts', agentEnv, 'obo')];
const cleanup = () => { procs.forEach((p) => p.kill()); okta.close(); groq.close(); };

let failed = 0;
const check = (name: string, cond: boolean, extra?: unknown) => {
  console.log(`${cond ? '  ✔' : '  ✘'} ${name}${cond ? '' : ` -> ${JSON.stringify(extra)}`}`);
  if (!cond) failed++;
};
const wait = async (url: string) => {
  for (let i = 0; i < 120; i++) { try { if ((await fetch(url)).ok) return; } catch { /* retry */ } await new Promise((r) => setTimeout(r, 250)); }
  throw new Error(`${url} did not start`);
};

/** A tiny browser: keeps cookies, never follows redirects on its own. */
function browser() {
  let cookie = '';
  const go = async (url: string, init: RequestInit = {}) => {
    const r = await fetch(url, { ...init, redirect: 'manual', headers: { ...(init.headers as Record<string, string>), ...(cookie ? { Cookie: cookie } : {}) } });
    const set = r.headers.getSetCookie().map((c) => c.split(';')[0]);
    if (set.length) cookie = [...new Map([...cookie.split('; ').filter(Boolean), ...set].map((c) => [c.split('=')[0], c])).values()].join('; ');
    return r;
  };
  const post = (p: string, body: unknown) => go(`${AGENT}${p}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  /** Whole sign-in: agent /login -> Okta authorize -> agent /callback. Returns the final redirect. */
  const signIn = async () => {
    const a = await go(`${AGENT}/login`);
    const b = await go(a.headers.get('location')!);
    const c = await go(b.headers.get('location')!);
    return c.headers.get('location');
  };
  return { go, post, signIn, get: (p: string) => go(`${AGENT}${p}`) };
}

try {
  await wait(`${PORTAL}/.well-known/oauth-protected-resource/mcp`);
  await wait(`${AGENT}/api/me`);

  console.log('1. Sign-in at the custom authorization server');
  const b = browser();
  const me0 = await (await b.get('/api/me')).json() as any;
  check('not signed in yet', me0.authenticated === false);
  check('page wording switches to OBO', me0.ui?.connectPath === '/api/obo/connect' && /on-behalf/i.test(me0.ui?.subtitle));
  check('chat is refused before sign-in', (await b.post('/api/chat', { message: 'hi' })).status === 401);
  check('signs in and lands on /', (await b.signIn()) === '/');
  const au = seen.authorizeUrl!;
  check('PKCE S256 used', au.searchParams.get('code_challenge_method') === 'S256');
  check('public client id sent', au.searchParams.get('client_id') === LOGIN_APP);
  check('only OIDC scopes at sign-in (no offline_access by default)', au.searchParams.get('scope') === 'openid profile email');
  const me1 = await (await b.get('/api/me')).json() as any;
  check('user is known after sign-in', me1.authenticated && me1.user?.sub === '00uINTERN' && me1.user?.email === 'intern@corp.test', me1.user);

  console.log('2. The on-behalf-of exchange (viewer)');
  const conn = await (await b.post('/api/obo/connect', {})).json() as any;
  check('exchange succeeds', Array.isArray(conn.scope) && conn.scope.length === 7, conn);
  check('sign-in happened at the user server, the exchange at the other one', au.pathname === '/oauth2/aus-users/v1/authorize' && seen.exchangePath === '/oauth2/aus-hpe/v1/token', [au.pathname, seen.exchangePath]);
  check('Okta saw the service app\'s Basic credentials', seen.basicOk === true);
  check('request used RFC 8693 parameters', seen.subjectType === 'urn:ietf:params:oauth:token-type:access_token' && seen.audience === AUD, seen);
  check('portal applied the viewer role', conn.role === 'viewer', conn.role);
  const toolNames = (conn.tools ?? []).map((t: { name: string }) => t.name).sort();
  check('viewer sees only the 4 read tools', toolNames.join() === 'check_inventory,get_order,list_orders,search_products', toolNames);
  const t = conn.trace as { step: number; title: string; detail?: string }[];
  check('trace: sign-in, exchange, portal', t.map((s) => s.step).join() === '1,2,3', t.map((s) => s.step));
  check('trace names the sign-in server as the subject token issuer', (t[0].detail ?? '').includes(ISS_USER), t[0]);
  check('trace shows the acting agent from act.sub', /act\.sub\)=0oaSERVICE/.test(t[1].detail ?? ''), t[1]);
  check('trace shows the portal saw the agent', /agent \(act\): 0oaSERVICE/.test(t[2].detail ?? ''), t[2]);

  console.log('3. Chat and governance');
  queued = { name: 'list_orders', args: { status: 'processing' } };
  const chat = await (await b.post('/api/chat', { message: 'Which orders are processing?' })).json() as any;
  check('agent called list_orders through the OBO token', chat.toolCalls?.[0]?.name === 'list_orders' && chat.toolCalls[0].isError === false, chat);
  check('model reply came back', /^Done:/.test(chat.reply ?? ''), chat.reply);
  check('the LLM was only offered the read tools', !offeredTools.includes('cancel_order') && offeredTools.includes('list_orders'), offeredTools);
  const audit = (await (await fetch(`${PORTAL}/admin/api/audit?since=0`)).json()) as any[];
  const entry = audit.find((a) => a.tool === 'list_orders');
  check('portal audit: user, role, client and actor recorded', entry?.decision === 'allow' && entry.role === 'viewer' && entry.user === 'intern@corp.test' && entry.clientId === SVC_ID && entry.actor === SVC_ID, entry);

  console.log('4. Different user, different role (same app, same data)');
  const boss = browser();
  signInAs = USERS.boss;
  await boss.signIn();
  const bc = await (await boss.post('/api/obo/connect', {})).json() as any;
  check('manager gets all 8 tools', bc.role === 'manager' && (bc.tools ?? []).length === 8, bc.tools?.length);
  queued = { name: 'cancel_order', args: { order_id: 'SO-10005', reason: 'test' } };
  const cancel = await (await boss.post('/api/chat', { message: 'Cancel SO-10005' })).json() as any;
  check('manager can cancel through OBO', cancel.toolCalls?.[0]?.name === 'cancel_order' && cancel.toolCalls[0].isError === false, cancel.toolCalls);
  const audit2 = (await (await fetch(`${PORTAL}/admin/api/audit?since=0`)).json()) as any[];
  check('audit shows the manager and the same acting agent', audit2.some((a) => a.tool === 'cancel_order' && a.user === 'boss@corp.test' && a.role === 'manager' && a.actor === SVC_ID && a.decision === 'allow'));

  console.log('5. Okta policy narrows or denies the scopes');
  policy = 'narrow';
  const nb = browser();
  signInAs = USERS.boss;
  await nb.signIn();
  const nc = await (await nb.post('/api/obo/connect', {})).json() as any;
  check('retried with only the allowed scopes', nc.scope?.slice().sort().join() === NARROW_ALLOWED.slice().sort().join(), nc.scope);
  check('trace explains the narrowing', nc.trace?.some((s: any) => /narrowed/i.test(s.title) && /orders:write/.test(s.detail)), nc.trace);
  check('narrowed token means only read tools, even for a manager', (nc.tools ?? []).length === 4, nc.tools?.length);
  policy = 'deny';
  const dc = await nb.post('/api/obo/connect', {});
  const dj = await dc.json() as any;
  check('policy denial surfaces as a clear error', dc.status === 502 && dj.error === 'access_denied' && /OBO_SCOPES/.test(dj.message), dj);
  policy = 'all';
  trustsUserServer = false;
  const uc = await nb.post('/api/obo/connect', {});
  const uj = await uc.json() as any;
  check('exchange server that does not trust the sign-in server: clear error with the fix', uc.status === 502 && /bad subject token/.test(uj.message) && /Trusted servers/.test(uj.message), uj);
  trustsUserServer = true;

  console.log('6. Expired sign-in');
  subjectTtl = 1; // Okta hands out a subject token that is (almost) already expired, and there is no refresh token
  const eb = browser();
  await eb.signIn();
  const er = await eb.post('/api/obo/connect', {});
  check('asks the user to sign in again', er.status === 401 && ((await er.json()) as any).error === 'id_token_expired');
  subjectTtl = 3600;

  console.log('7. The portal only accepts valid Okta tokens');
  const good = await sign({ uid: '00uINTERN', cid: SVC_ID, scp: ['orders:read'], act: { sub: SVC_ID } }, AUD, 'intern@corp.test');
  const me = await fetch(`${PORTAL}/api/me`, { headers: { Authorization: `Bearer ${good}` } });
  const mej = await me.json() as any;
  check('valid Okta token accepted; role from PORTAL_USER_ROLES; actor read from act', me.status === 200 && mej.role === 'viewer' && mej.actor === SVC_ID && mej.effectiveScopes.join() === 'orders:read', mej);
  const userToken = await sign({ uid: '00uBOSS', cid: LOGIN_APP, scp: ['openid'] }, AUD_USER, 'boss@corp.test', '1h', ISS_USER);
  check('the user\'s own sign-in token is refused by the portal', (await fetch(`${PORTAL}/api/me`, { headers: { Authorization: `Bearer ${userToken}` } })).status === 401);
  const wrongAud = await sign({ uid: '00uBOSS', cid: SVC_ID, scp: ['orders:read'] }, 'api://some-other-api', 'boss@corp.test');
  check('wrong audience refused', (await fetch(`${PORTAL}/api/me`, { headers: { Authorization: `Bearer ${wrongAud}` } })).status === 401);
  const other = await generateKeyPair('RS256');
  const forged = await new SignJWT({ uid: '00uBOSS', cid: SVC_ID, scp: ALL }).setProtectedHeader({ alg: 'RS256', kid: 'okta-kid' }).setIssuer(ISS).setAudience(AUD).setSubject('boss@corp.test').setIssuedAt().setExpirationTime('1h').sign(other.privateKey);
  check('token signed with another key refused', (await fetch(`${PORTAL}/api/me`, { headers: { Authorization: `Bearer ${forged}` } })).status === 401);
  const foreign = await new SignJWT({ scp: ALL }).setProtectedHeader({ alg: 'RS256' }).setIssuer('https://evil.example').setAudience(AUD).setSubject('x').setIssuedAt().setExpirationTime('1h').sign(other.privateKey);
  check('token from an unknown issuer refused', (await fetch(`${PORTAL}/api/me`, { headers: { Authorization: `Bearer ${foreign}` } })).status === 401);
  const noAct = await sign({ uid: '00uBOSS', cid: 'x', scp: ['orders:read'] }, AUD, 'boss@corp.test');
  const nj = await (await fetch(`${PORTAL}/api/me`, { headers: { Authorization: `Bearer ${noAct}` } })).json() as any;
  check('token without act is still valid but has no actor', nj.actor === undefined && nj.role === 'manager', nj);
} catch (e) {
  console.error('TEST ERROR:', e);
  failed++;
} finally {
  cleanup();
}
console.log(failed ? `\n${failed} check(s) failed` : '\nAll checks passed');
process.exit(failed ? 1 : 0);
