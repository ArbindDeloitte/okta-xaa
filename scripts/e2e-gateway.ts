// Tests the authorization-code flow that Okta Agent Gateway ("brokered consent") uses against the retail
// authorization server: /authorize (demo sign-in) -> code -> /oauth/token -> portal call -> refresh.
// Hermetic: starts its own auth server + portal on spare ports; does not touch Okta or your .env values.
import { spawn, type ChildProcess } from 'node:child_process';
import crypto from 'node:crypto';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const AUTH = 'http://localhost:15101';
const BASE = 'http://localhost:13101';
const RESOURCE = `${BASE}/mcp`; // clean layout: the resource identifier IS the MCP endpoint (like GitHub/Slack MCP)
const REDIRECT = 'https://gateway.example.test/oauth2/v1/sts/callback';
const SECRET = 'test-gateway-secret-' + crypto.randomUUID();

const env = {
  ...process.env,
  OKTA_ISSUER: 'http://localhost:1', // unused by this flow
  AUTH_PORT: '15101', PORTAL_PORT: '13101',
  RETAIL_AUTH_ISSUER: AUTH, RETAIL_RESOURCE: RESOURCE,
  RETAIL_LOGIN_MODE: 'picker', // this test covers the demo picker; the Okta sign-in has its own test (test:gateway-okta)
  RETAIL_GATEWAY_CLIENT_ID: 'okta-gateway-test', RETAIL_GATEWAY_CLIENT_SECRET: SECRET, RETAIL_GATEWAY_REDIRECT_URIS: REDIRECT,
  PORTAL_USER_ROLES: 'boss@corp.test=manager,intern@corp.test=viewer', PORTAL_DEFAULT_ROLE: 'support',
  RETAIL_AUTH_STATE_DIR: path.join(os.tmpdir(), `xaa-gw-e2e-${process.pid}`), // never touch the real .keys/
};
const procs: ChildProcess[] = [];
const start = (pkg: string) => {
  const p = spawn(process.execPath, ['--import', 'tsx', path.join(root, 'packages', pkg, 'src/index.ts')], { env, stdio: ['ignore', 'ignore', 'pipe'] });
  p.stderr!.on('data', (d) => process.stderr.write(`[${pkg}] ${d}`));
  procs.push(p);
  return p;
};
let authProc = start('retail-auth');
start('retail-portal');
const stop = () => procs.forEach((p) => p.kill());
async function waitFor(url: string) {
  for (let i = 0; i < 80; i++) { try { if ((await fetch(url)).ok) return; } catch { /* retry */ } await new Promise((r) => setTimeout(r, 250)); }
  throw new Error(`timeout waiting for ${url}`);
}

let failed = 0;
const check = (name: string, cond: boolean, extra?: unknown) => {
  console.log(`${cond ? '  ✔' : '  ✘'} ${name}${cond ? '' : ` -> ${JSON.stringify(extra)}`}`);
  if (!cond) failed++;
};
const b64u = (b: Buffer) => b.toString('base64url');
const ALL = 'orders:read products:read orders:write returns:read inventory:read customers:read returns:write';

try {
  await waitFor(`${AUTH}/.well-known/oauth-authorization-server`);
  await waitFor(`${BASE}/.well-known/oauth-protected-resource/mcp`);

  console.log('\n1. Metadata advertises the flow');
  const meta: any = await (await fetch(`${AUTH}/.well-known/oauth-authorization-server`)).json();
  check('authorization_endpoint present', meta.authorization_endpoint === `${AUTH}/authorize`, meta);
  check('grants include authorization_code + refresh_token', meta.grant_types_supported.includes('authorization_code') && meta.grant_types_supported.includes('refresh_token'), meta.grant_types_supported);
  check('PKCE S256 advertised', meta.code_challenge_methods_supported?.[0] === 'S256');

  // Runs /authorize -> picks a user -> returns the redirect Location from the decision.
  async function authorize(user: string, opts: { redirect?: string; decision?: string; scope?: string; method?: string } = {}) {
    const verifier = b64u(crypto.randomBytes(48));
    const params = new URLSearchParams({
      client_id: 'okta-gateway-test', response_type: 'code', scope: opts.scope ?? ALL, redirect_uri: opts.redirect ?? REDIRECT,
      state: 'st-' + crypto.randomUUID(), code_challenge: b64u(crypto.createHash('sha256').update(verifier).digest()), code_challenge_method: opts.method ?? 'S256',
    });
    const page = await fetch(`${AUTH}/authorize?${params}`, { redirect: 'manual' });
    if (page.status !== 200) return { page, verifier, state: params.get('state')!, location: page.headers.get('location') ?? '' };
    const html = await page.text();
    const tx = /name="tx" value="([^"]+)"/.exec(html)![1].replace(/&amp;/g, '&');
    const form = new URLSearchParams({ tx, user: user.includes('@') && !user.startsWith('other:') ? user : '__other', decision: opts.decision ?? 'approve' });
    if (user.startsWith('other:')) form.set('other_email', user.slice(6));
    const decision = await fetch(`${AUTH}/authorize/decision`, { method: 'POST', body: form, headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, redirect: 'manual' });
    return { page, html, verifier, state: params.get('state')!, location: decision.headers.get('location') ?? '', status: decision.status };
  }
  const token = (body: Record<string, string>, secret = SECRET) =>
    fetch(`${AUTH}/oauth/token`, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', Authorization: 'Basic ' + Buffer.from(`okta-gateway-test:${secret}`).toString('base64') }, body: new URLSearchParams(body) });
  const mcpTools = async (accessToken: string) => {
    const r = await fetch(RESOURCE, { method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream', Authorization: `Bearer ${accessToken}` }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' }) });
    const text = await r.text();
    const json = JSON.parse(text.startsWith('event:') ? text.split('\n').find((l) => l.startsWith('data:'))!.slice(5) : text);
    return { status: r.status, names: (json.result?.tools ?? []).map((t: any) => t.name) as string[] };
  };
  const claims = (jwt: string) => JSON.parse(Buffer.from(jwt.split('.')[1], 'base64url').toString());

  console.log('\n2. Manager signs in and approves');
  const a = await authorize('boss@corp.test');
  check('sign-in page shows the picker', a.page.status === 200 && a.html!.includes('boss@corp.test'), a.page.status);
  check('page is not frameable', a.page.headers.get('x-frame-options') === 'DENY');
  const loc = new URL(a.location);
  check('redirects to the registered redirect_uri with a code + state', loc.origin + loc.pathname === REDIRECT && Boolean(loc.searchParams.get('code')) && loc.searchParams.get('state') === a.state, a.location);
  const code = loc.searchParams.get('code')!;
  const t1 = await (await token({ grant_type: 'authorization_code', code, redirect_uri: REDIRECT, code_verifier: a.verifier })).json() as any;
  check('token response has access + refresh token', Boolean(t1.access_token) && Boolean(t1.refresh_token), t1);
  const c1 = claims(t1.access_token);
  check('claims: sub/email = boss, role manager, aud = portal, 7 scopes', c1.sub === 'boss@corp.test' && c1.role === 'manager' && c1.aud === RESOURCE && c1.iss === AUTH && c1.scope.split(' ').length === 7, c1);
  const tools1 = await mcpTools(t1.access_token);
  check('portal accepts the token and offers all 8 tools', tools1.status === 200 && tools1.names.length === 8, tools1);

  const rootPost = await fetch(`${BASE}/`, { method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream', Authorization: `Bearer ${t1.access_token}` }, body: '{}' });
  check('MCP is served only at the resource identifier (POST on the bare base URL is 404)', rootPost.status === 404, rootPost.status);
  const md: any = await (await fetch(`${BASE}/.well-known/oauth-protected-resource/mcp`)).json();
  check('path-inserted RFC 9728 metadata reports resource = the /mcp identifier', md.resource === RESOURCE && md.authorization_servers?.[0] === AUTH, md);
  const noTok = await fetch(RESOURCE, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
  check('no token -> 401 with resource_metadata pointing at the path-inserted URL', noTok.status === 401 && (noTok.headers.get('www-authenticate') ?? '').includes(`${BASE}/.well-known/oauth-protected-resource/mcp`), noTok.headers.get('www-authenticate'));

  console.log('\n3. Code is single use, PKCE and client are enforced');
  const replay = await token({ grant_type: 'authorization_code', code, redirect_uri: REDIRECT, code_verifier: a.verifier });
  check('replayed code rejected', replay.status === 400 && ((await replay.json()) as any).error === 'invalid_grant');
  const b = await authorize('boss@corp.test');
  const badPkce = await token({ grant_type: 'authorization_code', code: new URL(b.location).searchParams.get('code')!, redirect_uri: REDIRECT, code_verifier: b64u(crypto.randomBytes(48)) });
  check('wrong PKCE verifier rejected', badPkce.status === 400);
  const c = await authorize('boss@corp.test');
  const badSecret = await token({ grant_type: 'authorization_code', code: new URL(c.location).searchParams.get('code')!, redirect_uri: REDIRECT, code_verifier: c.verifier }, 'wrong');
  check('wrong client secret rejected (401)', badSecret.status === 401);
  const d = await authorize('boss@corp.test');
  const badRedirect = await token({ grant_type: 'authorization_code', code: new URL(d.location).searchParams.get('code')!, redirect_uri: 'https://evil.test/cb', code_verifier: d.verifier });
  check('redirect_uri mismatch at token endpoint rejected', badRedirect.status === 400);

  console.log('\n4. Per-user role caps the scopes (viewer)');
  const v = await authorize('intern@corp.test');
  const tv = await (await token({ grant_type: 'authorization_code', code: new URL(v.location).searchParams.get('code')!, redirect_uri: REDIRECT, code_verifier: v.verifier })).json() as any;
  const cv = claims(tv.access_token);
  check('viewer gets 3 read scopes only', cv.role === 'viewer' && cv.scope.split(' ').sort().join(' ') === 'inventory:read orders:read products:read', cv);
  const toolsV = await mcpTools(tv.access_token);
  check('viewer sees only read tools (4)', toolsV.names.length === 4 && !toolsV.names.includes('create_return'), toolsV.names);
  const o = await authorize('other:newhire@corp.test');
  const to = await (await token({ grant_type: 'authorization_code', code: new URL(o.location).searchParams.get('code')!, redirect_uri: REDIRECT, code_verifier: o.verifier })).json() as any;
  check('unlisted person gets the default role (support)', claims(to.access_token).role === 'support');

  console.log('\n5. Refresh token rotates');
  const r1 = await (await token({ grant_type: 'refresh_token', refresh_token: t1.refresh_token })).json() as any;
  check('refresh issues a new access + refresh token', Boolean(r1.access_token) && r1.refresh_token !== t1.refresh_token, r1);
  const reuse = await token({ grant_type: 'refresh_token', refresh_token: t1.refresh_token });
  check('old refresh token cannot be reused', reuse.status === 400);
  const rv = await (await token({ grant_type: 'refresh_token', refresh_token: tv.refresh_token, scope: 'orders:read' })).json() as any;
  check('refresh can narrow scope', rv.scope === 'orders:read', rv);

  console.log('\n5b. A restart of the auth server does not invalidate gateway tokens');
  const before = await authorize('boss@corp.test');
  const tb = await (await token({ grant_type: 'authorization_code', code: new URL(before.location).searchParams.get('code')!, redirect_uri: REDIRECT, code_verifier: before.verifier })).json() as any;
  authProc.kill();
  await new Promise((r) => setTimeout(r, 800));
  authProc = start('retail-auth');
  await waitFor(`${AUTH}/.well-known/oauth-authorization-server`);
  const afterTools = await mcpTools(tb.access_token);
  check('access token minted BEFORE the restart is still accepted by the portal', afterTools.status === 200 && afterTools.names.length === 8, afterTools);
  const afterRefresh = (await (await token({ grant_type: 'refresh_token', refresh_token: tb.refresh_token })).json()) as any;
  check('refresh token issued BEFORE the restart still works', Boolean(afterRefresh.access_token), afterRefresh);
  check('a token minted after the restart verifies too', (await mcpTools(afterRefresh.access_token)).status === 200);

  console.log('\n6. Bad authorization requests');
  const evil = await authorize('boss@corp.test', { redirect: 'https://evil.test/cb' });
  check('unregistered redirect_uri is NOT redirected to (400 page)', evil.page.status === 400 && !evil.location, evil.page.status);
  const noPkce = await authorize('boss@corp.test', { method: 'plain' });
  check('missing S256 PKCE redirects back with invalid_request', new URL(noPkce.location).searchParams.get('error') === 'invalid_request', noPkce.location);
  const denied = await authorize('boss@corp.test', { decision: 'deny' });
  check('deny redirects back with access_denied + state', new URL(denied.location).searchParams.get('error') === 'access_denied' && new URL(denied.location).searchParams.get('state') === denied.state, denied.location);
  const forged = await fetch(`${AUTH}/authorize/decision`, { method: 'POST', body: new URLSearchParams({ tx: 'AAAA.BBBB', user: 'boss@corp.test', decision: 'approve' }), headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, redirect: 'manual' });
  check('forged consent form rejected', forged.status === 400 && !forged.headers.get('location'));
  const ij = await fetch(`${AUTH}/oauth/token`, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', Authorization: 'Basic ' + Buffer.from(`okta-gateway-test:${SECRET}`).toString('base64') }, body: new URLSearchParams({ grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer', assertion: 'x' }) });
  check('gateway client cannot use the ID-JAG grant (client unknown there)', ij.status === 401);
} finally {
  stop();
}
console.log(failed ? `\n${failed} check(s) FAILED` : '\nAll gateway-flow checks passed');
process.exit(failed ? 1 : 0);
