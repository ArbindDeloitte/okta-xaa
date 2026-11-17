// Tests RETAIL_LOGIN_MODE=okta: the gateway's /authorize now signs the person in through Okta (OIDC code + PKCE, client
// authenticated with the agent's private key) instead of the demo picker. A mock Okta stands in for the real org.
// Run: npm run test:gateway-okta
import { spawn, type ChildProcess } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { exportJWK, generateKeyPair, importJWK, jwtVerify, SignJWT } from 'jose';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const OKTA_PORT = 14011;
const OKTA = `http://localhost:${OKTA_PORT}`;
const AUTH = 'http://localhost:15111';
const RESOURCE = 'http://localhost:13111/mcp';
const REDIRECT = 'https://gateway.example.test/oauth2/v1/sts/callback';
const AGENT_APP = 'agent-app-client';
const SECRET = 'gw-secret-' + crypto.randomUUID();
const b64u = (b: Buffer) => b.toString('base64url');
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'xaa-gw-okta-'));

// ---- the agent's private key (what Okta's public key would be registered for) --------------
const agentPair = await generateKeyPair('RS256', { extractable: true });
const agentPrivJwk = { ...(await exportJWK(agentPair.privateKey)), kid: 'agent-kid-1' };
const agentPubJwk = await exportJWK(agentPair.publicKey);
const keyFile = path.join(tmp, 'agent-private.jwk.json');
fs.writeFileSync(keyFile, JSON.stringify(agentPrivJwk));

// ---- mock Okta: discovery, authorize (auto sign-in), token (verifies the client assertion), jwks -
const oktaPair = await generateKeyPair('RS256', { extractable: true });
const oktaPubJwk = { ...(await exportJWK(oktaPair.publicKey)), kid: 'okta-kid', alg: 'RS256', use: 'sig' };
const codes = new Map<string, { nonce: string; challenge: string; redirectUri: string; user: { sub: string; email: string; name: string } }>();
let signInAs = { sub: '00uINTERN', email: 'intern@corp.test', name: 'Ian Intern' };
let badNonce = false;
const seen: { authorizeUrl?: URL; assertionOk?: boolean; assertionAud?: string; tokenError?: string } = {};

const okta = http.createServer(async (req, res) => {
  const url = new URL(req.url!, OKTA);
  const json = (o: unknown, code = 200) => { res.writeHead(code, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(o)); };
  if (url.pathname === '/.well-known/openid-configuration') {
    return json({ issuer: OKTA, authorization_endpoint: `${OKTA}/oauth2/v1/authorize`, token_endpoint: `${OKTA}/oauth2/v1/token`, jwks_uri: `${OKTA}/oauth2/v1/keys` });
  }
  if (url.pathname === '/oauth2/v1/keys') return json({ keys: [oktaPubJwk] });
  if (url.pathname === '/oauth2/v1/authorize') {
    seen.authorizeUrl = url;
    const code = 'okta-code-' + crypto.randomUUID();
    codes.set(code, { nonce: url.searchParams.get('nonce')!, challenge: url.searchParams.get('code_challenge')!, redirectUri: url.searchParams.get('redirect_uri')!, user: signInAs });
    const back = new URL(url.searchParams.get('redirect_uri')!);
    back.searchParams.set('code', code);
    back.searchParams.set('state', url.searchParams.get('state')!);
    res.writeHead(302, { Location: back.href });
    return void res.end();
  }
  if (url.pathname === '/oauth2/v1/token' && req.method === 'POST') {
    const form = new URLSearchParams(await new Promise<string>((r) => { let d = ''; req.on('data', (c) => (d += c)); req.on('end', () => r(d)); }));
    try {
      // the client must prove itself with a JWT signed by the agent's private key, audience = this token endpoint
      if (form.get('client_assertion_type') !== 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer') throw new Error('no client assertion');
      const { payload, protectedHeader } = await jwtVerify(form.get('client_assertion')!, await importJWK(agentPubJwk, 'RS256'), { issuer: AGENT_APP, subject: AGENT_APP, audience: `${OKTA}/oauth2/v1/token` });
      seen.assertionOk = protectedHeader.kid === 'agent-kid-1' && Boolean(payload.jti);
      seen.assertionAud = String(payload.aud);
      const rec = codes.get(form.get('code')!);
      codes.delete(form.get('code')!);
      if (!rec) throw new Error('unknown code');
      if (form.get('redirect_uri') !== rec.redirectUri) throw new Error('redirect_uri mismatch');
      if (b64u(crypto.createHash('sha256').update(form.get('code_verifier') ?? '').digest()) !== rec.challenge) throw new Error('PKCE mismatch');
      const idToken = await new SignJWT({ email: rec.user.email, name: rec.user.name, nonce: badNonce ? 'wrong' : rec.nonce })
        .setProtectedHeader({ alg: 'RS256', kid: 'okta-kid' }).setIssuer(OKTA).setAudience(AGENT_APP).setSubject(rec.user.sub).setIssuedAt().setExpirationTime('5m').sign(oktaPair.privateKey);
      return json({ id_token: idToken, access_token: 'unused', token_type: 'Bearer' });
    } catch (e) {
      seen.tokenError = (e as Error).message;
      return json({ error: 'invalid_client', error_description: (e as Error).message }, 401);
    }
  }
  res.writeHead(404); res.end();
});
await new Promise<void>((r) => okta.listen(OKTA_PORT, r));

// ---- the real auth server in Okta-login mode -------------------------------------------------
const env = {
  ...process.env,
  OKTA_ISSUER: OKTA, AGENT_CLIENT_ID: AGENT_APP, AGENT_PRIVATE_KEY_FILE: keyFile, AGENT_KEY_ID: '',
  AUTH_PORT: '15111', RETAIL_AUTH_ISSUER: AUTH, RETAIL_RESOURCE: RESOURCE,
  RETAIL_LOGIN_MODE: 'okta', RETAIL_LOGIN_CLIENT_SECRET: '',
  RETAIL_GATEWAY_CLIENT_ID: 'okta-gateway-test', RETAIL_GATEWAY_CLIENT_SECRET: SECRET, RETAIL_GATEWAY_REDIRECT_URIS: REDIRECT,
  PORTAL_USER_ROLES: '00uBOSS=manager,intern@corp.test=viewer', PORTAL_DEFAULT_ROLE: 'support',
  RETAIL_AUTH_STATE_DIR: path.join(tmp, 'state'),
};
const proc: ChildProcess = spawn(process.execPath, ['--import', 'tsx', path.join(root, 'packages/retail-auth/src/index.ts')], { env, stdio: ['ignore', 'ignore', 'pipe'] });
proc.stderr!.on('data', (d) => process.stderr.write(`[auth] ${d}`));
const cleanup = () => { proc.kill(); okta.close(); fs.rmSync(tmp, { recursive: true, force: true }); };

let failed = 0;
const check = (name: string, cond: boolean, extra?: unknown) => {
  console.log(`${cond ? '  ✔' : '  ✘'} ${name}${cond ? '' : ` -> ${JSON.stringify(extra)}`}`);
  if (!cond) failed++;
};

try {
  for (let i = 0; i < 80; i++) { try { if ((await fetch(`${AUTH}/.well-known/oauth-authorization-server`)).ok) break; } catch { /* retry */ } await new Promise((r) => setTimeout(r, 250)); }

  // Drives the whole browser journey: gateway -> /authorize -> Okta -> /authorize/callback -> consent page.
  async function journey(opts: { decision?: string } = {}) {
    const verifier = b64u(crypto.randomBytes(48));
    const state = 'gw-' + crypto.randomUUID();
    const q = new URLSearchParams({
      client_id: 'okta-gateway-test', response_type: 'code', scope: 'orders:read products:read orders:write returns:read inventory:read customers:read returns:write',
      redirect_uri: REDIRECT, state, code_challenge: b64u(crypto.createHash('sha256').update(verifier).digest()), code_challenge_method: 'S256',
    });
    const step1 = await fetch(`${AUTH}/authorize?${q}`, { redirect: 'manual' });
    const toOkta = step1.headers.get('location') ?? '';
    const step2 = await fetch(toOkta, { redirect: 'manual' }); // mock Okta signs the person in
    const toCallback = step2.headers.get('location') ?? '';
    const step3 = await fetch(toCallback, { redirect: 'manual' });
    const html = step3.status === 200 ? await step3.text() : '';
    let location = step3.headers.get('location') ?? '';
    if (html) {
      const tx = /name="tx" value="([^"]+)"/.exec(html)![1].replace(/&amp;/g, '&');
      const dec = await fetch(`${AUTH}/authorize/decision`, { method: 'POST', body: new URLSearchParams({ tx, decision: opts.decision ?? 'approve' }), headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, redirect: 'manual' });
      location = dec.headers.get('location') ?? '';
    }
    return { step1, toOkta, toCallback, step3, html, location, state, verifier };
  }
  const exchange = (code: string, verifier: string) =>
    fetch(`${AUTH}/oauth/token`, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', Authorization: 'Basic ' + Buffer.from(`okta-gateway-test:${SECRET}`).toString('base64') }, body: new URLSearchParams({ grant_type: 'authorization_code', code, redirect_uri: REDIRECT, code_verifier: verifier }) });
  const claims = (jwt: string) => JSON.parse(Buffer.from(jwt.split('.')[1], 'base64url').toString());

  console.log('\n1. /authorize hands the person to Okta (no demo picker)');
  signInAs = { sub: '00uINTERN', email: 'intern@corp.test', name: 'Ian Intern' };
  const j = await journey();
  check('302 to the Okta authorize endpoint', j.step1.status === 302 && j.toOkta.startsWith(`${OKTA}/oauth2/v1/authorize`), j.toOkta);
  const a = seen.authorizeUrl!;
  check('OIDC code flow with PKCE S256, scope openid profile email', a.searchParams.get('response_type') === 'code' && a.searchParams.get('code_challenge_method') === 'S256' && a.searchParams.get('scope') === 'openid profile email', a.search);
  check('uses the agent app as client_id', a.searchParams.get('client_id') === AGENT_APP);
  check('redirect_uri = <issuer>/authorize/callback', a.searchParams.get('redirect_uri') === `${AUTH}/authorize/callback`, a.searchParams.get('redirect_uri'));
  check('state and nonce present', Boolean(a.searchParams.get('state')) && Boolean(a.searchParams.get('nonce')));

  console.log('\n2. Callback verifies the person and shows the consent screen');
  check('callback shows the consent page', j.step3.status === 200, j.step3.status);
  check('page names the signed-in user and the role (viewer, by email)', j.html.includes('Ian Intern') && j.html.includes('intern@corp.test') && j.html.includes('viewer'), j.html.slice(0, 400));
  check('page lists only the 3 read scopes and the refused ones', j.html.includes('products:read') && j.html.includes('Not allowed for your role') && j.html.includes('returns:write'));
  check('there is no identity picker any more', !j.html.includes('name="user"') && !j.html.includes('Who are you?'));
  check('client authenticated to Okta with the agent private key (private_key_jwt, aud = token endpoint, kid)', seen.assertionOk === true && seen.assertionAud === `${OKTA}/oauth2/v1/token`, seen);

  console.log('\n3. Gateway gets a token for the verified identity');
  const loc = new URL(j.location);
  check('redirects to the gateway callback with a code and the original state', loc.origin + loc.pathname === REDIRECT && Boolean(loc.searchParams.get('code')) && loc.searchParams.get('state') === j.state, j.location);
  const tok = (await (await exchange(loc.searchParams.get('code')!, j.verifier)).json()) as any;
  const c = claims(tok.access_token);
  check('token sub = the Okta user id (same id the XAA path sees), email, role viewer', c.sub === '00uINTERN' && c.email === 'intern@corp.test' && c.role === 'viewer', c);
  check('token scope is capped to the 3 read scopes', c.scope.split(' ').sort().join(' ') === 'inventory:read orders:read products:read', c.scope);
  check('audience = the portal resource, issuer = this server', c.aud === RESOURCE && c.iss === AUTH);

  console.log('\n4. Role by Okta user id (same PORTAL_USER_ROLES entry the XAA path uses)');
  signInAs = { sub: '00uBOSS', email: 'someone@corp.test', name: 'Bea Boss' };
  const boss = await journey();
  const bossTok = (await (await exchange(new URL(boss.location).searchParams.get('code')!, boss.verifier)).json()) as any;
  check('00uBOSS gets role manager with all 7 scopes', claims(bossTok.access_token).role === 'manager' && claims(bossTok.access_token).scope.split(' ').length === 7, claims(bossTok.access_token));
  signInAs = { sub: '00uNEWHIRE', email: 'new@corp.test', name: 'Nia New' };
  const nh = await journey();
  const nhTok = (await (await exchange(new URL(nh.location).searchParams.get('code')!, nh.verifier)).json()) as any;
  check('an unlisted person gets the default role (support)', claims(nhTok.access_token).role === 'support');

  console.log('\n5. Failure cases');
  const deny = await journey({ decision: 'deny' });
  check('Deny redirects back with access_denied + state', new URL(deny.location).searchParams.get('error') === 'access_denied' && new URL(deny.location).searchParams.get('state') === deny.state, deny.location);
  const noState = await fetch(`${AUTH}/authorize/callback?code=x&state=unknown`, { redirect: 'manual' });
  check('callback with an unknown state is refused (400, no redirect)', noState.status === 400 && !noState.headers.get('location'), noState.status);
  const replay = await fetch(j.toCallback, { redirect: 'manual' });
  check('the same callback cannot be replayed (state is single use)', replay.status === 400, replay.status);
  badNonce = true;
  const bn = await journey();
  badNonce = false;
  check('ID token with the wrong nonce is rejected (access_denied)', new URL(bn.location).searchParams.get('error') === 'access_denied', bn.location);
  const forged = await fetch(`${AUTH}/authorize/decision`, { method: 'POST', body: new URLSearchParams({ tx: 'AAAA.BBBB', decision: 'approve', user: 'boss@corp.test' }), headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, redirect: 'manual' });
  check('a forged consent form is rejected', forged.status === 400 && !forged.headers.get('location'));
  const evil = await fetch(`${AUTH}/authorize?${new URLSearchParams({ client_id: 'okta-gateway-test', response_type: 'code', redirect_uri: 'https://evil.test/cb', code_challenge: 'x', code_challenge_method: 'S256' })}`, { redirect: 'manual' });
  check('unregistered redirect_uri is never redirected to or sent to Okta', evil.status === 400 && !evil.headers.get('location'), evil.status);
} finally {
  cleanup();
}
console.log(failed ? `\n${failed} check(s) FAILED` : '\nAll Okta-login checks passed');
process.exit(failed ? 1 : 0);
