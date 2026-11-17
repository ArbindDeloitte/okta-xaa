// End-to-end test of the XAA chain WITHOUT a real Okta org.
// A mock "Okta" issues ID-JAGs (RFC 8693 token exchange); the real retail-auth, retail-portal and
// the agent's XAA client + MCP client run against it. Run: npm run test:e2e
import { spawn, type ChildProcess } from 'node:child_process';
import http from 'node:http';
import path from 'node:path';
import crypto from 'node:crypto';
import os from 'node:os';
import { decodeJwt, exportJWK, generateKeyPair, SignJWT } from 'jose';

const root = path.resolve(import.meta.dirname, '..');
const P = { okta: 14010, auth: 15101, portal: 13101 };
const OKTA = `http://localhost:${P.okta}`;
const AUTH = `http://localhost:${P.auth}`;
const RESOURCE = `http://localhost:${P.portal}`;
const CLIENT_ID = 'agent-at-retail';
const CLIENT_SECRET = 'e2e-secret';

// ---------- mock Okta -------------------------------------------------------------------------
const { publicKey, privateKey } = await generateKeyPair('RS256');
const jwk = { ...(await exportJWK(publicKey)), kid: 'okta-test', alg: 'RS256', use: 'sig' };
let policy: { granted: string } = { granted: '' }; // central XAA policy the "admin" controls
let strictScopes = false; // real Okta rejects the WHOLE request if any requested scope is not allowed on the connection
let overrides: { aud?: string; typ?: string; clientId?: string } = {};
const issuedJags: string[] = [];
const refreshStore = new Map<string, { sub: string; email: string }>();

const oktaServer = http.createServer(async (req, res) => {
  const send = (code: number, body: unknown) => { res.writeHead(code, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(body)); };
  if (req.url === '/.well-known/openid-configuration') return send(200, { issuer: OKTA, jwks_uri: `${OKTA}/jwks`, token_endpoint: `${OKTA}/oauth2/v1/token` });
  if (req.url === '/jwks') return send(200, { keys: [jwk] });
  if (req.url === '/oauth2/v1/token' && req.method === 'POST') {
    const body = new URLSearchParams(await new Promise<string>((r) => { let d = ''; req.on('data', (c) => (d += c)); req.on('end', () => r(d)); }));
    if (body.get('grant_type') !== 'urn:ietf:params:oauth:grant-type:token-exchange' || body.get('requested_token_type') !== 'urn:ietf:params:oauth:token-type:id-jag') {
      return send(400, { error: 'unsupported_grant_type' });
    }
    if (!policy.granted) return send(400, { error: 'access_denied', error_description: 'XAA policy denies this agent' });
    if (strictScopes) {
      const allowed = new Set(policy.granted.split(/\s+/));
      const bad = (body.get('scope') ?? '').split(/\s+/).filter((s) => s && !allowed.has(s));
      if (bad.length) return send(400, { error: 'invalid_scope', error_description: `The following scopes are not allowed for this request: [${bad.join(', ')}].` });
    }
    const st = body.get('subject_token')!;
    const isRefresh = body.get('subject_token_type') === 'urn:ietf:params:oauth:token-type:refresh_token';
    const subj = isRefresh ? refreshStore.get(st) : decodeJwt(st);
    if (!subj) return send(400, { error: 'invalid_grant', error_description: 'unknown or already-used refresh token' });
    let rotated: string | undefined;
    if (isRefresh) { refreshStore.delete(st); rotated = 'rt-' + crypto.randomUUID(); refreshStore.set(rotated, subj as { sub: string; email: string }); }
    const jag = await new SignJWT({ client_id: overrides.clientId ?? CLIENT_ID, scope: policy.granted, email: subj.email as string, resource: body.get('resource') ?? undefined })
      .setProtectedHeader({ alg: 'RS256', typ: overrides.typ ?? 'oauth-id-jag+jwt', kid: 'okta-test' })
      .setIssuer(OKTA).setSubject(subj.sub!).setAudience(overrides.aud ?? body.get('audience')!).setJti(crypto.randomUUID())
      .setIssuedAt().setExpirationTime('5m').sign(privateKey);
    issuedJags.push(jag);
    return send(200, { access_token: jag, issued_token_type: 'urn:ietf:params:oauth:token-type:id-jag', token_type: 'N_A', expires_in: 300, ...(rotated ? { refresh_token: rotated } : {}) });
  }
  send(404, {});
});
await new Promise<void>((r) => oktaServer.listen(P.okta, r));

async function idTokenFor(email: string) {
  return new SignJWT({ email }).setProtectedHeader({ alg: 'RS256', kid: 'okta-test' })
    .setIssuer(OKTA).setSubject('00u' + email.split('@')[0]).setAudience('agent').setIssuedAt().setExpirationTime('1h').sign(privateKey);
}

// ---------- start real services ---------------------------------------------------------------
// ---------- mock OpenAI-compatible LLM (Groq-style) ---------------------------------------------
// Set E2E_LIVE_LLM=1 to skip it and use the LLM configured in your real .env instead.
const live = process.env.E2E_LIVE_LLM === '1';
const LLM_PORT = 14020;
const llmRequests: any[] = [];
let failOnce = false;
const llmServer = http.createServer(async (req, res) => {
  const body = JSON.parse(await new Promise<string>((r) => { let d = ''; req.on('data', (c) => (d += c)); req.on('end', () => r(d)); }));
  llmRequests.push({ auth: req.headers.authorization, body });
  const send = (code: number, json: unknown) => { res.writeHead(code, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(json)); };
  if (failOnce) { failOnce = false; return send(400, { error: { code: 'tool_use_failed', message: 'malformed tool call' } }); }
  const last = body.messages.at(-1);
  if (last.role === 'tool') {
    const order = JSON.parse(last.content);
    return send(200, { choices: [{ finish_reason: 'stop', message: { role: 'assistant', content: `Order ${order.id} is ${order.status}.` } }] });
  }
  return send(200, { choices: [{ finish_reason: 'tool_calls', message: { role: 'assistant', content: null, tool_calls: [{ id: 'call_1', type: 'function', function: { name: 'get_order', arguments: '{"order_id":"SO-10001"}' } }] } }] });
});
if (!live) await new Promise<void>((r) => llmServer.listen(LLM_PORT, r));

const env = {
  ...process.env,
  // hermetic: ignore whatever the real .env says about Okta client auth and the LLM
  AGENT_AUTH_METHOD: 'client_secret', AGENT_KEY_ID: '',
  ...(live ? {} : { LLM_PROVIDER: 'groq', GROQ_API_KEY: 'test-key', GROQ_BASE_URL: `http://localhost:${LLM_PORT}/v1`, GROQ_MODEL: 'mock-model' }),
  OKTA_ISSUER: OKTA, AGENT_CLIENT_ID: 'agent', AGENT_CLIENT_SECRET: 'x',
  AUTH_PORT: String(P.auth), PORTAL_PORT: String(P.portal),
  RETAIL_AUTH_ISSUER: AUTH, RETAIL_RESOURCE: RESOURCE, RETAIL_MCP_URL: `${RESOURCE}/mcp`,
  RETAIL_AGENT_CLIENT_ID: CLIENT_ID, RETAIL_AGENT_CLIENT_SECRET: CLIENT_SECRET,
  RETAIL_AGENT_CLIENTS: 'limited-agent:limited-secret', // a second agent registered at the auth server
  PORTAL_USER_ROLES: 'boss@corp.test=manager,intern@corp.test=viewer', PORTAL_DEFAULT_ROLE: 'support',
  RETAIL_AUTH_STATE_DIR: path.join(os.tmpdir(), `xaa-e2e-${process.pid}`), // never touch the real .keys/
};
const procs: ChildProcess[] = [];
const start = (pkg: string) => {
  const p = spawn(process.execPath, ['--import', 'tsx', path.join(root, 'packages', pkg, 'src/index.ts')], { env, stdio: ['ignore', 'pipe', 'pipe'] });
  p.stderr!.on('data', (d) => process.stderr.write(`[${pkg}] ${d}`));
  procs.push(p);
};
start('retail-auth'); start('retail-portal');
async function waitFor(url: string) {
  for (let i = 0; i < 80; i++) { try { if ((await fetch(url)).ok) return; } catch { /* retry */ } await new Promise((r) => setTimeout(r, 250)); }
  throw new Error(`timeout waiting for ${url}`);
}
await waitFor(`${AUTH}/.well-known/oauth-authorization-server`);
await waitFor(`${RESOURCE}/.well-known/oauth-protected-resource`);

// agent-side code under test (config reads env at import time)
Object.assign(process.env, env);
const { performXaa, XaaError } = await import('../packages/agent/src/xaa.ts');
const { listRetailTools } = await import('../packages/agent/src/agent.ts');
const { Client } = await import('@modelcontextprotocol/sdk/client/index.js');
const { StreamableHTTPClientTransport } = await import('@modelcontextprotocol/sdk/client/streamableHttp.js');

// ---------- tiny test harness -----------------------------------------------------------------
let failed = 0;
const check = (name: string, cond: boolean, extra?: unknown) => {
  console.log(`${cond ? '  ✔' : '  ✘'} ${name}${cond ? '' : ` -> ${JSON.stringify(extra)}`}`);
  if (!cond) failed++;
};
async function session(email: string, granted: string) {
  policy = { granted };
  const trace: any[] = [];
  const refreshToken = 'rt-' + crypto.randomUUID();
  refreshStore.set(refreshToken, { sub: '00u' + email.split('@')[0], email });
  const access = await performXaa({ idToken: await idTokenFor(email), refreshToken }, trace);
  const mcp = new Client({ name: 't', version: '1' });
  await mcp.connect(new StreamableHTTPClientTransport(new URL(`${RESOURCE}/mcp`), { requestInit: { headers: { Authorization: `Bearer ${access.accessToken}` } } }));
  const call = async (name: string, args: Record<string, unknown>) => {
    const r = await mcp.callTool({ name, arguments: args });
    const text = (r.content as any[]).map((c) => c.text).join('');
    return { isError: Boolean(r.isError), json: JSON.parse(text) };
  };
  return { access, mcp, call, trace };
}
const ALL = 'products:read inventory:read orders:read customers:read orders:write returns:read returns:write';

try {
  console.log('\n1. Happy path: support user, all scopes granted by Okta');
  const a = await session('alice@corp.test', ALL);
  check('XAA produced 3 trace steps', a.trace.length === 3 && a.trace.every((s) => s.status === 'ok'), a.trace.map((s) => s.status));
  check('access token has all scopes', a.access.scope.length === 7, a.access.scope);
  check('access token carries email + sub', a.access.claims.email === 'alice@corp.test' && a.access.claims.sub === '00ualice', a.access.claims);
  const tools = (await a.mcp.listTools()).tools.map((t) => t.name);
  check('agent sees all 8 tools', tools.length === 8, tools);
  const s1 = await a.call('search_products', { query: 'access point' });
  check('search_products works', !s1.isError && s1.json[0]?.sku === 'HPE-2001', s1);
  const inv = await a.call('check_inventory', { sku: 'HPE-1001', location: 'DC-SINGAPORE' });
  check('check_inventory works', inv.json.onHand === 3, inv);
  const ret1 = await a.call('create_return', { order_id: 'SO-10001', sku: 'HPE-2001', qty: 1, reason: 'wrong size' });
  check('small refund auto-approved', ret1.json.status === 'approved', ret1);
  const ret2 = await a.call('create_return', { order_id: 'SO-10008', sku: 'HPE-3002', qty: 1, reason: 'defective' });
  check('credit > $5,000 by support needs manager approval', ret2.json.status === 'pending_manager_approval', ret2);
  const ret3 = await a.call('create_return', { order_id: 'SO-10004', sku: 'HPE-3001', qty: 1, reason: 'late' });
  check('return window enforced (45 days)', ret3.isError && /window closed/.test(ret3.json.message), ret3);
  const can = await a.call('cancel_order', { order_id: 'SO-10005', reason: 'customer request' });
  check('cancel processing order works', can.json.status === 'cancelled', can);
  const can2 = await a.call('cancel_order', { order_id: 'SO-10001', reason: 'x' });
  check('cancel delivered order refused', can2.isError, can2);
  await a.mcp.close();

  console.log('\n2. Central governance: Okta grants read-only scopes');
  const b = await session('alice@corp.test', 'products:read orders:read');
  const bt = (await b.mcp.listTools()).tools.map((t) => t.name).sort();
  check('agent only sees tools for granted scopes', JSON.stringify(bt) === JSON.stringify(['get_order', 'list_orders', 'search_products']), bt);
  check('token scope intersected with Okta grant', b.access.scope.join(' ') === 'products:read orders:read', b.access.scope);
  await b.mcp.close();

  console.log('\n3. Same agent, same Okta grant (all 7 scopes): the signed-in USER decides what they get');
  const c = await session('intern@corp.test', ALL); // intern@ is a viewer; alice@ (section 1) is support
  check('the auth server reports the user role', c.access.role === 'viewer', c.access.role);
  check('viewer token is reduced to the 3 read scopes', c.access.scope.join(' ') === 'products:read inventory:read orders:read', c.access.scope);
  const vtools = (await c.mcp.listTools()).tools.map((t) => t.name).sort();
  check('viewer agent only sees the 4 read tools (support user saw 8)', JSON.stringify(vtools) === JSON.stringify(['check_inventory', 'get_order', 'list_orders', 'search_products']), vtools);
  const r = await c.call('get_order', { order_id: 'SO-10001' });
  check('viewer can read orders', !r.isError, r);
  const direct = await fetch(`${RESOURCE}/api/tools/create_return`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${c.access.accessToken}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ order_id: 'SO-10001', sku: 'HPE-4004', qty: 1, reason: 'x' }),
  });
  check('viewer cannot call a write tool even directly over REST (403 insufficient_scope)', direct.status === 403 && ((await direct.json()) as { error?: string }).error === 'insufficient_scope');
  await c.mcp.close();

  console.log('\n4. Manager has no refund limit');
  const m = await session('boss@corp.test', ALL);
  const mr = await m.call('create_return', { order_id: 'SO-10008', sku: 'HPE-3001', qty: 1, reason: 'defective' });
  check('manager return auto-approved', mr.json.status === 'approved', mr);
  await m.mcp.close();

  console.log('\n5. Okta denies the agent');
  policy = { granted: '' };
  try { await performXaa({ idToken: await idTokenFor('alice@corp.test'), refreshToken: 'rt-unknown' }, []); check('XAA error surfaced', false); }
  catch (e) { check('XAA error surfaced (access_denied, step 2)', e instanceof XaaError && e.code === 'access_denied' && e.step === 2, String(e)); }

  console.log('\n5b. Okta rejects scopes outside the connection: the agent retries with only the allowed ones');
  strictScopes = true;
  policy = { granted: 'products:read inventory:read orders:read' };
  const rtNarrow = 'rt-' + crypto.randomUUID();
  refreshStore.set(rtNarrow, { sub: '00ualice', email: 'alice@corp.test' });
  const narrowTrace: any[] = [];
  const narrowed = await performXaa({ idToken: await idTokenFor('alice@corp.test'), refreshToken: rtNarrow }, narrowTrace);
  check('exchange succeeds after the retry, with exactly the allowed scopes', [...narrowed.scope].sort().join(' ') === 'inventory:read orders:read products:read', narrowed.scope);
  check('trace explains which scopes Okta refused', narrowTrace.some((s) => /narrowed/i.test(s.title) && s.detail.includes('customers:read') && s.detail.includes('returns:write')), narrowTrace.map((s) => s.title));
  policy = { granted: 'unrelated:scope' };
  const rtNone = 'rt-' + crypto.randomUUID();
  refreshStore.set(rtNone, { sub: '00ualice', email: 'alice@corp.test' });
  try { await performXaa({ idToken: await idTokenFor('alice@corp.test'), refreshToken: rtNone }, []); check('nothing allowed -> error', false); }
  catch (e) { check('when NONE of the requested scopes is allowed, invalid_scope is surfaced (step 2)', e instanceof XaaError && e.code === 'invalid_scope' && e.step === 2, String(e)); }
  strictScopes = false;
  policy = { granted: ALL };

  console.log('\n6. Attacks on the retail authorization server');
  policy = { granted: ALL };
  const tokenUrl = `${AUTH}/oauth/token`;
  const exchange = (assertion: string, cid = CLIENT_ID, secret = CLIENT_SECRET) =>
    fetch(tokenUrl, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer', assertion, client_id: cid, client_secret: secret }) });
  const idTok = await idTokenFor('alice@corp.test');
  const fresh = async () => { await performXaaViaOkta(idTok); return issuedJags.at(-1)!; };
  const performXaaViaOkta = (t: string) => fetch(`${OKTA}/oauth2/v1/token`, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange', requested_token_type: 'urn:ietf:params:oauth:token-type:id-jag', subject_token: t, subject_token_type: 'urn:ietf:params:oauth:token-type:id_token', audience: AUTH }) });
  const jag1 = await fresh();
  check('first use of ID-JAG succeeds', (await exchange(jag1)).status === 200);
  const replay = await exchange(jag1);
  check('replayed ID-JAG rejected', replay.status === 400 && (await replay.json()).error === 'invalid_grant');
  check('bad client secret rejected (401)', (await exchange(await fresh(), CLIENT_ID, 'nope')).status === 401);
  overrides = { aud: 'http://evil.example' };
  const wrongAud = await exchange(await fresh());
  check('wrong audience rejected', wrongAud.status === 400 && (await wrongAud.json()).error === 'invalid_grant');
  overrides = { typ: 'JWT' };
  const wrongTyp = await exchange(await fresh());
  check('wrong typ (not oauth-id-jag+jwt) rejected', wrongTyp.status === 400);
  overrides = {};
  const idAsAssertion = await exchange(idTok);
  check('plain ID token as assertion rejected', idAsAssertion.status === 400);

  console.log('\n6b. A second (limited) agent client at the same authorization server');
  overrides = { clientId: 'limited-agent' };
  const okLimited = await exchange(await fresh(), 'limited-agent', 'limited-secret');
  const limitedBody = (await okLimited.json()) as { access_token?: string };
  check('second agent can redeem its own ID-JAG, token carries its client_id', okLimited.status === 200 && decodeJwt(limitedBody.access_token ?? '').client_id === 'limited-agent', limitedBody);
  const cross = await exchange(await fresh()); // the FIRST agent's credentials with the second agent's ID-JAG
  check("one agent cannot redeem another agent's ID-JAG", cross.status === 400 && ((await cross.json()) as { error?: string }).error === 'invalid_grant');
  overrides = {};
  check('unknown agent client id is rejected (401)', (await exchange(await fresh(), 'not-an-agent', 'x')).status === 401);
  check('second agent with a wrong secret is rejected (401)', (await exchange(await fresh(), 'limited-agent', 'wrong')).status === 401);

  console.log('\n7. Portal rejects bad bearer tokens');
  check('no token -> 401', (await fetch(`${RESOURCE}/api/me`)).status === 401);
  check('garbage token -> 401', (await fetch(`${RESOURCE}/api/me`, { headers: { Authorization: 'Bearer abc.def.ghi' } })).status === 401);
  const forged = await new SignJWT({ scope: ALL, client_id: CLIENT_ID }).setProtectedHeader({ alg: 'RS256', typ: 'at+jwt' }).setIssuer(AUTH).setAudience(RESOURCE).setSubject('x').setExpirationTime('5m').sign(privateKey);
  check('token signed by the wrong key -> 401', (await fetch(`${RESOURCE}/mcp`, { method: 'POST', headers: { Authorization: `Bearer ${forged}`, 'Content-Type': 'application/json' }, body: '{}' })).status === 401);

  console.log('\n7b. Okta rotates the refresh token on every use');
  policy = { granted: ALL };
  const rtFirst = 'rt-' + crypto.randomUUID();
  refreshStore.set(rtFirst, { sub: '00urot', email: 'rot@corp.test' });
  const tokensObj = { idToken: await idTokenFor('rot@corp.test'), refreshToken: rtFirst };
  await performXaa(tokensObj, []);
  check('first exchange returns a rotated refresh token', tokensObj.refreshToken !== rtFirst, tokensObj.refreshToken);
  let secondOk = true;
  try { await performXaa(tokensObj, []); } catch (e) { secondOk = false; console.log(String(e)); }
  check('second exchange works with the rotated token', secondOk);
  let staleRejected = false;
  try { await performXaa({ idToken: tokensObj.idToken, refreshToken: rtFirst }, []); } catch (e) { staleRejected = e instanceof XaaError && e.code === 'invalid_grant'; }
  check('stale (already used) refresh token is rejected', staleRejected);

  console.log(`\n7c. Agent LLM loop (${live ? 'LIVE LLM from .env' : 'mock OpenAI-compatible server'})`);
  const { runAgent } = await import('../packages/agent/src/agent.ts');
  policy = { granted: ALL };
  const full = await session('alice@corp.test', ALL);
  if (live) {
    const out = await runAgent({ accessToken: full.access.accessToken, userLabel: 'alice@corp.test', history: [], message: 'Which orders are still processing, and how many units of HPE-1001 are in DC-SINGAPORE? Use the tools.' });
    console.log(`   tools called: ${out.toolCalls.map((t) => t.name).join(', ') || '(none)'}`);
    console.log(`   reply: ${out.reply.slice(0, 600)}`);
    check('live LLM called portal tools through MCP and replied', out.toolCalls.length >= 1 && out.toolCalls.every((t) => !t.isError) && out.reply.length > 10, out);
  } else {
    const out = await runAgent({ accessToken: full.access.accessToken, userLabel: 'alice@corp.test', history: [{ role: 'user', content: 'hi' }, { role: 'assistant', content: 'hello' }], message: 'status of SO-10001?' });
    check('LLM tool call went through MCP to the portal', out.toolCalls.length === 1 && out.toolCalls[0].name === 'get_order' && !out.toolCalls[0].isError, out.toolCalls);
    check('final reply is built from the tool result', out.reply === 'Order SO-10001 is delivered.', out.reply);
    const first = llmRequests[0];
    check('request used the Bearer key and OpenAI-style function tools (no $schema)', first.auth === 'Bearer test-key' && first.body.tools?.[0]?.type === 'function' && !('$schema' in first.body.tools[0].function.parameters), first.body.tools?.[0]);
    check('system prompt first, history kept, then the user message', first.body.messages[0].role === 'system' && first.body.messages[1].content === 'hi' && first.body.messages.at(-1).content === 'status of SO-10001?', first.body.messages.map((m: any) => m.role));
    check('tool result was sent back as a "tool" message', llmRequests[1].body.messages.at(-1).role === 'tool' && llmRequests[1].body.messages.at(-2).tool_calls?.[0]?.id === 'call_1', llmRequests[1].body.messages.map((m: any) => m.role));
    failOnce = true;
    const retried = await runAgent({ accessToken: full.access.accessToken, userLabel: 'alice@corp.test', history: [], message: 'again' });
    check('retries once when the model emits a malformed tool call', retried.reply === 'Order SO-10001 is delivered.', retried.reply);
    const ro = await session('alice@corp.test', 'orders:read');
    llmRequests.length = 0;
    await runAgent({ accessToken: ro.access.accessToken, userLabel: 'alice@corp.test', history: [], message: 'status?' });
    const sent = llmRequests[0].body.tools.map((t: any) => t.function.name).sort();
    check('LLM is only offered the tools Okta granted', JSON.stringify(sent) === JSON.stringify(['get_order', 'list_orders']), sent);
    await ro.mcp.close();
  }
  await full.mcp.close();

  console.log('\n8. Audit log');
  const audit = (await (await fetch(`${RESOURCE}/admin/api/audit`)).json()) as any[];
  check('audit has allow, deny and error decisions', ['allow', 'deny', 'error'].every((d) => audit.some((x) => x.decision === d)), audit.length);
} catch (e) {
  console.error('\nTEST CRASHED:', e);
  failed++;
} finally {
  procs.forEach((p) => p.kill());
  oktaServer.close();
  llmServer.close();
}
console.log(failed ? `\n${failed} check(s) FAILED` : '\nAll checks passed');
process.exit(failed ? 1 : 0);
