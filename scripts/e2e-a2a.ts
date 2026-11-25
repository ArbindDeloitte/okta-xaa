// End-to-end test of the DIRECT A2A path (packages/agent -> packages/agent-hr) WITHOUT a real Okta org.
// A mock "Okta" plays BOTH roles the real org plays for this flow: the org authorization server (RFC 8693
// token-exchange -> ID-JAG) and the HR Agent's own custom authorization server (RFC 7523 jwt-bearer -> access
// token) -- the same single-mock-server trick scripts/e2e-obo.ts already uses for its two custom authorization
// servers. The real agent-hr app runs as a real process; packages/agent's a2a.ts and agent.ts run in-process
// (same technique scripts/e2e.ts uses for xaa.ts). Run: npm run test:a2a
//
// Set E2E_LIVE_LLM=1 to ALSO use the real LLM configured in .env for the HR Agent's own internal Claude call (it
// has no mock-swap option, unlike the main agent's Groq fallback) -- without it, those specific replies show a
// graceful "ANTHROPIC_API_KEY is not set" error instead of a real HR answer; the Okta exchange and the A2A wire
// protocol itself are fully exercised either way.
import { spawn, type ChildProcess } from 'node:child_process';
import crypto from 'node:crypto';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import dotenv from 'dotenv';
import { decodeJwt, exportJWK, generateKeyPair, jwtVerify, SignJWT } from 'jose';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
// Load the real .env BEFORE anything is spawned or configured below (nothing else in this script would -- each
// app normally does this itself, in its own env.ts, but that only runs once ITS process starts). Needed only so
// that with E2E_LIVE_LLM=1 the real ANTHROPIC_API_KEY/BEDROCK_API_KEY reach the spawned agent-hr process; the
// hermetic (non-live) path below overrides these back out regardless of what .env contains.
dotenv.config({ path: path.join(root, '.env'), quiet: true });
if (!process.env.BEDROCK_API_KEY?.trim() && process.env.AWS_BEARER_TOKEN_BEDROCK?.trim()) process.env.BEDROCK_API_KEY = process.env.AWS_BEARER_TOKEN_BEDROCK.trim();
const P = { okta: 14060, hr: 14070, groq: 14080, mcp: 14090 };
const OKTA = `http://localhost:${P.okta}`;
const ORG_TOKEN_EP = `${OKTA}/oauth2/v1/token`;
const HR_ISSUER = `${OKTA}/oauth2/hr-as`; // the HR Agent's OWN authorization server, on the same mock
const HR_URL = `http://localhost:${P.hr}`;
const MCP = `http://localhost:${P.mcp}/mcp`;
const live = process.env.E2E_LIVE_LLM === '1';

// ---------- mock Okta: org AS (token-exchange) + HR Agent's own AS (jwt-bearer + JWKS) -----------
const { publicKey, privateKey } = await generateKeyPair('RS256');
const jwk = { ...(await exportJWK(publicKey)), kid: 'okta-test', alg: 'RS256', use: 'sig' };
let policy: { granted: string } = { granted: 'hr:read hr:write' };
let strictScopes = false;
const issuedJags = new Set<string>(); // ID-JAGs are single-use
const refreshStore = new Map<string, { sub: string }>();

const oktaServer = http.createServer(async (req, res) => {
  const send = (code: number, body: unknown) => { res.writeHead(code, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(body)); };
  const body = req.method === 'POST' ? new URLSearchParams(await new Promise<string>((r) => { let d = ''; req.on('data', (c) => (d += c)); req.on('end', () => r(d)); })) : undefined;

  if (req.url === '/.well-known/openid-configuration') return send(200, { issuer: OKTA, jwks_uri: `${OKTA}/jwks`, token_endpoint: ORG_TOKEN_EP });
  if (req.url === '/jwks') return send(200, { keys: [jwk] });

  if (req.url === '/oauth2/v1/token' && req.method === 'POST' && body) {
    if (body.get('grant_type') !== 'urn:ietf:params:oauth:grant-type:token-exchange' || body.get('requested_token_type') !== 'urn:ietf:params:oauth:token-type:id-jag') {
      return send(400, { error: 'unsupported_grant_type' });
    }
    // Real Okta rejects the WHOLE request (and does not consume the refresh token) if any requested scope is
    // not allowed -- check that BEFORE touching refreshStore, so a rejected request leaves the token usable for
    // the caller's retry. (scripts/e2e.ts's own mock Okta already gets this order right; this mirrors it.)
    const requested = (body.get('scope') ?? '').split(/\s+/).filter(Boolean);
    const allowed = new Set(policy.granted.split(/\s+/));
    if (strictScopes) {
      const bad = requested.filter((s) => !allowed.has(s));
      if (bad.length) return send(400, { error: 'invalid_scope', error_description: `The following scopes are not allowed for this request: [${bad.join(', ')}].` });
    }
    const st = body.get('subject_token')!;
    const isRefresh = body.get('subject_token_type') === 'urn:ietf:params:oauth:token-type:refresh_token';
    const subj = isRefresh ? refreshStore.get(st) : decodeJwt(st);
    if (!subj) return send(400, { error: 'invalid_grant', error_description: 'unknown or already-used refresh token' });
    let rotated: string | undefined;
    if (isRefresh) { refreshStore.delete(st); rotated = 'rt-' + crypto.randomUUID(); refreshStore.set(rotated, subj as { sub: string }); }
    const granted = requested.filter((s) => allowed.has(s)).join(' ') || policy.granted;
    const jag = await new SignJWT({ client_id: 'agent', scope: granted, resource: body.get('resource') ?? undefined })
      .setProtectedHeader({ alg: 'RS256', typ: 'oauth-id-jag+jwt', kid: 'okta-test' })
      .setIssuer(OKTA).setSubject(subj.sub!).setAudience(body.get('audience')!).setJti(crypto.randomUUID())
      .setIssuedAt().setExpirationTime('5m').sign(privateKey);
    return send(200, { access_token: jag, issued_token_type: 'urn:ietf:params:oauth:token-type:id-jag', token_type: 'N_A', expires_in: 300, ...(rotated ? { refresh_token: rotated } : {}) });
  }

  if (req.url === '/oauth2/hr-as/v1/keys') return send(200, { keys: [jwk] });
  if (req.url === '/oauth2/hr-as/.well-known/openid-configuration') return send(200, { issuer: HR_ISSUER, jwks_uri: `${HR_ISSUER}/v1/keys`, token_endpoint: `${HR_ISSUER}/v1/token` });
  if (req.url === '/oauth2/hr-as/v1/token' && req.method === 'POST' && body) {
    if (body.get('grant_type') !== 'urn:ietf:params:oauth:grant-type:jwt-bearer') return send(400, { error: 'unsupported_grant_type' });
    const assertion = body.get('assertion')!;
    let payload;
    try {
      ({ payload } = await jwtVerify(assertion, publicKey, { issuer: OKTA, audience: HR_ISSUER, typ: 'oauth-id-jag+jwt', algorithms: ['RS256'] }));
    } catch (e) {
      return send(400, { error: 'invalid_grant', error_description: `ID-JAG validation failed: ${(e as Error).message}` });
    }
    if (!payload.jti || issuedJags.has(payload.jti)) return send(400, { error: 'invalid_grant', error_description: 'ID-JAG missing jti or already used' });
    issuedJags.add(payload.jti);
    // Confirmed live (Okta Event Log) that the real "Connect to another AI Agent" delegation link expects
    // resource == audience == the custom AS's own issuer URL, NOT the agent's own resource URL -- see a2a.ts.
    if (payload.resource && payload.resource !== HR_ISSUER) {
      return send(400, { error: 'invalid_target', error_description: `resource "${payload.resource}" does not match this authorization server's issuer` });
    }
    const scope = String(payload.scope ?? '');
    // Real Okta access tokens carry scopes as an ARRAY under "scp" (confirmed from the OBO token decoded
    // earlier in this project), not a space-separated string under "scope" -- auth.ts reads "scp".
    const at = await new SignJWT({ scp: scope.split(/\s+/).filter(Boolean), client_id: 'agent' })
      .setProtectedHeader({ alg: 'RS256', typ: 'at+jwt', kid: 'okta-test' })
      .setIssuer(HR_ISSUER).setAudience(HR_URL).setSubject(payload.sub as string)
      .setJti(crypto.randomUUID()).setIssuedAt().setExpirationTime('10m').sign(privateKey);
    return send(200, { access_token: at, token_type: 'Bearer', expires_in: 600, scope });
  }
  send(404, {});
});
await new Promise<void>((r) => oktaServer.listen(P.okta, r));

async function idTokenFor(sub: string) {
  return new SignJWT({}).setProtectedHeader({ alg: 'RS256', kid: 'okta-test' }).setIssuer(OKTA).setSubject(sub).setAudience('agent').setIssuedAt().setExpirationTime('1h').sign(privateKey);
}

// ---------- mock Groq (the OUTER agent's own LLM) and a trivial mock portal MCP server (zero tools) ----------
let queuedToolCall: { name: string; args: Record<string, unknown> } | undefined;
let offeredTools: string[] = [];
const groqServer = http.createServer(async (req, res) => {
  const body = JSON.parse(await new Promise<string>((r) => { let d = ''; req.on('data', (c) => (d += c)); req.on('end', () => r(d)); }));
  offeredTools = (body.tools ?? []).map((t: { function: { name: string } }) => t.function.name);
  const send = (json: unknown) => { res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(json)); };
  const last = body.messages.at(-1);
  if (last.role === 'tool' || !queuedToolCall) return send({ choices: [{ finish_reason: 'stop', message: { role: 'assistant', content: last.role === 'tool' ? `HR said: ${String(last.content).slice(0, 300)}` : 'Hello' } }] });
  const call = queuedToolCall;
  queuedToolCall = undefined;
  send({ choices: [{ finish_reason: 'tool_calls', message: { role: 'assistant', content: null, tool_calls: [{ id: 'c1', type: 'function', function: { name: call.name, arguments: JSON.stringify(call.args) } }] } }] });
});
await new Promise<void>((r) => groqServer.listen(P.groq, r));

// A placeholder portal: runAgent() always connects to one, even for this HR-focused test, and listTools()
// needs at least one registered tool for the MCP SDK to answer tools/list at all.
const mcpHttp = http.createServer(async (req, res) => {
  const server = new McpServer({ name: 'mock-portal', version: '1.0.0' });
  server.registerTool('noop', { description: 'Does nothing; this test does not exercise portal tools.', inputSchema: {} }, async () => ({ content: [{ type: 'text' as const, text: '{}' }] }));
  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
  res.on('close', () => { transport.close(); server.close(); });
  await server.connect(transport);
  const chunks: Buffer[] = [];
  for await (const c of req) chunks.push(c as Buffer);
  await transport.handleRequest(req, res, JSON.parse(Buffer.concat(chunks).toString() || '{}'));
});
await new Promise<void>((r) => mcpHttp.listen(P.mcp, r));

// ---------- real agent-hr process --------------------------------------------------------------
const hrEnv = {
  ...process.env,
  AGENT_HR_PORT: String(P.hr), AGENT_HR_BASE_URL: HR_URL,
  HR_AGENT_URL: HR_URL, HR_AGENT_AUTH_ISSUER: HR_ISSUER, HR_AGENT_SCOPES: 'hr:read hr:write',
  // Also clears AWS_BEARER_TOKEN_BEDROCK: agent-hr's own config.ts maps it to BEDROCK_API_KEY (matching
  // packages/agent), so leaving it set would leak the real .env's live credential into this "no credentials"
  // scenario, exactly as it did the first time this test caught the missing mapping.
  ...(live ? {} : { ANTHROPIC_API_KEY: '', BEDROCK_API_KEY: '', ANTHROPIC_AUTH_TOKEN: '', ANTHROPIC_BASE_URL: '', AWS_BEARER_TOKEN_BEDROCK: '' }),
};
const procs: ChildProcess[] = [];
const hrProc = spawn(process.execPath, ['--import', 'tsx', path.join(root, 'packages/agent-hr/src/index.ts')], { env: hrEnv, stdio: ['ignore', 'ignore', 'pipe'] });
hrProc.stderr!.on('data', (d) => process.stderr.write(`[agent-hr] ${d}`));
procs.push(hrProc);

async function waitFor(url: string) {
  for (let i = 0; i < 80; i++) { try { if ((await fetch(url)).ok) return; } catch { /* retry */ } await new Promise((r) => setTimeout(r, 250)); }
  throw new Error(`timeout waiting for ${url}`);
}
await waitFor(`${HR_URL}/healthz`);

// agent-side code under test (config reads env at import time)
Object.assign(process.env, {
  OKTA_ISSUER: OKTA, AGENT_CLIENT_ID: 'agent', AGENT_AUTH_METHOD: 'client_secret', AGENT_CLIENT_SECRET: 'x',
  HR_AGENT_URL: HR_URL, HR_AGENT_AUTH_ISSUER: HR_ISSUER, HR_AGENT_SCOPES: 'hr:read hr:write',
  LLM_PROVIDER: 'groq', GROQ_API_KEY: 'test-key', GROQ_BASE_URL: `http://localhost:${P.groq}`, GROQ_MODEL: 'mock-model',
  RETAIL_MCP_URL: MCP, RETAIL_AUTH_ISSUER: 'http://localhost:1', RETAIL_RESOURCE: 'http://localhost:1',
});
const { performA2aExchange, callAgentOverA2a, hrAgentConfigured, HrAccessError } = await import('../packages/agent/src/a2a.ts');
const { runAgent } = await import('../packages/agent/src/agent.ts');

// ---------- tiny test harness -----------------------------------------------------------------
let failed = 0;
const check = (name: string, cond: boolean, extra?: unknown) => {
  console.log(`${cond ? '  ✔' : '  ✘'} ${name}${cond ? '' : ` -> ${JSON.stringify(extra)}`}`);
  if (!cond) failed++;
};

try {
  console.log(`\n0. Config (live LLM: ${live ? 'yes, using .env' : 'no, expect graceful LLM errors from agent-hr'})`);
  check('hrAgentConfigured() is true once HR_AGENT_URL/HR_AGENT_AUTH_ISSUER are set', hrAgentConfigured());

  console.log('\n1. Happy path: full exchange, then a real A2A call');
  policy = { granted: 'hr:read hr:write' };
  const refreshToken = 'rt-' + crypto.randomUUID();
  refreshStore.set(refreshToken, { sub: '00ualice' });
  const trace: any[] = [];
  const access = await performA2aExchange({ idToken: await idTokenFor('00ualice'), refreshToken }, trace);
  check('two trace steps, both ok', trace.length === 2 && trace.every((s) => s.status === 'ok'), trace.map((s) => s.status));
  check('access token has both scopes', [...access.scope].sort().join(' ') === 'hr:read hr:write', access.scope);
  const reply1 = await callAgentOverA2a(HR_URL, 'What is Priya Natarajan\'s PTO balance?', () => access.accessToken);
  check('got a real reply from agent-hr over A2A', typeof reply1 === 'string' && reply1.length > 0, reply1);
  if (live) check('live reply mentions Priya\'s PTO figure (14)', /14/.test(reply1), reply1);
  else check('without a live LLM key, agent-hr reports that gracefully (not a crash)', /ANTHROPIC_API_KEY/.test(reply1), reply1);

  console.log('\n2. Central governance: Okta narrows the scope to hr:read only');
  policy = { granted: 'hr:read' };
  const rt2 = 'rt-' + crypto.randomUUID();
  refreshStore.set(rt2, { sub: '00ualice' });
  const trace2: any[] = [];
  const access2 = await performA2aExchange({ idToken: await idTokenFor('00ualice'), refreshToken: rt2 }, trace2);
  check('token only has hr:read', access2.scope.join(' ') === 'hr:read', access2.scope);
  if (live) {
    const reply2 = await callAgentOverA2a(HR_URL, 'Approve 2 PTO days for Marcus Webb', () => access2.accessToken);
    check('live: an hr:read-only token cannot approve PTO (model explains insufficient_scope)', /scope|not authorized|unauthorized/i.test(reply2), reply2);
  }
  policy = { granted: 'hr:read hr:write' };

  console.log('\n3. Okta rejects a scope the connection does not allow, agent retries with only the allowed ones');
  strictScopes = true;
  policy = { granted: 'hr:read' };
  const rt3 = 'rt-' + crypto.randomUUID();
  refreshStore.set(rt3, { sub: '00ualice' });
  const trace3: any[] = [];
  try {
    await performA2aExchange({ idToken: await idTokenFor('00ualice'), refreshToken: rt3 }, trace3);
    check('step 2 then runs with the narrowed scope', true);
  } catch (e) {
    check('exchange did not throw on a narrowable scope set', false, String(e));
  }
  strictScopes = false;
  policy = { granted: 'hr:read hr:write' };

  console.log('\n4. Attacks on the HR Agent\'s own authorization server');
  const rt4 = 'rt-' + crypto.randomUUID();
  refreshStore.set(rt4, { sub: '00ualice' });
  const t4: any[] = [];
  const a4 = await performA2aExchange({ idToken: await idTokenFor('00ualice'), refreshToken: rt4 }, t4);
  check('first redemption of the ID-JAG at the HR AS succeeded', typeof a4.accessToken === 'string');
  // Replay the SAME ID-JAG: redo step 1 only is not possible here (performA2aExchange does both steps), so
  // call the HR AS token endpoint directly with a captured assertion to prove single-use is enforced.
  const rt4b = 'rt-' + crypto.randomUUID();
  refreshStore.set(rt4b, { sub: '00ureplay' });
  const orgRes = await fetch(ORG_TOKEN_EP, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange', requested_token_type: 'urn:ietf:params:oauth:token-type:id-jag', subject_token: rt4b, subject_token_type: 'urn:ietf:params:oauth:token-type:refresh_token', audience: HR_ISSUER, resource: HR_ISSUER, scope: 'hr:read' }) });
  const idJag4 = ((await orgRes.json()) as { access_token: string }).access_token;
  const redeem = (assertion: string) => fetch(`${HR_ISSUER}/v1/token`, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer', assertion }) });
  check('first redemption of a captured ID-JAG succeeds', (await redeem(idJag4)).status === 200);
  check('replayed ID-JAG rejected (single-use)', (await redeem(idJag4)).status === 400);
  const wrongAudJag = await new SignJWT({ scope: 'hr:read', resource: HR_URL }).setProtectedHeader({ alg: 'RS256', typ: 'oauth-id-jag+jwt', kid: 'okta-test' }).setIssuer(OKTA).setSubject('00ux').setAudience('http://evil.example').setJti(crypto.randomUUID()).setIssuedAt().setExpirationTime('5m').sign(privateKey);
  check('ID-JAG with the wrong audience is rejected', (await redeem(wrongAudJag)).status === 400);
  const wrongResourceJag = await new SignJWT({ scope: 'hr:read', resource: 'http://not-the-hr-agent.example' }).setProtectedHeader({ alg: 'RS256', typ: 'oauth-id-jag+jwt', kid: 'okta-test' }).setIssuer(OKTA).setSubject('00ux').setAudience(HR_ISSUER).setJti(crypto.randomUUID()).setIssuedAt().setExpirationTime('5m').sign(privateKey);
  check('ID-JAG whose resource does not match this agent is rejected', (await redeem(wrongResourceJag)).status === 400);

  console.log('\n5. The HR Agent itself rejects bad bearer tokens (not just the AS that minted them)');
  const meHealthy = await fetch(`${HR_URL}/healthz`);
  check('healthz answers with the self-check header', meHealthy.headers.get('x-agent-hr') === '1');
  const agentCardRes = await fetch(`${HR_URL}/.well-known/agent-card.json`);
  const card = (await agentCardRes.json()) as { name?: string; supportedInterfaces?: { url?: string }[] };
  check('Agent Card is served and names this agent', agentCardRes.ok && card.name === 'HPE HR Agent', card);
  check("Agent Card's interface URL matches HR_AGENT_URL", card.supportedInterfaces?.[0]?.url === HR_URL, card.supportedInterfaces);
  // Use the REAL client (callAgentOverA2a) rather than a hand-rolled JSON-RPC body, so these checks exercise the
  // same wire path everything else in this test already does, instead of guessing at the exact request shape.
  const noAuthReply = await callAgentOverA2a(HR_URL, 'hi', () => '');
  check('an empty bearer token is treated as unauthenticated, not a crash', /unauthoriz/i.test(noAuthReply), noAuthReply);
  const expired = await new SignJWT({ scope: 'hr:read hr:write' }).setProtectedHeader({ alg: 'RS256', typ: 'at+jwt', kid: 'okta-test' }).setIssuer(HR_ISSUER).setAudience(HR_URL).setSubject('x').setIssuedAt().setExpirationTime('-10s').sign(privateKey);
  const expiredReply = await callAgentOverA2a(HR_URL, 'hi', () => expired);
  check('an expired access token is treated as unauthenticated, not a crash', /unauthoriz/i.test(expiredReply), expiredReply);
  const wrongAudAt = await new SignJWT({ scope: 'hr:read hr:write' }).setProtectedHeader({ alg: 'RS256', typ: 'at+jwt', kid: 'okta-test' }).setIssuer(HR_ISSUER).setAudience('http://not-the-hr-agent.example').setSubject('x').setIssuedAt().setExpirationTime('5m').sign(privateKey);
  const wrongAudReply = await callAgentOverA2a(HR_URL, 'hi', () => wrongAudAt);
  check('an access token minted for a DIFFERENT audience is rejected', /unauthoriz/i.test(wrongAudReply), wrongAudReply);

  console.log('\n6. Full chat loop: the model decides to call ask_hr_agent (mock outer LLM, real HR Agent)');
  queuedToolCall = { name: 'ask_hr_agent', args: { task: "What is Priya Natarajan's title?" } };
  const rt6 = 'rt-' + crypto.randomUUID();
  refreshStore.set(rt6, { sub: '00ubob' });
  const tokens6 = { idToken: await idTokenFor('00ubob'), refreshToken: rt6 };
  const hrTrace: any[] = [];
  const askHrAgent = async (task: string) => {
    const a = await performA2aExchange(tokens6, hrTrace);
    const text = await callAgentOverA2a(HR_URL, task, () => a.accessToken);
    return { text, isError: live ? false : /ANTHROPIC_API_KEY/.test(text) }; // without a live LLM, agent-hr's own reply IS an error
  };
  const out = await runAgent({ accessToken: 'dummy-portal-token', userLabel: 'bob@corp.test', history: [], message: "What is Priya's title?", mcpUrl: MCP, askHrAgent });
  check('model was offered the ask_hr_agent tool', offeredTools.includes('ask_hr_agent'), offeredTools);
  check('exactly one tool call, to ask_hr_agent', out.toolCalls.length === 1 && out.toolCalls[0].name === 'ask_hr_agent', out.toolCalls);
  check('final reply echoes what the HR Agent said', out.reply.startsWith('HR said:'), out.reply);
  if (live) check("live: reply mentions Priya's real title", /Field Service Engineer/i.test(out.reply), out.reply);

  console.log('\n7. Without an askHrAgent function, the tool is simply not offered (this is how index.ts degrades when HR_AGENT_URL is unset)');
  offeredTools = [];
  await runAgent({ accessToken: 'dummy-portal-token', userLabel: 'bob@corp.test', history: [], message: 'hello', mcpUrl: MCP });
  check('ask_hr_agent is absent from the tool list when askHrAgent is not passed', !offeredTools.includes('ask_hr_agent'), offeredTools);
} catch (e) {
  console.error('\nTEST CRASHED:', e);
  failed++;
} finally {
  procs.forEach((p) => p.kill());
  oktaServer.close();
  groqServer.close();
  mcpHttp.close();
}
console.log(failed ? `\n${failed} check(s) FAILED` : '\nAll checks passed');
process.exit(failed ? 1 : 0);
