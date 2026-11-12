// Preflight: verifies .env, the agent's private key, and that Okta accepts the agent's client authentication.
import crypto from 'node:crypto';
import dotenv from 'dotenv';
import fs from 'node:fs';
import path from 'node:path';
import { SignJWT } from 'jose';

const root = path.resolve(import.meta.dirname, '..');
dotenv.config({ path: path.join(root, '.env'), quiet: true });
// `npm run check:env -- --profile limited` checks the second agent (.env.limited overrides .env)
const pi = process.argv.indexOf('--profile');
const profileName = pi >= 0 ? process.argv[pi + 1] : undefined;
if (profileName) {
  if (!/^[A-Za-z0-9_-]+$/.test(profileName)) throw new Error('invalid profile name');
  const pf = path.join(root, `.env.${profileName}`);
  if (!fs.existsSync(pf)) {
    console.error(`Missing ${pf} (copy .env.${profileName}.example)`);
    process.exit(1);
  }
  dotenv.config({ path: pf, override: true, quiet: true });
  console.log(`Using profile "${profileName}" (.env.${profileName} overrides .env)`);
}
const e = process.env;
let bad = 0;
const ok = (m: string) => console.log(`  ✔ ${m}`);
const fail = (m: string) => { bad++; console.log(`  ✘ ${m}`); };
const warn = (m: string) => console.log(`  ! ${m}`);
const set = (k: string) => Boolean(e[k]?.trim());

const method = e.AGENT_AUTH_METHOD?.trim() || 'private_key_jwt';
console.log(`Checking .env (agent auth: ${method})`);
for (const k of ['OKTA_ISSUER', 'AGENT_CLIENT_ID']) (set(k) ? ok : fail)(`${k} ${set(k) ? 'set' : 'missing'}`);
if (method === 'client_secret') (set('AGENT_CLIENT_SECRET') ? ok : fail)(`AGENT_CLIENT_SECRET ${set('AGENT_CLIENT_SECRET') ? 'set' : 'missing'}`);
else if (method !== 'private_key_jwt') fail('AGENT_AUTH_METHOD must be private_key_jwt or client_secret');
if (!e.SESSION_SECRET || e.SESSION_SECRET.startsWith('change-me')) warn('SESSION_SECRET is the default; change it for anything beyond a local demo');
if (!e.RETAIL_AGENT_CLIENT_SECRET || e.RETAIL_AGENT_CLIENT_SECRET.startsWith('change-me')) warn('RETAIL_AGENT_CLIENT_SECRET is the default; change it for anything beyond a local demo');

// ---- private key ----
let jwk: (JsonWebKey & { kid?: string }) | undefined;
if (method === 'private_key_jwt') {
  const file = path.resolve(root, e.AGENT_PRIVATE_KEY_FILE?.trim() || '.keys/agent-private.jwk.json');
  if (!fs.existsSync(file)) fail(`private key not found at ${file}. Run "npm run gen:key"`);
  else {
    try {
      jwk = JSON.parse(fs.readFileSync(file, 'utf8'));
      if (e.AGENT_KEY_ID?.trim()) jwk!.kid = e.AGENT_KEY_ID.trim();
      if (!jwk?.d || !jwk.kid) fail('key file is not a private JWK with a "kid"');
      else ok(`private key loaded; signing with kid ${jwk.kid}${e.AGENT_KEY_ID?.trim() ? ' (from AGENT_KEY_ID)' : ''}. This must equal the Key ID shown in Okta`);
    } catch (err) { fail(`cannot read key file: ${(err as Error).message}`); }
  }
}

// ---- Okta reachability + client authentication ----
if (set('OKTA_ISSUER')) {
  const issuer = e.OKTA_ISSUER!.trim().replace(/\/+$/, '');
  let tokenEndpoint: string | undefined;
  try {
    const r = await fetch(`${issuer}/.well-known/openid-configuration`);
    const meta = (await r.json()) as { issuer?: string; token_endpoint?: string };
    if (meta.issuer?.replace(/\/+$/, '') !== issuer) fail(`discovery issuer "${meta.issuer}" differs from OKTA_ISSUER`);
    else { ok(`Okta discovery OK (token endpoint ${meta.token_endpoint})`); tokenEndpoint = meta.token_endpoint; }
  } catch (err) {
    fail(`could not read Okta discovery document: ${(err as Error).message}`);
  }

  // Send a deliberately bogus refresh token with the real client authentication. Okta authenticates the
  // client first: invalid_client = bad key/secret/client id; invalid_grant = client auth was accepted.
  if (tokenEndpoint && set('AGENT_CLIENT_ID') && (method === 'client_secret' ? set('AGENT_CLIENT_SECRET') : jwk?.d)) {
    try {
      const form = new URLSearchParams({ grant_type: 'refresh_token', refresh_token: 'preflight-invalid-token', client_id: e.AGENT_CLIENT_ID!.trim() });
      if (method === 'client_secret') form.set('client_secret', e.AGENT_CLIENT_SECRET!.trim());
      else {
        const key = await crypto.webcrypto.subtle.importKey('jwk', jwk as crypto.webcrypto.JsonWebKey, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, true, ['sign']);
        const assertion = await new SignJWT({}).setProtectedHeader({ alg: 'RS256', kid: jwk!.kid })
          .setIssuer(e.AGENT_CLIENT_ID!.trim()).setSubject(e.AGENT_CLIENT_ID!.trim()).setAudience(tokenEndpoint)
          .setJti(crypto.randomUUID()).setIssuedAt().setExpirationTime('60s').sign(key);
        form.set('client_assertion_type', 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer');
        form.set('client_assertion', assertion);
      }
      const r = await fetch(tokenEndpoint, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' }, body: form });
      const j = (await r.json().catch(() => ({}))) as { error?: string; error_description?: string };
      if (j.error === 'invalid_grant') ok('Okta accepted the agent\'s client authentication (it only rejected the dummy refresh token, as expected)');
      else if (j.error === 'invalid_client') fail(`Okta rejected the client authentication: ${j.error_description ?? ''} Check AGENT_CLIENT_ID, and that the public key is registered AND active on the agent (Client registration → Activate/Enable).`);
      else if (j.error === 'unauthorized_client') warn(`Client auth OK, but Okta says the app can't use the refresh_token grant: ${j.error_description ?? ''} Enable "Refresh Token" on the linked app.`);
      else warn(`Unexpected response from Okta: ${r.status} ${JSON.stringify(j)}`);
    } catch (err) {
      fail(`client authentication check failed: ${(err as Error).message}`);
    }
  }
}
// ---- LLM credentials ----
const provider = (() => {
  const p = (e.LLM_PROVIDER ?? '').trim().toLowerCase();
  if (p === 'groq' || p === 'anthropic') return p;
  const anth = Boolean(e.ANTHROPIC_API_KEY?.trim() || e.BEDROCK_API_KEY?.trim());
  return !anth && e.GROQ_API_KEY?.trim() ? 'groq' : 'anthropic';
})();
console.log(`  (LLM provider: ${provider})`);
if (provider === 'groq') {
  const groqKey = e.GROQ_API_KEY?.trim();
  const groqBase = (e.GROQ_BASE_URL?.trim() || 'https://api.groq.com/openai/v1').replace(/\/+$/, '');
  const groqModel = e.GROQ_MODEL?.trim() || 'openai/gpt-oss-120b';
  if (!groqKey) fail('GROQ_API_KEY missing');
  else {
    try {
      const r = await fetch(`${groqBase}/models`, { headers: { Authorization: `Bearer ${groqKey}` }, signal: AbortSignal.timeout(20_000) });
      const j = (await r.json().catch(() => ({}))) as { data?: { id: string }[]; error?: { message?: string } };
      if (r.status === 401) fail('Groq rejected GROQ_API_KEY (401 Invalid API Key). Make sure .env holds exactly one key (gsk_ + 52 characters = 56)');
      else if (!r.ok) fail(`Groq check failed: HTTP ${r.status} ${j.error?.message ?? ''}`);
      else if (!j.data?.some((m) => m.id === groqModel)) fail(`Groq key works but model "${groqModel}" isn't in its model list (${(j.data ?? []).length} models); set GROQ_MODEL`);
      else ok(`Groq key accepted; model "${groqModel}" is available`);
    } catch (err) {
      fail(`Groq check failed: ${(err as Error).message}`);
    }
  }
} else {
// Anthropic API (default) or an Anthropic-compatible endpoint such as Amazon Bedrock Mantle (ANTHROPIC_BASE_URL).
const baseUrl = e.ANTHROPIC_BASE_URL?.trim();
const llmKey = e.ANTHROPIC_API_KEY?.trim() || e.BEDROCK_API_KEY?.trim();
const llmModel = e.AGENT_MODEL_ID?.trim() || e.ANTHROPIC_MODEL?.trim() || 'claude-opus-5-5';
if (!llmKey) {
  // already reported above when ANTHROPIC_API_KEY is missing
} else if (!baseUrl && llmKey.startsWith('bedrock-')) {
  fail('ANTHROPIC_API_KEY holds an Amazon Bedrock key (starts with "bedrock-") but ANTHROPIC_BASE_URL is not set, so it is being sent to api.anthropic.com, which rejects it. Set ANTHROPIC_BASE_URL to your Bedrock Mantle endpoint, or use an sk-ant- key');
} else {
  try {
    const { default: Anthropic } = await import('@anthropic-ai/sdk');
    const client = new Anthropic({ apiKey: llmKey, maxRetries: 0 });
    if (baseUrl) {
      // One tiny request; the Models API isn't assumed to exist on third-party endpoints.
      const r = await client.messages.create({ model: llmModel, max_tokens: 16, messages: [{ role: 'user', content: 'Reply with the single word OK.' }] });
      ok(`LLM endpoint ${baseUrl} accepted the key; model "${llmModel}" replied (stop_reason ${r.stop_reason})`);
    } else {
      const m = await client.models.retrieve(llmModel);
      ok(`Anthropic key accepted; model "${m.id}" is available to it`);
    }
  } catch (err) {
    const status = (err as { status?: number }).status;
    const msg = ((err as Error).message ?? '').replace(/\s+/g, ' ');
    if (/signature expired/i.test(msg)) fail('The Bedrock API key has EXPIRED (short-term keys last hours). Generate a new key and update ANTHROPIC_API_KEY / BEDROCK_API_KEY');
    else if (status === 401 || status === 403) fail(`The LLM endpoint rejected the key (${status}): ${msg.slice(0, 200)}`);
    else if (status === 404) fail(`Key works but model "${llmModel}" isn't available there (404). Check AGENT_MODEL_ID / ANTHROPIC_MODEL and that your account has access in this region`);
    else fail(`LLM check failed: ${msg.slice(0, 250)}`);
  }
}
}
process.exit(bad ? 1 : 0);
