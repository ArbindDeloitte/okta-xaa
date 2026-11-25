import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { env, trimSlash } from './env.js';

// AWS's own name for a Bedrock API key; treat it as BEDROCK_API_KEY so either spelling works.
if (!process.env.BEDROCK_API_KEY?.trim() && process.env.AWS_BEARER_TOKEN_BEDROCK?.trim()) {
  process.env.BEDROCK_API_KEY = process.env.AWS_BEARER_TOKEN_BEDROCK.trim();
}

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');

const port = Number(env('AGENT_PORT', '3000'));
const authMethod = env('AGENT_AUTH_METHOD', 'private_key_jwt');
if (authMethod !== 'client_secret' && authMethod !== 'private_key_jwt') {
  throw new Error('AGENT_AUTH_METHOD must be "client_secret" or "private_key_jwt"');
}

function loadPrivateJwk(): (JsonWebKey & { kid?: string }) | undefined {
  if (authMethod !== 'private_key_jwt') return undefined;
  const file = path.resolve(repoRoot, env('AGENT_PRIVATE_KEY_FILE', '.keys/agent-private.jwk.json'));
  if (!fs.existsSync(file)) {
    throw new Error(`AGENT_AUTH_METHOD=private_key_jwt but ${file} does not exist. Run "npm run gen:key".`);
  }
  const jwk = JSON.parse(fs.readFileSync(file, 'utf8')) as JsonWebKey & { kid?: string };
  // Okta may assign its own Key ID to a public key you register. The JWT header's kid must equal the
  // Key ID shown in Okta, so allow overriding it without editing the key file.
  const kidOverride = process.env.AGENT_KEY_ID?.trim();
  if (kidOverride) jwk.kid = kidOverride;
  return jwk;
}

// Which LLM backend the agent uses. LLM_PROVIDER=anthropic|groq, otherwise auto: Groq only when it is the only key present.
const llmProvider = ((): 'anthropic' | 'groq' => {
  const p = env('LLM_PROVIDER', '').toLowerCase();
  if (p === 'groq' || p === 'anthropic') return p;
  if (p) throw new Error('LLM_PROVIDER must be "anthropic" or "groq"');
  const hasAnthropic = Boolean(process.env.ANTHROPIC_API_KEY?.trim() || process.env.BEDROCK_API_KEY?.trim() || process.env.ANTHROPIC_AUTH_TOKEN?.trim());
  return !hasAnthropic && process.env.GROQ_API_KEY?.trim() ? 'groq' : 'anthropic';
})();

export const cfg = {
  // Shown in the UI after the "HPE" mark, e.g. "Ops Agent" or "Ops Agent (Limited)".
  agentName: env('AGENT_NAME', 'Ops Agent'),
  port,
  baseUrl: trimSlash(env('AGENT_BASE_URL', `http://localhost:${port}`)),
  sessionSecret: env('SESSION_SECRET', 'dev-only-change-me'),

  okta: {
    issuer: trimSlash(env('OKTA_ISSUER')),
    clientId: env('AGENT_CLIENT_ID'),
    clientSecret: authMethod === 'client_secret' ? env('AGENT_CLIENT_SECRET') : undefined,
    authMethod: authMethod as 'client_secret' | 'private_key_jwt',
    privateJwk: loadPrivateJwk(),
    sendResource: env('XAA_SEND_RESOURCE', 'true') === 'true',
    // Okta's current docs exchange the user's REFRESH token (needs the offline_access scope and the
    // Refresh Token grant on the app). "id_token" is the older flow used by the reference repo.
    subjectToken: ((): 'refresh_token' | 'id_token' => {
      const v = env('XAA_SUBJECT_TOKEN', 'refresh_token');
      if (v !== 'refresh_token' && v !== 'id_token') throw new Error('XAA_SUBJECT_TOKEN must be "refresh_token" or "id_token"');
      return v;
    })(),
  },

  retail: {
    authIssuer: trimSlash(env('RETAIL_AUTH_ISSUER', 'http://localhost:5001')),
    resource: trimSlash(env('RETAIL_RESOURCE', 'http://localhost:3001')),
    // If the resource identifier already has a path (e.g. https://host/mcp) it IS the MCP endpoint; a bare base URL gets "/mcp".
    mcpUrl: env('RETAIL_MCP_URL', ((r) => (new URL(r).pathname.replace(/\/+$/, '') ? r : `${r}/mcp`))(trimSlash(env('RETAIL_RESOURCE', 'http://localhost:3001')))),
    // The agent's client credentials *at the retail authorization server*. In Okta these are
    // configured on the XAA connection; the ID-JAG's client_id claim must match.
    clientId: env('RETAIL_AGENT_CLIENT_ID', 'agent-at-retail'),
    clientSecret: env('RETAIL_AGENT_CLIENT_SECRET', 'change-me-retail-secret'),
    scopes: env(
      'RETAIL_SCOPES',
      'products:read inventory:read orders:read customers:read orders:write returns:read returns:write',
    )
      .split(/\s+/)
      .filter(Boolean),
  },

  // Okta Agent Gateway test mode (optional): the gateway's MCP URL, e.g. https://<org>.gateway.oktapreview.com/mcp/servers/<name>.
  // The authorization server that issues gateway tokens is discovered from the gateway; override with GATEWAY_AUTH_ISSUER.
  gateway: {
    mcpUrl: env('GATEWAY_MCP_URL', ''),
    authIssuer: trimSlash(env('GATEWAY_AUTH_ISSUER', '')),
  },

  // Direct A2A (optional): a second agent (the HPE HR Agent) this agent can call over the real Agent2Agent
  // protocol, secured by the same Cross App Access mechanism as `retail` above -- see a2a.ts and
  // docs/A2A_AGENT_TO_AGENT.md. Empty HR_AGENT_URL / HR_AGENT_AUTH_ISSUER = the ask_hr_agent tool is not offered.
  hrAgent: {
    url: trimSlash(env('HR_AGENT_URL', '')),
    authIssuer: trimSlash(env('HR_AGENT_AUTH_ISSUER', '')),
    scopes: env('HR_AGENT_SCOPES', 'hr:read hr:write').split(/\s+/).filter(Boolean),
  },

  llm: {
    provider: llmProvider,
    // anthropic: AGENT_MODEL_ID wins (e.g. "anthropic.claude-haiku-4-5" on Bedrock), then ANTHROPIC_MODEL.
    // groq: GROQ_MODEL.
    model:
      llmProvider === 'groq'
        ? env('GROQ_MODEL', 'openai/gpt-oss-120b')
        : env('AGENT_MODEL_ID', env('ANTHROPIC_MODEL', 'claude-opus-5-5')),
    // Server-side refusal fallbacks are an Anthropic-API feature; not available behind ANTHROPIC_BASE_URL
    // (e.g. Amazon Bedrock Mantle).
    serverFallbacks: env('ANTHROPIC_BASE_URL', '') === '',
    groq: {
      apiKey: process.env.GROQ_API_KEY?.trim() || undefined,
      baseUrl: trimSlash(env('GROQ_BASE_URL', 'https://api.groq.com/openai/v1')),
    },
    maxToolRounds: Number(env('AGENT_MAX_TOOL_ROUNDS', '8')),
  },
};
