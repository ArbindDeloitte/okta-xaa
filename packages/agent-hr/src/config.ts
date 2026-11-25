// Settings for the HPE HR Agent: a small, independent agent reachable over the real A2A protocol (not MCP).
// It never talks to Okta itself -- it only verifies the Bearer tokens callers present, exactly like a resource
// server (compare packages/retail-portal). Everything lives in the shared .env at the repo root.
import { env, trimSlash } from './env.js';

// AWS's own name for a Bedrock API key; treat it as BEDROCK_API_KEY so either spelling works -- same mapping
// packages/agent/src/config.ts does. Without this, a .env that only sets AWS_BEARER_TOKEN_BEDROCK (as this
// project's own setup does) leaves this agent's own LLM call with no usable key, even though every other app
// reading the SAME .env finds one.
if (!process.env.BEDROCK_API_KEY?.trim() && process.env.AWS_BEARER_TOKEN_BEDROCK?.trim()) {
  process.env.BEDROCK_API_KEY = process.env.AWS_BEARER_TOKEN_BEDROCK.trim();
}

const port = Number(env('AGENT_HR_PORT', '3400'));

export const cfg = {
  agentName: env('AGENT_HR_NAME', 'HPE HR Agent'),
  port,
  baseUrl: trimSlash(env('AGENT_HR_BASE_URL', `http://localhost:${port}`)),

  /** This agent's own identity as an A2A resource: the Okta custom authorization server that mints its callers'
   * access tokens (an Okta-native custom AS, e.g. https://<org>.okta.com/oauth2/<id>; NOT the org issuer), and the
   * audience/resource URL every caller must request. Usually the same value as `baseUrl`, but kept separate in
   * case this agent is reached through a tunnel or a reverse proxy whose public URL differs from where it binds. */
  authIssuer: trimSlash(env('HR_AGENT_AUTH_ISSUER', '')),
  resource: trimSlash(env('HR_AGENT_URL', `http://localhost:${port}`)),
  scopes: env('HR_AGENT_SCOPES', 'hr:read hr:write').split(/\s+/).filter(Boolean),

  llm: {
    // Same env vars as every other app in this project (ANTHROPIC_API_KEY / ANTHROPIC_BASE_URL / AGENT_MODEL_ID),
    // so this agent runs against the same Bedrock/Anthropic endpoint with no extra configuration.
    model: env('AGENT_MODEL_ID', env('ANTHROPIC_MODEL', 'claude-opus-5-5')),
  },

  /** Debug only. '' = off (default) | 'claims' = log the verified caller's decoded token claims on every call. */
  logClaims: env('HR_AGENT_LOG_CLAIMS', '').toLowerCase() === 'claims',
};

export function missingConfig(): string[] {
  const need: [string, string][] = [
    ['HR_AGENT_AUTH_ISSUER', "the Okta custom authorization server that mints this agent's callers' tokens"],
  ];
  return need.filter(([k]) => !process.env[k]?.trim()).map(([k, what]) => `${k}  (${what})`);
}
