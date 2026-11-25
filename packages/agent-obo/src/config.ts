// Settings for the on-behalf-of (OBO) agent app. Everything lives in the shared .env at the repo root.
import { env, trimSlash } from '../../agent/src/env.js';

const port = Number(env('AGENT_OBO_PORT', '3200'));

export const oboCfg = {
  agentName: env('AGENT_OBO_NAME', 'Ops Agent (OBO)'),
  port,
  baseUrl: trimSlash(env('AGENT_OBO_BASE_URL', `http://localhost:${port}`)),
  sessionSecret: env('SESSION_SECRET', 'dev-only-change-me'),

  /**
   * The custom authorization server that performs the exchange and mints the PORTAL token, e.g.
   * https://<org>.okta.com/oauth2/<id>. The portal trusts this one. It must list the sign-in server under "Trusted servers".
   */
  issuer: trimSlash(env('OBO_ISSUER', '')),
  /** `aud` the exchanged token gets: that server's audience. The portal expects the same value. */
  audience: env('OBO_AUDIENCE', ''),
  /**
   * The custom authorization server where users sign in and get their own access token (the subject token).
   * Defaults to OBO_ISSUER (one server does both). Set it to use two servers.
   */
  loginIssuer: trimSlash(env('OBO_LOGIN_ISSUER', trimSlash(env('OBO_ISSUER', '')))),

  /** The Okta app the user signs in with (Native or Web app, Authorization Code + PKCE). The secret is empty for a public client. */
  login: { clientId: env('OBO_LOGIN_CLIENT_ID', ''), clientSecret: env('OBO_LOGIN_CLIENT_SECRET', '') },
  /** The Okta "API Services" app that performs the exchange (grant type Token Exchange). */
  service: { clientId: env('OBO_SERVICE_CLIENT_ID', ''), clientSecret: env('OBO_SERVICE_CLIENT_SECRET', '') },

  /** Scopes requested in the exchange; they must exist on the custom authorization server and be allowed by its policy. */
  scopes: env('OBO_SCOPES', 'products:read inventory:read orders:read customers:read orders:write returns:read returns:write')
    .split(/\s+/)
    .filter(Boolean),
  /** Ask for a refresh token at sign-in (the login app needs the Refresh Token grant) so the subject token can be renewed. */
  offlineAccess: env('OBO_OFFLINE_ACCESS', 'false') === 'true',
  /** Debug only. '' = off (default) | 'claims' = log the decoded OBO token claims | 'full' = also log the raw token (a live credential until it expires). */
  logToken: ((v) => (v === 'claims' || v === 'full' ? v : ''))(env('OBO_LOG_TOKEN', '').toLowerCase()),
};

/** Settings that must be present before the app can start, with what each one is. */
export function missingConfig(): string[] {
  const need: [string, string][] = [
    ['OBO_ISSUER', 'the custom authorization server URL'],
    ['OBO_AUDIENCE', 'that server\'s audience'],
    ['OBO_LOGIN_CLIENT_ID', 'the Okta app users sign in with'],
    ['OBO_SERVICE_CLIENT_ID', 'the Okta API Services app that does the exchange'],
    ['OBO_SERVICE_CLIENT_SECRET', 'that app\'s client secret'],
  ];
  return need.filter(([k]) => !process.env[k]?.trim()).map(([k, what]) => `${k}  (${what})`);
}
