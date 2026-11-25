// Verifies the Bearer token on every A2A call: an access token issued by this agent's own Okta custom
// authorization server (Cross App Access, agent-to-agent -- see docs/A2A_AGENT_TO_AGENT.md). No session, no
// sign-in page: this agent only ever receives a Bearer token per call, exactly like a resource server (compare
// packages/retail-portal's requireBearer). Authentication is NOT enforced by the SDK itself -- the executor
// checks `isAuthenticated` before running anything (see executor.ts), which is the pattern the SDK's own
// authentication sample uses.
import { createRemoteJWKSet, decodeJwt, jwtVerify } from 'jose';
import type { Request } from 'express';
import { UnauthenticatedUser, type User } from '@a2a-js/sdk/server';
import { UserBuilder } from '@a2a-js/sdk/server/express';
import { cfg } from './config.js';

export class VerifiedCaller implements User {
  isAuthenticated = true;
  constructor(public userName: string, public scopes: string[], public claims: Record<string, unknown>) {}
  hasScope(scope: string): boolean {
    return this.scopes.includes(scope);
  }
}

let jwks: ReturnType<typeof createRemoteJWKSet> | undefined;
// Okta custom authorization servers serve their JWKS at /v1/keys (the same convention the OBO flow already
// relies on directly in packages/retail-portal/src/index.ts -- no discovery needed).
const getJwks = () => (jwks ??= createRemoteJWKSet(new URL(`${cfg.authIssuer}/v1/keys`)));

// Confirmed live: the Okta custom authorization server mints this token with `aud` reflecting the `resource`
// value the CALLER requested at the org-AS exchange step (RFC 8707) -- which packages/agent/src/a2a.ts sets to
// the authorization server's own issuer URL, not necessarily this authorization server's separately-configured
// "Default Audience". Accept either value: both uniquely identify this one authorization server, which is
// dedicated to this one agent, so there is no confused-deputy risk in accepting both.
const VALID_AUDIENCES = [cfg.resource, cfg.authIssuer].filter(Boolean);

export const userBuilder: UserBuilder = async (req: Request): Promise<User> => {
  if (!cfg.authIssuer) {
    console.warn('[agent-hr] HR_AGENT_AUTH_ISSUER is not set: every caller is treated as unauthenticated.');
    return new UnauthenticatedUser();
  }
  const m = /^Bearer (.+)$/i.exec(req.headers.authorization ?? '');
  if (!m) return new UnauthenticatedUser();
  try {
    const { payload } = await jwtVerify(m[1], getJwks(), { issuer: cfg.authIssuer, audience: VALID_AUDIENCES, algorithms: ['RS256'] });
    const scopes = Array.isArray(payload.scp) ? payload.scp.map(String) : typeof payload.scp === 'string' ? payload.scp.split(/\s+/).filter(Boolean) : [];
    if (cfg.logClaims) console.log(`[agent-hr] verified caller claims:\n${JSON.stringify(payload, null, 2)}`);
    const name = typeof payload.sub === 'string' ? payload.sub : 'unknown-caller';
    return new VerifiedCaller(name, scopes, payload as Record<string, unknown>);
  } catch (e) {
    // Decode (not verify -- the signature/claims may be exactly what's wrong) so a REJECTED token's claims are
    // still visible. This is precisely the moment full visibility matters most; the error message alone
    // ("unexpected aud claim value") doesn't say what the actual value was.
    const seen = (() => {
      try {
        return decodeJwt(m[1]);
      } catch {
        return undefined;
      }
    })();
    console.warn(`[agent-hr] rejected bearer token: ${(e as Error).message}`, seen ? `\n  claims seen: ${JSON.stringify(seen)}\n  expected audience (one of): ${VALID_AUDIENCES.join(', ')}` : '(token did not even decode as a JWT)');
    return new UnauthenticatedUser();
  }
};
