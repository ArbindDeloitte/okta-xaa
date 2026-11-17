// Scopes, roles, user mapping and the audit log.
//
// Two layers of governance apply to every agent call:
//   1. Okta (central): which scopes this agent may ever get for this app (the XAA connection).
//   2. The user's role: the auth server issues each user a token with only their role's scopes, the portal
//      enforces the same cap again, and business rules (e.g. credit limits) apply on top.
// The agent only SEES the tools its signed-in user may use.
import { isRole, ROLE_SCOPES, roleFor, type Role } from '../../shared/roles.js';

export const SCOPES = {
  'products:read': 'Search the product catalog',
  'inventory:read': 'Read stock levels by location',
  'orders:read': 'Look up orders',
  'customers:read': 'Look up enterprise accounts, tier and spend',
  'orders:write': 'Modify orders (e.g. cancel)',
  'returns:read': 'Look up return requests',
  'returns:write': 'Create return requests / refunds',
} as const;
export type Scope = keyof typeof SCOPES;
export const ALL_SCOPES = Object.keys(SCOPES) as Scope[];

export { ROLE_SCOPES, type Role } from '../../shared/roles.js';
/** Refund amount above which a non-manager's return needs manager approval. */
export const SUPPORT_REFUND_LIMIT = 5000;

export type Principal = {
  sub: string;
  email?: string;
  clientId: string;
  /** The agent acting for the user, when the token carries an `act` claim (Okta on-behalf-of exchange). */
  actor?: string;
  jti?: string;
  role: Role;
  /** Scopes carried by the access token (what Okta granted through XAA). */
  tokenScopes: Scope[];
  /** tokenScopes ∩ role scopes (what the portal actually allows). */
  effectiveScopes: Scope[];
  label: string;
};

// ---- user -> role mapping (shared with the auth server; see packages/shared/roles.ts) ----------
export type KnownUser = { sub: string; email?: string; role: Role; firstSeen: string; lastSeen: string };
const knownUsers = new Map<string, KnownUser>();

/** `tokenRole` is the role the auth server put in the signed access token (from PORTAL_USER_ROLES or the default). */
export function resolveUser(sub: string, email?: string, tokenRole?: Role): KnownUser {
  const key = email?.toLowerCase() ?? sub;
  const role = tokenRole ?? roleFor(sub, email);
  const now = new Date().toISOString();
  const existing = knownUsers.get(key);
  if (existing) {
    existing.lastSeen = now;
    existing.role = role;
    return existing;
  }
  const created: KnownUser = { sub, email, role, firstSeen: now, lastSeen: now };
  knownUsers.set(key, created);
  return created;
}
export const listKnownUsers = () => [...knownUsers.values()];

export function parseScopes(raw: unknown): Scope[] {
  const list = Array.isArray(raw) ? raw.map(String) : typeof raw === 'string' ? raw.split(/\s+/) : [];
  return list.filter((s): s is Scope => s in SCOPES);
}

export function buildPrincipal(claims: {
  sub: string;
  email?: string;
  client_id: string;
  actor?: string;
  jti?: string;
  scope?: string;
  role?: unknown;
}): Principal {
  const user = resolveUser(claims.sub, claims.email, isRole(claims.role) ? claims.role : undefined);
  const tokenScopes = parseScopes(claims.scope);
  const roleScopes = new Set(ROLE_SCOPES[user.role]);
  return {
    sub: claims.sub,
    email: claims.email,
    clientId: claims.client_id,
    actor: claims.actor,
    jti: claims.jti,
    role: user.role,
    tokenScopes,
    effectiveScopes: tokenScopes.filter((s) => roleScopes.has(s)),
    label: claims.email ?? claims.sub,
  };
}

// ---- audit log ------------------------------------------------------------------------------
export type AuditEntry = {
  id: number;
  ts: string;
  via: 'mcp' | 'rest' | 'auth';
  user: string;
  role?: Role;
  clientId?: string;
  /** Agent acting on the user's behalf (`act` claim), present for on-behalf-of tokens. */
  actor?: string;
  tool: string;
  scope?: Scope;
  decision: 'allow' | 'deny' | 'error';
  reason?: string;
  args?: unknown;
  ms?: number;
};

const audit: AuditEntry[] = [];
let auditSeq = 0;
export function recordAudit(e: Omit<AuditEntry, 'id' | 'ts'>): AuditEntry {
  const entry: AuditEntry = { id: ++auditSeq, ts: new Date().toISOString(), ...e };
  audit.push(entry);
  if (audit.length > 500) audit.shift();
  const tag = entry.decision.toUpperCase().padEnd(5);
  console.log(`[audit] ${tag} ${entry.via} ${entry.user} ${entry.tool}${entry.reason ? ` - ${entry.reason}` : ''}`);
  return entry;
}
export const getAudit = (sinceId = 0) => audit.filter((a) => a.id > sinceId);
