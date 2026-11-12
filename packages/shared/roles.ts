// Role -> scope policy, shared by:
//   * the retail authorization server, which issues each user a token with only the scopes their role allows, and
//   * the portal, which enforces the same cap again on every call (defence in depth).
// Users are mapped to roles with PORTAL_USER_ROLES="a@corp.com=viewer,00u1abc...=manager"; anyone else gets
// PORTAL_DEFAULT_ROLE (default: support). Read lazily so each service's .env is loaded first.

export const SCOPE_NAMES = [
  'products:read',
  'inventory:read',
  'orders:read',
  'customers:read',
  'orders:write',
  'returns:read',
  'returns:write',
] as const;
export type Scope = (typeof SCOPE_NAMES)[number];

export type Role = 'viewer' | 'support' | 'manager';
export const ROLES: readonly Role[] = ['viewer', 'support', 'manager'];

export const ROLE_SCOPES: Record<Role, readonly Scope[]> = {
  // read-only: look things up, change nothing
  viewer: ['products:read', 'inventory:read', 'orders:read'],
  support: SCOPE_NAMES,
  // same scopes as support; the difference is business rules (no credit limit on RMAs)
  manager: SCOPE_NAMES,
};

let overrides: Map<string, Role> | undefined;
function loadOverrides(): Map<string, Role> {
  if (!overrides) {
    overrides = new Map();
    for (const pair of (process.env.PORTAL_USER_ROLES ?? '').split(',')) {
      const [key, role] = pair.split('=').map((s) => s?.trim());
      if (key && (ROLES as readonly string[]).includes(role)) overrides.set(key.toLowerCase(), role as Role);
    }
  }
  return overrides;
}

export function defaultRole(): Role {
  const r = process.env.PORTAL_DEFAULT_ROLE?.trim();
  return r === 'viewer' || r === 'manager' ? r : 'support';
}

export const isRole = (x: unknown): x is Role => typeof x === 'string' && (ROLES as readonly string[]).includes(x);

/** Role for a user: an entry in PORTAL_USER_ROLES (matched on email first, then on the Okta `sub`), else the default. */
export function roleFor(sub: string, email?: string): Role {
  const map = loadOverrides();
  return (email && map.get(email.toLowerCase())) || map.get(sub.toLowerCase()) || defaultRole();
}
