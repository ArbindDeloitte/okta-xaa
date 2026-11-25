// Live, in-memory record of what hits this server's token endpoint: which caller, which grant, and -- for the
// jwt-bearer (ID-JAG) grant -- the decoded assertion claims. Powers the /portal demo view (see index.ts).
// Same shape/idea as the Retail Portal's own audit log (packages/retail-portal/src/governance.ts).
export type ExchangeEntry = {
  id: number;
  ts: string;
  grantType: string;
  clientId?: string;
  /** Friendly label for who this looks like (see callerLabel in index.ts); falls back to the raw client_id. */
  caller: string;
  decision: 'allow' | 'deny';
  reason?: string;
  /** Decoded ID-JAG claims, jwt-bearer grant only. Never the raw token. */
  assertion?: Record<string, unknown>;
  issuedScope?: string;
  /** The raw minted access token (a live credential). Only ever set when AUTH_PORTAL_SHOW_TOKENS=true. */
  accessToken?: string;
  ms?: number;
};

const exchanges: ExchangeEntry[] = [];
let seq = 0;

export function recordExchange(e: Omit<ExchangeEntry, 'id' | 'ts'>): ExchangeEntry {
  const entry: ExchangeEntry = { id: ++seq, ts: new Date().toISOString(), ...e };
  exchanges.push(entry);
  if (exchanges.length > 200) exchanges.shift();
  const tag = entry.decision.toUpperCase().padEnd(5);
  console.log(`[exchange] ${tag} ${entry.caller}${entry.clientId ? ` (client_id ${entry.clientId})` : ''} grant=${entry.grantType}${entry.reason ? ` - ${entry.reason}` : ''}`);
  return entry;
}

export const getExchanges = (sinceId = 0) => exchanges.filter((e) => e.id > sinceId);
