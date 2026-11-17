// The order-portal tool registry: single source of truth used by both the MCP endpoint and the REST API.
import { z } from 'zod';
import {
  customers, inventory, locations, nextReturnId, orders, products, returns,
  type Order,
} from './data.js';
import { recordAudit, SUPPORT_REFUND_LIMIT, type Principal, type Scope } from './governance.js';

export class BusinessError extends Error {
  constructor(message: string, public code = 'business_rule') {
    super(message);
  }
}

export type ToolDef = {
  name: string;
  description: string;
  scope: Scope;
  input: z.ZodRawShape;
  run: (args: any, p: Principal) => unknown;
};

const money = (n: number) => Math.round(n * 100) / 100;
const findOrder = (id: string): Order => {
  const o = orders.find((x) => x.id.toLowerCase() === id.toLowerCase());
  if (!o) throw new BusinessError(`Order ${id} not found`, 'not_found');
  return o;
};
const enrichOrder = (o: Order) => ({
  ...o,
  customer: customers.find((c) => c.id === o.customerId)?.name,
  items: o.items.map((l) => ({ ...l, name: products.find((p) => p.sku === l.sku)?.name })),
});
const summarizeOrder = (o: Order) => ({
  id: o.id,
  status: o.status,
  customerId: o.customerId,
  customer: customers.find((c) => c.id === o.customerId)?.name,
  channel: o.channel,
  placedAt: o.placedAt,
  total: o.total,
  itemCount: o.items.reduce((s, l) => s + l.qty, 0),
});

export const tools: ToolDef[] = [
  {
    name: 'search_products',
    description: 'Search the product catalog by free-text query and/or category. Returns SKU, name, category and price.',
    scope: 'products:read',
    input: {
      query: z.string().optional().describe('Text to match against name/description/SKU'),
      category: z.string().optional().describe('servers | storage | networking | components'),
    },
    run: ({ query, category }) => {
      const q = query?.toLowerCase();
      return products.filter(
        (p) =>
          (!category || p.category === category.toLowerCase()) &&
          (!q || `${p.sku} ${p.name} ${p.description}`.toLowerCase().includes(q)),
      );
    },
  },
  {
    name: 'check_inventory',
    description: 'Get units on hand for a SKU across the distribution centres, optionally for one location.',
    scope: 'inventory:read',
    input: {
      sku: z.string().describe('Product SKU, e.g. HPE-1001'),
      location: z.string().optional().describe(`One of: ${locations.join(', ')}`),
    },
    run: ({ sku, location }) => {
      const stock = inventory[sku.toUpperCase()];
      if (!stock) throw new BusinessError(`Unknown SKU ${sku}`, 'not_found');
      const product = products.find((p) => p.sku === sku.toUpperCase());
      if (location) {
        const loc = location.toUpperCase();
        if (!(loc in stock)) throw new BusinessError(`Unknown location ${location}`, 'not_found');
        return { sku: product!.sku, name: product!.name, location: loc, onHand: stock[loc] };
      }
      return {
        sku: product!.sku,
        name: product!.name,
        byLocation: stock,
        total: Object.values(stock).reduce((a, b) => a + b, 0),
      };
    },
  },
  {
    name: 'list_orders',
    description: 'List recent orders, optionally filtered by status or customer. Newest first.',
    scope: 'orders:read',
    input: {
      status: z.enum(['processing', 'shipped', 'delivered', 'cancelled', 'returned']).optional(),
      customer_id: z.string().optional().describe('Account ID such as ACC-001'),
      limit: z.number().int().min(1).max(50).optional().describe('Max results (default 10)'),
    },
    run: ({ status, customer_id, limit }) =>
      orders
        .filter((o) => (!status || o.status === status) && (!customer_id || o.customerId.toLowerCase() === customer_id.toLowerCase()))
        .sort((a, b) => b.placedAt.localeCompare(a.placedAt))
        .slice(0, limit ?? 10)
        .map(summarizeOrder),
  },
  {
    name: 'get_order',
    description: 'Get full details of one order including line items, delivery date and notes.',
    scope: 'orders:read',
    input: { order_id: z.string().describe('Order ID such as SO-10001') },
    run: ({ order_id }) => enrichOrder(findOrder(order_id)),
  },
  {
    name: 'get_customer',
    description: 'Look up an enterprise account by account ID or contact email, including account tier, annual spend and its order IDs.',
    scope: 'customers:read',
    input: {
      customer_id: z.string().optional(),
      email: z.string().optional(),
    },
    run: ({ customer_id, email }) => {
      if (!customer_id && !email) throw new BusinessError('Provide customer_id or email', 'invalid_request');
      const c = customers.find(
        (x) => (customer_id && x.id.toLowerCase() === customer_id.toLowerCase()) || (email && x.email.toLowerCase() === email.toLowerCase()),
      );
      if (!c) throw new BusinessError('Customer not found', 'not_found');
      return { ...c, orderIds: orders.filter((o) => o.customerId === c.id).map((o) => o.id) };
    },
  },
  {
    name: 'cancel_order',
    description: 'Cancel an order. Only orders still in "processing" can be cancelled.',
    scope: 'orders:write',
    input: {
      order_id: z.string(),
      reason: z.string().describe('Why the order is being cancelled'),
    },
    run: ({ order_id, reason }, p) => {
      const o = findOrder(order_id);
      if (o.status !== 'processing') {
        throw new BusinessError(`Order ${o.id} is "${o.status}" and can no longer be cancelled`);
      }
      o.status = 'cancelled';
      o.notes.push(`Cancelled by ${p.label}: ${reason}`);
      return summarizeOrder(o);
    },
  },
  {
    name: 'create_return',
    description:
      'Create a return (RMA) for items on a delivered order within 30 days of delivery. ' +
      `Refunds above $${SUPPORT_REFUND_LIMIT} by non-managers are queued for manager approval.`,
    scope: 'returns:write',
    input: {
      order_id: z.string(),
      sku: z.string().describe('SKU being returned'),
      qty: z.number().int().min(1).describe('Units being returned'),
      reason: z.string(),
    },
    run: ({ order_id, sku, qty, reason }, p) => {
      const o = findOrder(order_id);
      if (o.status !== 'delivered' || !o.deliveredAt) {
        throw new BusinessError(`Order ${o.id} is "${o.status}"; only delivered orders can be returned`);
      }
      const ageDays = (Date.now() - new Date(o.deliveredAt).getTime()) / 86_400_000;
      if (ageDays > 30) {
        throw new BusinessError(`Return window closed: delivered ${Math.floor(ageDays)} days ago (limit 30)`);
      }
      const l = o.items.find((x) => x.sku === sku.toUpperCase());
      if (!l) throw new BusinessError(`${sku} is not on order ${o.id}`);
      const already = returns.filter((r) => r.orderId === o.id && r.sku === l.sku).reduce((s, r) => s + r.qty, 0);
      if (qty + already > l.qty) {
        throw new BusinessError(`Cannot return ${qty}: ordered ${l.qty}, already returned ${already}`);
      }
      const refundAmount = money(qty * l.unitPrice);
      const needsApproval = refundAmount > SUPPORT_REFUND_LIMIT && p.role !== 'manager';
      const rma = {
        id: nextReturnId(),
        orderId: o.id,
        sku: l.sku,
        qty,
        reason,
        refundAmount,
        status: needsApproval ? ('pending_manager_approval' as const) : ('approved' as const),
        createdAt: new Date().toISOString(),
        createdBy: p.label,
      };
      returns.push(rma);
      return rma;
    },
  },
  {
    name: 'list_returns',
    description: 'List return requests, optionally for a single order.',
    scope: 'returns:read',
    input: { order_id: z.string().optional() },
    run: ({ order_id }) => returns.filter((r) => !order_id || r.orderId.toLowerCase() === order_id.toLowerCase()),
  },
];

export type ToolResult =
  | { ok: true; data: unknown }
  | { ok: false; code: string; error: string };

/** Enforce portal-side scope check, run the tool, and write the audit record. */
export function invokeTool(def: ToolDef, rawArgs: unknown, p: Principal, via: 'mcp' | 'rest'): ToolResult {
  const t0 = Date.now();
  const base = { via, user: p.label, role: p.role, clientId: p.clientId, actor: p.actor, tool: def.name, scope: def.scope, args: rawArgs };

  if (!p.tokenScopes.includes(def.scope)) {
    recordAudit({ ...base, decision: 'deny', reason: `token lacks scope ${def.scope} (not granted by Okta)` });
    return { ok: false, code: 'insufficient_scope', error: `The access token does not include scope "${def.scope}".` };
  }
  if (!p.effectiveScopes.includes(def.scope)) {
    recordAudit({ ...base, decision: 'deny', reason: `role "${p.role}" is not permitted ${def.scope}` });
    return { ok: false, code: 'forbidden_for_role', error: `Your portal role "${p.role}" is not permitted to use "${def.name}".` };
  }
  const parsed = z.object(def.input).safeParse(rawArgs ?? {});
  if (!parsed.success) {
    recordAudit({ ...base, decision: 'error', reason: 'invalid arguments', ms: Date.now() - t0 });
    return { ok: false, code: 'invalid_request', error: parsed.error.issues.map((i) => `${i.path.join('.')}: ${i.message}`).join('; ') };
  }
  try {
    const data = def.run(parsed.data, p);
    recordAudit({ ...base, args: parsed.data, decision: 'allow', ms: Date.now() - t0 });
    return { ok: true, data };
  } catch (e) {
    const be = e instanceof BusinessError ? e : null;
    recordAudit({ ...base, args: parsed.data, decision: 'error', reason: be ? be.message : 'internal error', ms: Date.now() - t0 });
    if (!be) console.error(e);
    return { ok: false, code: be?.code ?? 'internal_error', error: be?.message ?? 'Internal error' };
  }
}
