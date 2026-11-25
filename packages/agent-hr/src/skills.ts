// The HR Agent's two skills, run by its own (internal) one-round Claude tool call -- see llm.ts. Each is gated by
// a scope, checked by the caller's verified token before the skill ever runs (the same governance story as the
// Retail Portal's scope-gated MCP tools, one layer simpler: no per-user role on top of the scope).
import { findEmployee } from './data.js';

export type SkillName = 'lookup_employee' | 'update_pto_request';

export const SKILL_SCOPE: Record<SkillName, string> = {
  lookup_employee: 'hr:read',
  update_pto_request: 'hr:write',
};

/** Anthropic tool schemas for the HR Agent's own internal tool-use round (distinct from the A2A protocol itself:
 * a caller never sees these -- it only ever sends a free-text task and gets a free-text reply). */
export const SKILL_TOOLS = [
  {
    name: 'lookup_employee' as const,
    description: "Look up an HPE employee by name or email: title, department, manager and current PTO balance.",
    input_schema: {
      type: 'object' as const,
      properties: { name: { type: 'string', description: 'Full or partial name, or an email address' } },
      required: ['name'],
    },
  },
  {
    name: 'update_pto_request' as const,
    description: "Deduct a number of PTO (time off) days from an employee's balance, approving a time-off request. Refuses if the balance is insufficient.",
    input_schema: {
      type: 'object' as const,
      properties: {
        name: { type: 'string', description: 'Full or partial name, or an email address' },
        days: { type: 'number', description: 'Number of PTO days to deduct' },
      },
      required: ['name', 'days'],
    },
  },
];

export function runSkill(name: string, args: Record<string, unknown>): { text: string; isError: boolean } {
  if (name === 'lookup_employee') {
    const emp = findEmployee(String(args.name ?? ''));
    if (!emp) return { text: JSON.stringify({ error: 'not_found', message: `No employee matching "${args.name}"` }), isError: true };
    return { text: JSON.stringify(emp), isError: false };
  }
  if (name === 'update_pto_request') {
    const emp = findEmployee(String(args.name ?? ''));
    if (!emp) return { text: JSON.stringify({ error: 'not_found', message: `No employee matching "${args.name}"` }), isError: true };
    const days = Number(args.days);
    if (!Number.isFinite(days) || days <= 0) {
      return { text: JSON.stringify({ error: 'invalid_request', message: 'days must be a positive number' }), isError: true };
    }
    if (days > emp.ptoBalanceDays) {
      return {
        text: JSON.stringify({ error: 'insufficient_balance', message: `${emp.name} has only ${emp.ptoBalanceDays} PTO day(s) left`, ptoBalanceDays: emp.ptoBalanceDays }),
        isError: true,
      };
    }
    emp.ptoBalanceDays -= days;
    return { text: JSON.stringify({ status: 'approved', name: emp.name, daysDeducted: days, ptoBalanceDays: emp.ptoBalanceDays }), isError: false };
  }
  return { text: JSON.stringify({ error: 'unknown_skill', message: `No skill named "${name}"` }), isError: true };
}
