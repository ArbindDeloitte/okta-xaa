// HPE HR Agent: a small, independent AI agent reachable over the real A2A protocol (Agent2Agent, @a2a-js/sdk),
// not MCP. It is the "second agent" both A2A call paths in this project reach: packages/agent calls it directly
// (Cross App Access, agent-to-agent -- see src/a2a.ts there), and packages/agent-bridge calls it through the Okta
// MCP Bridge. See docs/A2A_AGENT_TO_AGENT.md for the full design.
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import type { NextFunction, Request, Response } from 'express';
import express from 'express';
import { AGENT_CARD_PATH } from '@a2a-js/sdk';
import { DefaultRequestHandler, InMemoryTaskStore } from '@a2a-js/sdk/server';
import { agentCardHandler, jsonRpcHandler } from '@a2a-js/sdk/server/express';
import { cfg, missingConfig } from './config.js';
import { hrAgentCard } from './card.js';
import { HrAgentExecutor } from './executor.js';
import { userBuilder } from './auth.js';
import { employees } from './data.js';
import { env } from './env.js';

const missing = missingConfig();
if (missing.length) {
  console.warn(`[agent-hr] Missing config (every caller will be treated as unauthenticated until this is set):\n  - ${missing.join('\n  - ')}`);
}

const requestHandler = new DefaultRequestHandler(hrAgentCard, new InMemoryTaskStore(), new HrAgentExecutor());

const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '100kb' }));

app.get('/healthz', (_req, res) => {
  res.set('X-Agent-Hr', '1'); // lets the startup self-check tell this server apart from another program on the port
  res.json({ ok: true, agent: cfg.agentName, resource: cfg.resource, authIssuer: cfg.authIssuer || null });
});

app.use(`/${AGENT_CARD_PATH}`, agentCardHandler({ agentCardProvider: requestHandler }));
app.use(jsonRpcHandler({ requestHandler, userBuilder }));

// ---- HR portal (demo visual, for presenting to a client): shows the same in-memory data the agent itself reads,
// live-updating as the agent approves PTO requests over A2A. Loopback only unless HR_PORTAL_PUBLIC=true -- same
// safety default packages/retail-portal's own admin console uses.
const isLoopback = (a?: string) => !!a && ['127.0.0.1', '::1', '::ffff:127.0.0.1'].includes(a);
const portalGuard = (req: Request, res: Response, next: NextFunction) => {
  if (env('HR_PORTAL_PUBLIC', 'false') === 'true' || isLoopback(req.socket.remoteAddress)) return next();
  res.status(403).send('The HR portal is only available on localhost.');
};
app.get('/portal/api/employees', portalGuard, (_req, res) => res.json(employees));
/** Lets a presenter reset/adjust the demo data live -- e.g. "add leave" or fix a record -- from the portal page
 * itself, not just through the agent. Same in-memory array the agent's own skills (skills.ts) read and write. */
app.put('/portal/api/employees/:index', portalGuard, (req, res) => {
  const i = Number(req.params.index);
  const emp = employees[i];
  if (!Number.isInteger(i) || !emp) return void res.status(404).json({ error: 'not_found' });
  const b = (req.body ?? {}) as Record<string, unknown>;
  if (typeof b.name === 'string' && b.name.trim()) emp.name = b.name.trim();
  if (typeof b.title === 'string') emp.title = b.title.trim();
  if (typeof b.department === 'string') emp.department = b.department.trim();
  if (typeof b.manager === 'string') emp.manager = b.manager.trim();
  if (typeof b.email === 'string') emp.email = b.email.trim();
  if (b.ptoBalanceDays !== undefined) {
    const n = Number(b.ptoBalanceDays);
    if (!Number.isFinite(n) || n < 0) return void res.status(400).json({ error: 'invalid_pto', message: 'PTO balance must be a non-negative number.' });
    emp.ptoBalanceDays = n;
  }
  res.json(emp);
});
/** Adds a new demo employee record. Same scope as the edit endpoint above: a presenter setting up a demo, not
 * something the agent itself ever calls (its own skills only read/update existing records by name). */
app.post('/portal/api/employees', portalGuard, (req, res) => {
  const b = (req.body ?? {}) as Record<string, unknown>;
  const name = typeof b.name === 'string' ? b.name.trim() : '';
  if (!name) return void res.status(400).json({ error: 'invalid_request', message: 'Name is required.' });
  const ptoBalanceDays = b.ptoBalanceDays !== undefined ? Number(b.ptoBalanceDays) : 0;
  if (!Number.isFinite(ptoBalanceDays) || ptoBalanceDays < 0) {
    return void res.status(400).json({ error: 'invalid_pto', message: 'PTO balance must be a non-negative number.' });
  }
  const emp = {
    name,
    title: typeof b.title === 'string' ? b.title.trim() : '',
    department: typeof b.department === 'string' ? b.department.trim() : '',
    manager: typeof b.manager === 'string' ? b.manager.trim() : '',
    email: typeof b.email === 'string' ? b.email.trim() : '',
    ptoBalanceDays,
  };
  employees.push(emp);
  res.status(201).json(emp);
});
app.use('/portal', portalGuard, express.static(path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../public')));

/** Warn if another program answers on this port (same self-check every other app in this project does). */
async function selfCheck() {
  for (const host of ['127.0.0.1', '[::1]']) {
    try {
      const r = await fetch(`http://${host}:${cfg.port}/healthz`, { signal: AbortSignal.timeout(3000) });
      if (r.headers.get('x-agent-hr') !== '1') {
        console.warn(`\n!! Port ${cfg.port} is shared with ANOTHER program: http://${host}:${cfg.port} answered HTTP ${r.status}, not this app. Change AGENT_HR_PORT (and AGENT_HR_BASE_URL / HR_AGENT_URL).\n`);
      }
    } catch {
      /* that address family isn't bound here; fine */
    }
  }
}

const server = app.listen(cfg.port, () => {
  void selfCheck();
  console.log(`HPE HR Agent (A2A) on ${cfg.baseUrl}`);
  console.log(`  Agent Card  : ${cfg.baseUrl}/${AGENT_CARD_PATH}`);
  console.log(`  Trusts      : ${cfg.authIssuer || '(HR_AGENT_AUTH_ISSUER not set -- no caller will be authenticated)'}`);
  console.log(`  Resource    : ${cfg.resource}`);
  console.log(`  Scopes      : ${cfg.scopes.join(' ')}`);
  console.log(`  LLM         : anthropic / ${cfg.llm.model}${process.env.ANTHROPIC_BASE_URL ? `  via ${process.env.ANTHROPIC_BASE_URL}` : ''}`);
  console.log(`  HR portal   : ${cfg.baseUrl}/portal  (demo view${env('HR_PORTAL_PUBLIC', 'false') === 'true' ? '' : ', localhost only'})`);
});
server.on('error', (e: NodeJS.ErrnoException) => {
  if (e.code === 'EADDRINUSE') {
    console.error(`Port ${cfg.port} is already in use by another program. Change AGENT_HR_PORT and AGENT_HR_BASE_URL.`);
    process.exit(1);
  }
  throw e;
});
