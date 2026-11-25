// The HR Agent's Agent Card: what a caller (or the @a2a-js/sdk client) fetches at /.well-known/agent-card.json
// to learn who this agent is and where its A2A endpoint lives. Shape confirmed against the installed
// @a2a-js/sdk@1.3.0 types (node_modules/@a2a-js/sdk/dist/a2a-CJdXl9vi.d.ts) -- the URL lives on
// supportedInterfaces[], not as a top-level `url` field.
import { A2A_PROTOCOL_VERSION, type AgentCard } from '@a2a-js/sdk';
import { cfg } from './config.js';

export const hrAgentCard: AgentCard = {
  name: cfg.agentName,
  description:
    'Answers HR questions for HPE staff: employee lookups (title, department, manager) and PTO (time off) balances and requests. Demo data only.',
  supportedInterfaces: [{ url: cfg.resource, protocolBinding: 'JSONRPC', tenant: '', protocolVersion: A2A_PROTOCOL_VERSION }],
  provider: { organization: 'HPE (demo)', url: cfg.resource },
  version: '1.0.0',
  documentationUrl: '',
  capabilities: { streaming: false, pushNotifications: false, extensions: [], extendedAgentCard: false },
  securitySchemes: {
    Bearer: {
      scheme: {
        $case: 'httpAuthSecurityScheme',
        value: { description: 'Okta-issued access token (Cross App Access, agent-to-agent)', scheme: 'bearer', bearerFormat: 'JWT' },
      },
    },
  },
  securityRequirements: [{ schemes: { Bearer: { list: cfg.scopes } } }],
  defaultInputModes: ['text/plain'],
  defaultOutputModes: ['text/plain'],
  skills: [
    {
      id: 'lookup_employee',
      name: 'Look up an employee',
      description: 'Title, department, manager and current PTO balance.',
      tags: ['hr', 'read'],
      examples: ["What is Priya Natarajan's PTO balance?"],
      inputModes: ['text/plain'],
      outputModes: ['text/plain'],
      securityRequirements: [{ schemes: { Bearer: { list: ['hr:read'] } } }],
    },
    {
      id: 'update_pto_request',
      name: 'Approve a PTO request',
      description: "Deducts PTO days from an employee's balance.",
      tags: ['hr', 'write'],
      examples: ['Approve 3 PTO days for Marcus Webb'],
      inputModes: ['text/plain'],
      outputModes: ['text/plain'],
      securityRequirements: [{ schemes: { Bearer: { list: ['hr:write'] } } }],
    },
  ],
  signatures: [],
  iconUrl: '',
};
