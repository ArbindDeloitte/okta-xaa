// The agent: an LLM (Claude via Anthropic/Bedrock, or Groq) + an MCP client connected to the Retail Portal using the
// XAA-issued access token. The model only ever sees the tools Okta's policy let this user have.
import Anthropic from '@anthropic-ai/sdk';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { cfg } from './config.js';
import { runOpenAiLoop, type CallTool } from './llm-openai.js';

export type ToolInfo = { name: string; description: string };
export type ToolCall = { name: string; args: unknown; result: string; isError: boolean; ms: number };
export type ChatMessage = { role: 'user' | 'assistant'; content: string };

export class McpAuthError extends Error {}
/** The Okta Agent Gateway asks the user to connect their account to the portal once (brokered consent). */
export class ConsentRequiredError extends Error {
  constructor(public url: string) {
    super('The gateway needs you to connect your account to the HPE Order Portal (one time).');
  }
}

/** The gateway prefixes every tool name (e.g. "HPEOrderPortalMCPv2_list_orders"); find that shared prefix to show clean names. */
export function commonToolPrefix(names: string[]): string {
  if (names.length < 2) return '';
  const i = names[0].indexOf('_');
  if (i <= 0) return '';
  let end = i + 1;
  while (names.every((n) => n[end] === '_')) end++; // "server__tool" style: take the whole run of underscores
  const p = names[0].slice(0, end);
  return names.every((n) => n.startsWith(p) && n.length > p.length) ? p : '';
}

/** Tools that only read (search_/check_/list_/get_). Safe to repeat; create_return and cancel_order are not. */
export const isReadOnlyTool = (name: string) => /^(search|check|list|get)_/.test(name);

/** The gateway gave up waiting for the portal (e.g. a flaky tunnel in between). The call may or may not have reached it. */
export const isUpstreamUnavailable = (text: string) => /target MCP server unavailable/i.test(text);

/** Gateway tool result "Connection required: visit <okta link> to connect your account." -> the link (Okta hosts only). */
export function consentUrlFrom(text: string): string | undefined {
  const m = /Connection required: visit (https:\/\/\S+)/.exec(text);
  if (!m) return undefined;
  try {
    const u = new URL(m[1]);
    return /(^|\.)okta(preview)?\.com$/.test(u.hostname) ? u.href : undefined;
  } catch {
    return undefined;
  }
}

const SYSTEM_PROMPT = (user: string) => `You are the HPE Order Operations Assistant, an AI agent that helps order-desk and support staff look up sales orders and enterprise accounts, check hardware stock across distribution centres, and handle cancellations and RMAs (return merchandise authorizations) by calling tools exposed by the HPE Order Portal. All data is sample demo data.

You are acting on behalf of ${user}. Access is governed centrally: the tools you can see, and what each is allowed to do, are decided by the company's identity provider (Okta Cross App Access) and by this user's role in the portal. Never try to work around a restriction.

Guidelines:
- Use tools to get facts; never invent order numbers, stock levels, prices or account data.
- If the user asks for something none of your tools can do, say plainly that you don't have access to that capability. If a tool call is denied (for example "forbidden_for_role" or "insufficient_scope"), explain that it's a permission limit and suggest who could approve it.
- For actions that change data (cancel_order, create_return, which files an RMA), only act when the user has clearly asked for that action and given the details; otherwise ask. After acting, report the result, including any approval state.
- Be concise. Use short bullet lists for multiple records. The chat window shows plain text with only **bold** and \`code\`, so do not use markdown tables or headings.`;

let anthropic: Anthropic | undefined;
// Reads ANTHROPIC_BASE_URL from the environment (e.g. a Bedrock Mantle endpoint). BEDROCK_API_KEY is accepted
// as a fallback for ANTHROPIC_API_KEY.
const getAnthropic = () =>
  (anthropic ??= new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY?.trim() || process.env.BEDROCK_API_KEY?.trim() || undefined }));

async function connectMcp(accessToken: string, url: string = cfg.retail.mcpUrl): Promise<Client> {
  // Connecting has no side effects, so a stalled attempt (flaky tunnel or proxy) is safe to abandon and retry quickly
  // instead of waiting for the SDK's 60 s default.
  let lastError = '';
  for (let attempt = 1; attempt <= 3; attempt++) {
    const client = new Client({ name: 'retail-agent', version: '1.0.0' });
    const transport = new StreamableHTTPClientTransport(new URL(url), {
      requestInit: { headers: { Authorization: `Bearer ${accessToken}` } },
    });
    try {
      await client.connect(transport, { timeout: 10_000 });
      return client;
    } catch (e) {
      lastError = (e as Error).message ?? String(e);
      await client.close().catch(() => {});
      if (/401|unauthori[sz]ed|invalid_token/i.test(lastError)) throw new McpAuthError(lastError);
    }
  }
  throw new Error(`Cannot reach the MCP server at ${url} (3 attempts): ${lastError}`);
}

/** List the tools the Retail Portal exposes to this token (used to show governance in the UI). */
export async function listRetailTools(accessToken: string, url?: string): Promise<ToolInfo[]> {
  const mcp = await connectMcp(accessToken, url);
  try {
    const { tools } = await mcp.listTools();
    const prefix = commonToolPrefix(tools.map((t) => t.name));
    return tools.map((t) => ({ name: t.name.slice(prefix.length), description: t.description ?? '' }));
  } finally {
    await mcp.close();
  }
}

export async function runAgent(opts: {
  accessToken: string;
  userLabel: string;
  history: ChatMessage[];
  message: string;
  /** MCP endpoint to use instead of the portal's own (the Okta Agent Gateway URL). */
  mcpUrl?: string;
}): Promise<{ reply: string; toolCalls: ToolCall[]; tools: ToolInfo[] }> {
  if (cfg.llm.provider === 'groq') {
    if (!cfg.llm.groq.apiKey) throw new Error('GROQ_API_KEY is not set. Add it to .env and restart.');
  } else if (!process.env.ANTHROPIC_API_KEY && !process.env.ANTHROPIC_AUTH_TOKEN && !process.env.BEDROCK_API_KEY) {
    throw new Error('ANTHROPIC_API_KEY (or BEDROCK_API_KEY) is not set. Add it to .env and restart.');
  }
  const mcp = await connectMcp(opts.accessToken, opts.mcpUrl);
  const toolCalls: ToolCall[] = [];
  try {
    const { tools: mcpTools } = await mcp.listTools();
    const prefix = commonToolPrefix(mcpTools.map((t) => t.name));
    const toolInfos = mcpTools.map((t) => ({ name: t.name.slice(prefix.length), description: t.description ?? '' }));
    let consentUrl: string | undefined;
    const done = (reply: string) => {
      if (consentUrl) throw new ConsentRequiredError(consentUrl); // discard the model's reply: the user must connect first
      return { reply, toolCalls, tools: toolInfos };
    };

    // Calls a Retail Portal tool over MCP and records it for the UI (shared by every LLM provider).
    const callTool: CallTool = async (name, args) => {
      const t0 = Date.now();
      let text = '';
      let isError = false;
      const attempt = async () => {
        try {
          const r = await mcp.callTool({ name, arguments: args });
          text = (r.content as Array<{ type: string; text?: string }>).map((c) => c.text ?? '').join('\n');
          isError = Boolean(r.isError);
        } catch (e) {
          text = JSON.stringify({ error: 'tool_call_failed', message: (e as Error).message });
          isError = true;
        }
      };
      await attempt();
      // A read that failed because the gateway could not reach the portal is repeated once. Writes never are:
      // the stalled call may still have gone through, and a repeat could file a second RMA.
      if (isError && isUpstreamUnavailable(text) && isReadOnlyTool(name.slice(prefix.length))) await attempt();
      const url = isError ? consentUrlFrom(text) : undefined;
      if (url) {
        consentUrl = url;
        text = 'The user has not connected their account to the portal yet. Stop calling tools and tell them to use the Connect button, then ask again.';
      }
      toolCalls.push({ name: name.slice(prefix.length), args, result: text, isError, ms: Date.now() - t0 });
      return { text, isError };
    };

    if (cfg.llm.provider === 'groq') {
      const reply = await runOpenAiLoop({
        system: SYSTEM_PROMPT(opts.userLabel),
        history: opts.history,
        message: opts.message,
        tools: mcpTools.map((t) => ({ name: t.name, description: t.description, inputSchema: t.inputSchema as Record<string, unknown> })),
        callTool,
      });
      return done(reply);
    }

    const tools = mcpTools.map((t) => ({
      name: t.name,
      description: t.description ?? '',
      input_schema: t.inputSchema as Anthropic.Beta.BetaTool.InputSchema,
    }));

    const messages: Anthropic.Beta.BetaMessageParam[] = [
      ...opts.history.map((m) => ({ role: m.role, content: m.content })),
      { role: 'user', content: opts.message },
    ];

    let reply = '';
    for (let round = 0; round < cfg.llm.maxToolRounds; round++) {
      const params = { model: cfg.llm.model, max_tokens: 16000, system: SYSTEM_PROMPT(opts.userLabel), tools, messages };
      const resp = cfg.llm.serverFallbacks
        ? await getAnthropic().beta.messages.create({
            ...params,
            // If a safety classifier declines this request, retry server-side on the default fallback.
            betas: ['server-side-fallback-2026-07-01'],
            fallbacks: 'default',
          })
        : ((await getAnthropic().messages.create(params as unknown as Anthropic.MessageCreateParamsNonStreaming)) as unknown as Anthropic.Beta.BetaMessage);

      const text = resp.content
        .filter((b): b is Anthropic.Beta.BetaTextBlock => b.type === 'text')
        .map((b) => b.text)
        .join('\n')
        .trim();

      if (resp.stop_reason === 'refusal') {
        reply = text || 'The model declined to continue with this request.';
        break;
      }
      if (resp.stop_reason !== 'tool_use') {
        reply = resp.stop_reason === 'max_tokens' ? `${text}\n\n(Response was cut off at the length limit.)` : text;
        break;
      }

      // Echo the assistant turn back unchanged, then answer ALL tool calls in one user message.
      messages.push({ role: 'assistant', content: resp.content as unknown as Anthropic.Beta.BetaContentBlockParam[] });
      const results: Anthropic.Beta.BetaToolResultBlockParam[] = [];
      for (const block of resp.content) {
        if (block.type !== 'tool_use') continue;
        const out = await callTool(block.name, block.input as Record<string, unknown>);
        results.push({ type: 'tool_result', tool_use_id: block.id, content: out.text, is_error: out.isError });
      }
      messages.push({ role: 'user', content: results });
      if (round === cfg.llm.maxToolRounds - 1) {
        reply = 'I hit the tool-call limit for one request before finishing. Please narrow the question.';
      }
    }
    return done(reply);
  } finally {
    await mcp.close();
  }
}
