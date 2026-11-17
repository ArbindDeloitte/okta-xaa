// OpenAI-style chat-completions tool loop, used for Groq (https://api.groq.com/openai/v1).
// Same job as the Anthropic loop in agent.ts: let the model call the Retail Portal's MCP tools.
import { cfg } from './config.js';

export type LlmTool = { name: string; description?: string; inputSchema: Record<string, unknown> };
export type CallTool = (name: string, args: Record<string, unknown>) => Promise<{ text: string; isError: boolean }>;

type OaMessage = {
  role: 'system' | 'user' | 'assistant' | 'tool';
  content: string | null;
  tool_calls?: { id: string; type: 'function'; function: { name: string; arguments: string } }[];
  tool_call_id?: string;
};

class LlmApiError extends Error {
  constructor(message: string, public status: number, public code?: string) {
    super(message);
  }
}

async function chat(body: Record<string, unknown>): Promise<any> {
  const { apiKey, baseUrl } = cfg.llm.groq;
  if (!apiKey) throw new Error('GROQ_API_KEY is not set. Add it to .env and restart.');
  const res = await fetch(`${baseUrl}/chat/completions`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(90_000),
  });
  const text = await res.text();
  let json: any;
  try {
    json = JSON.parse(text);
  } catch {
    json = { error: { message: text.slice(0, 300) } };
  }
  if (!res.ok) {
    const msg: string = json?.error?.message ?? `HTTP ${res.status}`;
    if (res.status === 401) throw new LlmApiError('Groq rejected GROQ_API_KEY (401). Check the key in .env.', 401);
    if (res.status === 429) throw new LlmApiError(`Groq rate limit reached: ${msg}. Wait a moment and try again.`, 429);
    throw new LlmApiError(`Groq error ${res.status}: ${msg}`, res.status, json?.error?.code);
  }
  return json;
}

// The MCP SDK emits JSON Schema with a "$schema" key; not every OpenAI-compatible server accepts it.
// Models (gpt-oss on Groq) often send null for an optional argument they have nothing for, and Groq rejects the call
// ("expected string, but got null"). So optional properties accept null here, and the nulls are dropped before the MCP call.
const cleanSchema = (schema: Record<string, unknown>) => {
  const { $schema: _ignored, ...rest } = schema;
  const props = rest.properties as Record<string, Record<string, unknown>> | undefined;
  if (!props) return rest;
  const required = new Set((rest.required as string[] | undefined) ?? []);
  const properties = Object.fromEntries(
    Object.entries(props).map(([k, p]) => [
      k,
      !required.has(k) && typeof p.type === 'string' ? { ...p, type: [p.type, 'null'] } : p,
    ]),
  );
  return { ...rest, properties };
};

const dropNulls = (args: Record<string, unknown>) => Object.fromEntries(Object.entries(args).filter(([, v]) => v !== null));

export async function runOpenAiLoop(o: {
  system: string;
  history: { role: 'user' | 'assistant'; content: string }[];
  message: string;
  tools: LlmTool[];
  callTool: CallTool;
}): Promise<string> {
  const messages: OaMessage[] = [
    { role: 'system', content: o.system },
    ...o.history.map((m) => ({ role: m.role, content: m.content })),
    { role: 'user', content: o.message },
  ];
  const tools = o.tools.map((t) => ({
    type: 'function' as const,
    function: { name: t.name, description: t.description ?? '', parameters: cleanSchema(t.inputSchema) },
  }));
  const model = cfg.llm.model;

  for (let round = 0; round < cfg.llm.maxToolRounds; round++) {
    const request = {
      model,
      messages,
      max_completion_tokens: 4096,
      ...(tools.length ? { tools, tool_choice: 'auto' } : {}),
      // gpt-oss models "think" before answering; keep it short so replies are quick and fit in the token budget.
      ...(/gpt-oss/i.test(model) ? { reasoning_effort: 'low' } : {}),
    };
    let data: any;
    try {
      data = await chat(request);
    } catch (e) {
      // The model sometimes emits a malformed tool call; one retry usually fixes it.
      if (e instanceof LlmApiError && e.code === 'tool_use_failed') data = await chat(request);
      else throw e;
    }
    const choice = data.choices?.[0];
    const msg = choice?.message;
    if (!msg) throw new Error('Groq returned no message');

    const calls: NonNullable<OaMessage['tool_calls']> = msg.tool_calls ?? [];
    if (!calls.length) {
      const text = (msg.content ?? '').trim();
      if (choice.finish_reason === 'length') return `${text}\n\n(Response was cut off at the length limit.)`.trim();
      return text || '(The model returned an empty reply.)';
    }

    messages.push({ role: 'assistant', content: msg.content ?? null, tool_calls: calls });
    for (const call of calls) {
      let args: Record<string, unknown> = {};
      let out: { text: string; isError: boolean };
      try {
        args = dropNulls(call.function.arguments ? JSON.parse(call.function.arguments) : {});
        out = await o.callTool(call.function.name, args);
      } catch (e) {
        out = { text: JSON.stringify({ error: 'invalid_tool_arguments', message: (e as Error).message }), isError: true };
      }
      messages.push({ role: 'tool', tool_call_id: call.id, content: out.text });
    }
  }
  return 'I hit the tool-call limit for one request before finishing. Please narrow the question.';
}
