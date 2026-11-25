// The HR Agent's own small LLM turn: receives the free-text task an A2A caller sent, runs ONE bounded round of
// tool use against its two skills (see skills.ts), and replies in free text. This is what makes it a genuine
// second AGENT rather than one more MCP tool server: the caller sends a natural-language request and this agent
// reasons about it, instead of the caller invoking a fixed, schema-typed function directly.
import Anthropic from '@anthropic-ai/sdk';
import { cfg } from './config.js';
import { SKILL_SCOPE, SKILL_TOOLS, runSkill, type SkillName } from './skills.js';
import type { VerifiedCaller } from './auth.js';

let anthropic: Anthropic | undefined;
const getAnthropic = () => (anthropic ??= new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY?.trim() || process.env.BEDROCK_API_KEY?.trim() || undefined }));

const SYSTEM_PROMPT = `You are the HPE HR Agent, an AI agent that other AI agents call (over the Agent2Agent / A2A protocol) to answer HR questions: employee lookups, manager and department info, and PTO (paid time off) balances and requests. All data is sample demo data.

Guidelines:
- Use the tools to get facts; never invent an employee, title, department or PTO balance.
- If a tool call is denied for lacking a scope, say plainly that the caller is not authorized for that action, and name which scope it would need. Never try to work around it.
- Be concise: a few sentences or a short list. No markdown headings or tables -- the caller may show this as plain text.`;

export async function answerHrTask(task: string, caller: VerifiedCaller): Promise<string> {
  if (!process.env.ANTHROPIC_API_KEY && !process.env.ANTHROPIC_AUTH_TOKEN && !process.env.BEDROCK_API_KEY) {
    throw new Error('ANTHROPIC_API_KEY (or BEDROCK_API_KEY) is not set. Add it to .env and restart.');
  }
  const messages: Anthropic.MessageParam[] = [{ role: 'user', content: task }];
  const params = { model: cfg.llm.model, max_tokens: 1024, system: SYSTEM_PROMPT, tools: SKILL_TOOLS };

  const first = await getAnthropic().messages.create({ ...params, messages });
  const textOf = (resp: Anthropic.Message) => resp.content.filter((b): b is Anthropic.TextBlock => b.type === 'text').map((b) => b.text).join('\n').trim();
  if (first.stop_reason !== 'tool_use') return textOf(first) || '(no reply)';

  // One bounded round: answer every tool call the model asked for, in one user turn, then take its final answer.
  // No further rounds are allowed, matching this agent's deliberately small scope (see docs/A2A_AGENT_TO_AGENT.md §4).
  messages.push({ role: 'assistant', content: first.content });
  const results: Anthropic.ToolResultBlockParam[] = [];
  for (const block of first.content) {
    if (block.type !== 'tool_use') continue;
    const needed = SKILL_SCOPE[block.name as SkillName];
    if (needed && !caller.hasScope(needed)) {
      results.push({
        type: 'tool_result',
        tool_use_id: block.id,
        is_error: true,
        content: JSON.stringify({ error: 'insufficient_scope', message: `This caller's token does not have the "${needed}" scope.` }),
      });
      continue;
    }
    const r = runSkill(block.name, block.input as Record<string, unknown>);
    results.push({ type: 'tool_result', tool_use_id: block.id, is_error: r.isError, content: r.text });
  }
  messages.push({ role: 'user', content: results });

  const second = await getAnthropic().messages.create({ ...params, messages });
  return textOf(second) || '(no reply)';
}
