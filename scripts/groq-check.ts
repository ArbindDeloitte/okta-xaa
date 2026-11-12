// Tests GROQ_API_KEY against Groq's OpenAI-compatible API: key, model list, chat, and tool calling.
// Prints no secrets.
import dotenv from 'dotenv';
import path from 'node:path';

dotenv.config({ path: path.resolve(import.meta.dirname, '../.env'), quiet: true });
const key = process.env.GROQ_API_KEY?.trim();
const base = (process.env.GROQ_BASE_URL?.trim() || 'https://api.groq.com/openai/v1').replace(/\/+$/, '');
if (!key) { console.error('GROQ_API_KEY is not set in .env'); process.exit(1); }
console.log(`endpoint: ${base}`);

async function call(p: string, init?: RequestInit) {
  const r = await fetch(`${base}${p}`, { ...init, headers: { Authorization: `Bearer ${key}`, 'Content-Type': 'application/json' }, signal: AbortSignal.timeout(45_000) });
  const text = await r.text();
  let json: any; try { json = JSON.parse(text); } catch { json = { raw: text.slice(0, 200) }; }
  return { r, json };
}

const models = await call('/models');
if (!models.r.ok) { console.log(`✘ GET /models -> HTTP ${models.r.status}: ${JSON.stringify(models.json).slice(0, 300)}`); process.exit(1); }
const ids: string[] = (models.json.data ?? []).filter((m: any) => m.active !== false).map((m: any) => m.id).sort();
console.log(`✔ key accepted. ${ids.length} model(s):\n  ${ids.join('\n  ')}\n`);

const wanted = process.env.GROQ_MODEL?.trim();
const candidates = wanted ? [wanted] : ['openai/gpt-oss-120b', 'llama-3.3-70b-versatile', 'openai/gpt-oss-20b', 'meta-llama/llama-4-scout-17b-16e-instruct'].filter((m) => ids.includes(m));
if (!candidates.length) { console.log('No known tool-capable model found in the list; set GROQ_MODEL.'); process.exit(1); }

const tool = { type: 'function', function: { name: 'get_order', description: 'Get an order by id', parameters: { type: 'object', properties: { order_id: { type: 'string' } }, required: ['order_id'] } } };
for (const model of candidates) {
  const chat = await call('/chat/completions', { method: 'POST', body: JSON.stringify({ model, max_tokens: 16, messages: [{ role: 'user', content: 'Reply with the single word OK.' }] }) });
  if (!chat.r.ok) { console.log(`✘ chat with ${model}: HTTP ${chat.r.status} ${JSON.stringify(chat.json).slice(0, 250)}`); continue; }
  console.log(`✔ chat with ${model}: "${chat.json.choices?.[0]?.message?.content?.trim()}"`);
  const t = await call('/chat/completions', { method: 'POST', body: JSON.stringify({ model, max_tokens: 200, tools: [tool], tool_choice: 'auto', messages: [{ role: 'user', content: 'What is the status of order ORD-10001? Use the tool.' }] }) });
  const tc = t.json.choices?.[0]?.message?.tool_calls?.[0];
  if (!t.r.ok) console.log(`  ✘ tool calling with ${model}: HTTP ${t.r.status} ${JSON.stringify(t.json).slice(0, 250)}`);
  else if (tc) console.log(`  ✔ tool calling with ${model}: called ${tc.function.name}(${tc.function.arguments})`);
  else console.log(`  ✘ ${model} answered without calling the tool`);
}
