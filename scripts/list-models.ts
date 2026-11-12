// Lists the models the configured key can use (Models API; free, spends no tokens).
// Works against api.anthropic.com, and against ANTHROPIC_BASE_URL endpoints that implement /v1/models.
import Anthropic from '@anthropic-ai/sdk';
import dotenv from 'dotenv';
import path from 'node:path';

dotenv.config({ path: path.resolve(import.meta.dirname, '../.env'), quiet: true });
const key = process.env.ANTHROPIC_API_KEY?.trim() || process.env.BEDROCK_API_KEY?.trim();
if (!key) { console.error('No ANTHROPIC_API_KEY / BEDROCK_API_KEY in .env'); process.exit(1); }
console.log(`endpoint: ${process.env.ANTHROPIC_BASE_URL?.trim() || 'https://api.anthropic.com'}`);
try {
  const client = new Anthropic({ apiKey: key, maxRetries: 0 });
  let n = 0;
  for await (const m of client.models.list({ limit: 100 })) { console.log(`  ${m.id}${m.display_name ? `  (${m.display_name})` : ''}`); n++; }
  console.log(n ? `\n${n} model(s). Set AGENT_MODEL_ID to one of these.` : '\nNo models returned.');
} catch (err) {
  if ((err as { status?: number }).status === 404 && process.env.ANTHROPIC_BASE_URL?.includes('bedrock')) {
    // The Bedrock Mantle endpoint has no Models API; use Bedrock's own catalogue (ListFoundationModels) instead.
    const region = process.env.AWS_REGION?.trim() || 'us-east-1';
    console.log('(this endpoint has no Models API; asking the Bedrock catalogue for Anthropic models)');
    const r = await fetch(`https://bedrock.${region}.amazonaws.com/foundation-models?byProvider=anthropic`, { headers: { Authorization: `Bearer ${key}` } });
    const body = await r.text();
    if (!r.ok) {
      console.error(/expired/i.test(body) ? 'The key has EXPIRED. Generate a new Bedrock key (npm run check:aws shows when each key expired).' : `Catalogue request failed: HTTP ${r.status} ${body.replace(/\s+/g, ' ').slice(0, 250)}`);
      process.exit(1);
    }
    const models = (JSON.parse(body) as { modelSummaries: { modelId: string; modelName: string; modelLifecycle?: { status?: string } }[] }).modelSummaries;
    for (const m of models) console.log(`  ${m.modelId}  (${m.modelName}, ${m.modelLifecycle?.status ?? '?'})`);
    console.log(`
${models.length} Anthropic model(s) in the catalogue for ${region}. Being listed doesn't guarantee your account has access to it.`);
    process.exit(0);
  }
  const msg = ((err as Error).message ?? '').replace(/\s+/g, ' ');
  console.error(/signature expired/i.test(msg) ? 'The key has EXPIRED. Generate a new Bedrock key (npm run check:aws shows when each key expired).' : `Failed: ${msg.slice(0, 300)}`);
  process.exit(1);
}
