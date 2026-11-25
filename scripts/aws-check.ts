// Reachability + key-expiry diagnostics for the Bedrock setup. Prints no secrets (only host names, dates, status codes).
import dns from 'node:dns/promises';
import dotenv from 'dotenv';
import path from 'node:path';

dotenv.config({ path: path.resolve(import.meta.dirname, '../.env'), quiet: true });
const e = process.env;
const region = e.AWS_REGION?.trim() || 'us-east-1';
const mantle = e.ANTHROPIC_BASE_URL?.trim() || `https://bedrock-mantle.${region}.api.aws/anthropic`;

console.log('== Reachability (no credentials sent) ==');
const targets = [...new Set([mantle, `https://bedrock-runtime.${region}.amazonaws.com`, `https://bedrock.${region}.amazonaws.com`])];
for (const url of targets) {
  const host = new URL(url).host;
  try {
    const addrs = await dns.lookup(host, { all: true });
    const t0 = Date.now();
    const r = await fetch(url, { method: 'GET', signal: AbortSignal.timeout(10_000) });
    console.log(`  ✔ ${host}: DNS ok (${addrs.length} addr), HTTPS answered ${r.status} in ${Date.now() - t0}ms`);
  } catch (err) {
    console.log(`  ✘ ${host}: ${(err as Error).message}${(err as { cause?: { code?: string } }).cause?.code ? ` (${(err as { cause: { code: string } }).cause.code})` : ''}`);
  }
}

console.log('\n== Bedrock key expiry (decoded locally; secrets not printed) ==');
for (const name of ['ANTHROPIC_API_KEY', 'BEDROCK_API_KEY', 'AWS_BEARER_TOKEN_BEDROCK']) {
  const key = e[name]?.trim();
  if (!key) { console.log(`  - ${name}: not set`); continue; }
  try {
    const b64 = key.replace(/^bedrock-api-key-/, '');
    const url = Buffer.from(b64, 'base64').toString('utf8');
    const q = new URLSearchParams(url.slice(url.indexOf('?') + 1));
    const date = q.get('X-Amz-Date'); // 20261007T223422Z
    const secs = Number(q.get('X-Amz-Expires'));
    if (!date || !secs) throw new Error('not a presigned-style (short-term) Bedrock key; may be a long-term key');
    const start = Date.parse(date.replace(/^(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})Z$/, '$1-$2-$3T$4:$5:$6Z'));
    const end = start + secs * 1000;
    const cred = q.get('X-Amz-Credential') ?? '';
    console.log(`  ${end > Date.now() ? '✔' : '✘'} ${name}: issued ${new Date(start).toISOString()}, valid ${Math.round(secs / 3600 * 10) / 10}h, ${end > Date.now() ? 'expires' : 'EXPIRED'} ${new Date(end).toISOString()} (${cred.startsWith('ASIA') ? 'temporary STS credentials' : cred.startsWith('AKIA') ? 'IAM user credentials' : 'unknown credential type'}, region ${cred.split('/')[2] ?? '?'})`);
  } catch (err) {
    console.log(`  ? ${name}: cannot decode (${(err as Error).message})`);
  }
}
