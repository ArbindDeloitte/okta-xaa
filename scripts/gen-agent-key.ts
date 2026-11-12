// Key pair for the agent's private_key_jwt client authentication at Okta.
//
//   npm run gen:key            create a new RS256 key pair (refuses to overwrite an existing one)
//   npm run gen:key -- --force overwrite the existing key (you must then re-register the public key in Okta)
//   npm run show:key           re-print the PUBLIC JWK of the existing key (to paste into Okta)
//
// The PRIVATE JWK lives in .keys/agent-private.jwk.json (git-ignored). Only the public JWK goes to Okta:
// AI agent -> Client registration -> Public/private key -> Add public key.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { exportJWK, generateKeyPair } from 'jose';

const dir = path.resolve(import.meta.dirname, '../.keys');
// --name limited  ->  .keys/agent-limited-private.jwk.json (a separate key for a second agent)
const nameIdx = process.argv.indexOf('--name');
const keyName = nameIdx >= 0 ? process.argv[nameIdx + 1] : undefined;
if (keyName !== undefined && !/^[A-Za-z0-9_-]+$/.test(keyName)) {
  console.error('--name must be letters, digits, - or _');
  process.exit(1);
}
const file = path.join(dir, keyName ? `agent-${keyName}-private.jwk.json` : 'agent-private.jwk.json');
const publicOf = (priv: Record<string, unknown>) => ({ kty: priv.kty, n: priv.n, e: priv.e, kid: priv.kid, alg: priv.alg ?? 'RS256', use: priv.use ?? 'sig' });

if (process.argv.includes('--public')) {
  if (!fs.existsSync(file)) {
    console.error(`No key at ${file}. Run "npm run gen:key" first.`);
    process.exit(1);
  }
  console.log(JSON.stringify(publicOf(JSON.parse(fs.readFileSync(file, 'utf8'))), null, 2));
  process.exit(0);
}

if (fs.existsSync(file) && !process.argv.includes('--force')) {
  console.error(`${file} already exists. Use "npm run show:key" to print its public JWK, or "npm run gen:key -- --force" to replace it.`);
  process.exit(1);
}

const { publicKey, privateKey } = await generateKeyPair('RS256', { extractable: true });
const kid = crypto.randomUUID();
const priv = { ...(await exportJWK(privateKey)), kid, alg: 'RS256', use: 'sig' };
const pub = { ...(await exportJWK(publicKey)), kid, alg: 'RS256', use: 'sig' };

fs.mkdirSync(dir, { recursive: true });
fs.writeFileSync(file, JSON.stringify(priv, null, 2), { mode: 0o600 });

console.log(`Private key written to ${file}\n`);
console.log('Public JWK (paste into Okta: AI agent → Client registration → Public/private key → Add public key):\n');
console.log(JSON.stringify(pub, null, 2));
