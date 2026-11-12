// Loads the shared .env at the repo root (packages/<pkg>/src -> repo root).
// Optional profile: `--profile limited` (or AGENT_PROFILE=limited) then loads `.env.limited` ON TOP of .env, so a
// second copy of the agent app can run as a different Okta agent (own client id, key, port and scopes).
import dotenv from 'dotenv';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, '../../..');
dotenv.config({ path: path.join(root, '.env'), quiet: true });

function profileName(): string | undefined {
  const i = process.argv.indexOf('--profile');
  const fromArg = i >= 0 ? process.argv[i + 1] : process.argv.find((a) => a.startsWith('--profile='))?.split('=')[1];
  return (fromArg || process.env.AGENT_PROFILE)?.trim() || undefined;
}
export const profile = profileName();
if (profile) {
  if (!/^[A-Za-z0-9_-]+$/.test(profile)) throw new Error(`Invalid profile name "${profile}"`);
  const file = path.join(root, `.env.${profile}`);
  if (!fs.existsSync(file)) throw new Error(`Profile "${profile}" needs ${file} (copy .env.${profile}.example)`);
  dotenv.config({ path: file, override: true, quiet: true });
}

export function env(name: string, fallback?: string): string {
  const v = process.env[name]?.trim();
  if (v) return v;
  if (fallback !== undefined) return fallback;
  throw new Error(`Missing required environment variable ${name} (see .env.example)`);
}

export const trimSlash = (s: string) => s.replace(/\/+$/, '');
