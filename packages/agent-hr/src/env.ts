// Loads the shared .env at the repo root (packages/<pkg>/src -> repo root). Copied from packages/agent/src/env.ts
// so this package has no import dependency on the agent package (it is a standalone resource server, like
// retail-portal and retail-auth, not another variant of the same agent identity).
import dotenv from 'dotenv';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, '../../..');
dotenv.config({ path: path.join(root, '.env'), quiet: true });

export function env(name: string, fallback?: string): string {
  const v = process.env[name]?.trim();
  if (v) return v;
  if (fallback !== undefined) return fallback;
  throw new Error(`Missing required environment variable ${name} (see .env.example)`);
}

export const trimSlash = (s: string) => s.replace(/\/+$/, '');
