// Loads the single shared .env at the repo root (packages/<pkg>/src -> repo root).
import dotenv from 'dotenv';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
dotenv.config({ path: path.resolve(here, '../../../.env'), quiet: true });

export function env(name: string, fallback?: string): string {
  const v = process.env[name]?.trim();
  if (v) return v;
  if (fallback !== undefined) return fallback;
  throw new Error(`Missing required environment variable ${name} (see .env.example)`);
}

export const trimSlash = (s: string) => s.replace(/\/+$/, '');
