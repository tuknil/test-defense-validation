import { createHash, randomUUID } from 'node:crypto';

/** Deterministic JSON serialisation so digests are stable regardless of key order. */
export function canonicalJson(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value ?? null);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  const keys = Object.keys(value).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(value[k])}`).join(',')}}`;
}

export function sha256(input) {
  const text = typeof input === 'string' ? input : canonicalJson(input);
  return `sha256:${createHash('sha256').update(text).digest('hex')}`;
}

export function shortDigest(digest, length = 12) {
  return digest?.startsWith('sha256:') ? `sha256:${digest.slice(7, 7 + length)}…` : digest;
}

export function uuid() {
  return randomUUID();
}

export function nowIso() {
  return new Date().toISOString();
}
