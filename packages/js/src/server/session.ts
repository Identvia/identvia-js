import { EncryptJWT, jwtDecrypt, base64url } from 'jose';
import { ConfigurationError } from '../core/errors.js';

const enc = new TextEncoder();

/** Derives a 256-bit key from your secret (at least 32 characters; e.g. `openssl rand -base64 48`). */
export async function deriveKey(secret: string, purpose: string): Promise<Uint8Array> {
  if (typeof secret !== 'string' || secret.length < 32) throw new ConfigurationError('Session secret must be at least 32 random characters.');
  const base = await crypto.subtle.importKey('raw', enc.encode(secret), 'HKDF', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: enc.encode('identvia-js-session-v1'), info: enc.encode(purpose) }, base, 256);
  return new Uint8Array(bits);
}

/** Authenticated encryption (JWE dir + A256GCM). Tampered or foreign cookies fail to open. */
export async function seal(payload: Record<string, unknown>, key: Uint8Array, maxAgeSec: number): Promise<string> {
  return new EncryptJWT(payload).setProtectedHeader({ alg: 'dir', enc: 'A256GCM' }).setIssuedAt().setExpirationTime(`${maxAgeSec}s`).encrypt(key);
}

export async function unseal<T>(token: string | undefined, key: Uint8Array): Promise<T | null> {
  if (!token) return null;
  try {
    const { payload } = await jwtDecrypt(token, key, { keyManagementAlgorithms: ['dir'], contentEncryptionAlgorithms: ['A256GCM'] });
    return payload as T;
  } catch { return null; }
}

export function parseCookies(header: string | null | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  if (!header) return out;
  for (const part of header.split(';')) {
    const i = part.indexOf('=');
    if (i < 0) continue;
    const k = part.slice(0, i).trim();
    if (!k || k in out) continue;
    try { out[k] = decodeURIComponent(part.slice(i + 1).trim()); } catch { /* skip */ }
  }
  return out;
}

export interface CookieOptions { secure: boolean; maxAge?: number; path?: string; sameSite?: 'Lax' | 'Strict' }

export function serializeCookie(name: string, value: string, o: CookieOptions): string {
  let c = `${name}=${encodeURIComponent(value)}; Path=${o.path ?? '/'}; HttpOnly; SameSite=${o.sameSite ?? 'Lax'}`;
  if (o.secure) c += '; Secure';
  if (o.maxAge !== undefined) c += `; Max-Age=${Math.max(0, Math.floor(o.maxAge))}`;
  return c;
}

const CHUNK = 3800;

/** Splits a long sealed value across `name.0`, `name.1`, ... (browsers cap cookies near 4 KB). */
export function chunkCookies(name: string, value: string, o: CookieOptions, existing: Record<string, string>): string[] {
  const parts: string[] = [];
  for (let i = 0; i < value.length; i += CHUNK) parts.push(value.slice(i, i + CHUNK));
  const out = parts.map((p, i) => serializeCookie(`${name}.${i}`, p, o));
  for (const k of Object.keys(existing)) {
    const m = k.startsWith(`${name}.`) ? Number(k.slice(name.length + 1)) : NaN;
    if (Number.isInteger(m) && m >= parts.length) out.push(serializeCookie(k, '', { ...o, maxAge: 0 }));
  }
  return out;
}

export function readChunked(name: string, cookies: Record<string, string>): string | undefined {
  let v = '';
  for (let i = 0; i < 20; i++) {
    const p = cookies[`${name}.${i}`];
    if (p === undefined) break;
    v += p;
  }
  return v === '' ? undefined : v;
}

export function clearChunked(name: string, cookies: Record<string, string>, o: CookieOptions): string[] {
  return Object.keys(cookies).filter((k) => k.startsWith(`${name}.`)).map((k) => serializeCookie(k, '', { ...o, maxAge: 0 }));
}

export { base64url };
