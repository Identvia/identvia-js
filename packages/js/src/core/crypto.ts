import { base64UrlEncode, utf8 } from './encoding.js';
import { ConfigurationError } from './errors.js';

function webCrypto(): Crypto {
  const c = (globalThis as { crypto?: Crypto }).crypto;
  if (!c || typeof c.getRandomValues !== 'function' || !c.subtle) {
    throw new ConfigurationError('Web Crypto is not available. Use a modern browser, Node 18+ or install a crypto polyfill.');
  }
  return c;
}

/** Cryptographically random base64url string from `bytes` random bytes. */
export function randomToken(bytes = 32): string {
  const b = new Uint8Array(bytes);
  webCrypto().getRandomValues(b);
  return base64UrlEncode(b);
}

export async function sha256(input: string): Promise<Uint8Array> {
  return new Uint8Array(await webCrypto().subtle.digest('SHA-256', utf8(input) as Uint8Array<ArrayBuffer>));
}

/** RFC 7636: a 64-character verifier (48 random bytes), within the 43–128 limit. */
export function createCodeVerifier(): string {
  return randomToken(48);
}

/** RFC 7636 §4.2, S256 only (Identvia rejects `plain`). */
export async function createCodeChallenge(verifier: string): Promise<string> {
  if (!/^[A-Za-z0-9\-._~]{43,128}$/.test(verifier)) throw new ConfigurationError('PKCE code_verifier must be 43–128 unreserved characters.');
  return base64UrlEncode(await sha256(verifier));
}

export interface Pkce { verifier: string; challenge: string; method: 'S256' }

export async function createPkce(): Promise<Pkce> {
  const verifier = createCodeVerifier();
  return { verifier, challenge: await createCodeChallenge(verifier), method: 'S256' };
}

/** OIDC Core §3.1.3.6 at_hash / §3.3.2.11 c_hash for RS256/ES256: left half of SHA-256, base64url. */
export async function leftHalfHash(value: string): Promise<string> {
  return base64UrlEncode((await sha256(value)).slice(0, 16));
}

/** Constant-time string comparison (both inputs are attacker-influenced in callbacks). */
export function timingSafeEqual(a: string, b: string): boolean {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const x = utf8(a);
  const y = utf8(b);
  let diff = x.length ^ y.length;
  const n = Math.max(x.length, y.length);
  for (let i = 0; i < n; i++) diff |= (x[i] ?? 0) ^ (y[i] ?? 0);
  return diff === 0;
}
