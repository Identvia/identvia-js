import { ConfigurationError } from './errors.js';

const LOOPBACK = new Set(['localhost', '127.0.0.1', '[::1]']);

export function isLoopback(u: URL): boolean {
  return LOOPBACK.has(u.hostname) || u.hostname === '::1';
}

/**
 * Issuers must be https (http only on loopback for local development), have no query or fragment
 * and no trailing slash, exactly like the `iss` Identvia puts in tokens.
 */
export function normalizeIssuer(issuer: string): string {
  let u: URL;
  try { u = new URL(issuer); } catch { throw new ConfigurationError(`issuer "${issuer}" is not a valid URL.`); }
  if (u.protocol !== 'https:' && !(u.protocol === 'http:' && isLoopback(u))) throw new ConfigurationError('issuer must use https:// (http:// is only allowed for localhost).');
  if (u.search || u.hash || u.username || u.password) throw new ConfigurationError('issuer must not contain a query, fragment or credentials.');
  return issuer.replace(/\/+$/, '');
}

/**
 * Redirect URIs for web clients: https, or http on loopback (development). No fragments, no credentials.
 * Native apps may also pass a private-use reverse-domain scheme (com.example.app:/callback) with `allowCustomScheme`.
 */
export function assertRedirectUri(uri: string, name = 'redirectUri', allowCustomScheme = false): string {
  let u: URL;
  try { u = new URL(uri); } catch { throw new ConfigurationError(`${name} "${uri}" is not an absolute URL.`); }
  if (u.hash || uri.includes('#')) throw new ConfigurationError(`${name} must not contain a #fragment.`);
  if (u.username || u.password) throw new ConfigurationError(`${name} must not contain credentials.`);
  if (u.protocol === 'https:') return uri;
  if (u.protocol === 'http:' && isLoopback(u)) return uri;
  const scheme = u.protocol.slice(0, -1);
  if (allowCustomScheme && /^[a-z][a-z0-9+\-]*(\.[a-z0-9+\-]+)+$/.test(scheme)) return uri;
  throw new ConfigurationError(`${name} must use https:// (http:// only for localhost${allowCustomScheme ? ', or a reverse-domain app scheme such as com.example.app:/callback' : ''}).`);
}

/** Only same-origin relative paths ("/dashboard?tab=1"), so `returnTo` can never become an open redirect. */
export function safeReturnTo(to: unknown): string | undefined {
  if (typeof to !== 'string' || to === '' || to.length > 2000) return undefined;
  if (!to.startsWith('/') || to.startsWith('//') || to.startsWith('/\\')) return undefined;
  if (/[\u0000-\u001f\u007f\\]/.test(to)) return undefined;
  return to;
}

export function withQuery(endpoint: string, params: Record<string, string | undefined>): string {
  const u = new URL(endpoint);
  for (const [k, v] of Object.entries(params)) if (v !== undefined) u.searchParams.set(k, v);
  return u.toString();
}
