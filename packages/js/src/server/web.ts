import { AuthorizationError, ConfigurationError, IdentviaError, InvalidStateError, TokenError } from '../core/errors.js';
import type { IdTokenClaims } from '../core/idtoken.js';
import type { AuthorizeOptions, AuthTransaction } from '../core/oidc.js';
import { safeReturnTo } from '../core/urls.js';
import { IdentviaServerClient, type IdentviaServerOptions } from './client.js';
import { chunkCookies, clearChunked, deriveKey, parseCookies, readChunked, seal, serializeCookie, unseal, type CookieOptions } from './session.js';

export interface IdentviaAuthOptions extends IdentviaServerOptions {
  /** ≥ 32 random characters, used to encrypt the session and sign-in cookies. */
  secret: string;
  /** Where the routes live. Default '/auth' → /auth/login, /auth/logout, /auth/session. The callback is redirectUri's path. */
  basePath?: string;
  /** Session lifetime in seconds. Default 7 days (rolling on refresh). */
  sessionMaxAgeSec?: number;
  /** Keep access/refresh tokens in the encrypted session (needed for userinfo / calling APIs / refresh). Default true. */
  storeTokens?: boolean;
  /** Where to send people after sign-in when no returnTo was given. Default '/'. */
  defaultReturnTo?: string;
  /** Also sign out of Identvia (RP-initiated logout) on /auth/logout. Default false. */
  federatedLogout?: boolean;
  postLogoutRedirectUri?: string;
  /** Default authorization options for /auth/login (prompt, maxAge, authorizationDetails...). */
  authorizeParams?: AuthorizeOptions;
  /** Render your own error page. Default: plain 400 text, no details leaked. */
  onError?: (error: unknown, req: Request) => Response | Promise<Response>;
}

export interface IdentviaSession {
  user: Pick<IdTokenClaims, 'sub' | 'email' | 'email_verified' | 'name' | 'given_name' | 'family_name' | 'picture' | 'auth_time' | 'amr'>;
  idToken?: string;
  accessToken?: string;
  refreshToken?: string;
  /** Access token expiry, epoch ms. */
  expiresAt?: number;
}

export interface CookieSource { get(name: string): { value: string } | string | undefined | null }

const USER_CLAIMS = ['sub', 'email', 'email_verified', 'name', 'given_name', 'family_name', 'picture', 'auth_time', 'amr'] as const;

/** Framework-neutral server auth using Web Request/Response. Express and Next.js adapters are thin wrappers. */
export class IdentviaAuth {
  readonly client: IdentviaServerClient;
  private readonly o: IdentviaAuthOptions;
  private readonly basePath: string;
  private readonly callbackPath: string;
  private readonly origin: string;
  private readonly cookie: CookieOptions;
  private readonly sessionName: string;
  private readonly txPrefix: string;
  private keys: Promise<{ session: Uint8Array; tx: Uint8Array }>;

  constructor(o: IdentviaAuthOptions) {
    if (typeof o.secret !== 'string' || o.secret.length < 32) throw new ConfigurationError('`secret` must be at least 32 random characters (e.g. `openssl rand -base64 48`).');
    this.client = new IdentviaServerClient(o);
    this.o = o;
    this.basePath = (o.basePath ?? '/auth').replace(/\/+$/, '');
    const ru = new URL(this.client.redirectUri);
    this.callbackPath = ru.pathname;
    this.origin = ru.origin;
    const secure = ru.protocol === 'https:';
    this.cookie = { secure, path: '/', sameSite: 'Lax' };
    // __Host- prefix: Secure, Path=/, no Domain — the browser enforces it can't be set by a sibling subdomain.
    this.sessionName = secure ? '__Host-idv_session' : 'idv_session';
    this.txPrefix = secure ? '__Host-idv_tx_' : 'idv_tx_';
    this.keys = Promise.all([deriveKey(o.secret, 'session'), deriveKey(o.secret, 'tx')]).then(([session, tx]) => ({ session, tx }));
    this.keys.catch(() => undefined);
  }

  get routes() {
    return { login: `${this.basePath}/login`, logout: `${this.basePath}/logout`, session: `${this.basePath}/session`, callback: this.callbackPath };
  }

  /** Handles login/callback/logout/session; returns null for other paths so you can fall through. */
  async handle(req: Request): Promise<Response | null> {
    const url = new URL(req.url);
    const r = this.routes;
    try {
      if (url.pathname === r.login && req.method === 'GET') return await this.login(req);
      if (url.pathname === r.callback && req.method === 'GET') return await this.callback(req);
      if (url.pathname === r.logout) return await this.logout(req);
      if (url.pathname === r.session && req.method === 'GET') return await this.sessionJson(req);
    } catch (e) {
      return this.error(e, req);
    }
    return null;
  }

  async login(req: Request, opts: AuthorizeOptions = {}): Promise<Response> {
    const url = new URL(req.url);
    const returnTo = safeReturnTo(url.searchParams.get('returnTo') ?? url.searchParams.get('return_to') ?? undefined) ?? safeReturnTo(this.o.defaultReturnTo) ?? '/';
    const { url: authorizeUrl, transaction } = await this.client.createAuthorizationRequest({ ...this.o.authorizeParams, ...opts, returnTo });
    const sealed = await seal(transaction as unknown as Record<string, unknown>, (await this.keys).tx, 900);
    return redirect(authorizeUrl, [serializeCookie(this.txName(transaction.state), sealed, { ...this.cookie, maxAge: 900 })]);
  }

  async callback(req: Request): Promise<Response> {
    const url = new URL(req.url);
    const cookies = parseCookies(req.headers.get('cookie'));
    const state = url.searchParams.get('state') ?? '';
    const name = /^[A-Za-z0-9_-]{16,512}$/.test(state) ? this.txName(state) : undefined;
    const tx = name ? await unseal<AuthTransaction>(cookies[name], (await this.keys).tx) : null;
    const clearTx = name ? [serializeCookie(name, '', { ...this.cookie, maxAge: 0 })] : [];
    try {
      const r = await this.client.completeAuthorization(url.searchParams, tx ?? undefined);
      const session = this.toSession(r.claims, r.tokens);
      const set = await this.sessionCookies(session, cookies);
      return redirect(new URL(r.returnTo ?? '/', this.origin).toString(), [...clearTx, ...set]);
    } catch (e) {
      const res = await this.error(e, req);
      const h = new Headers(res.headers);
      for (const c of clearTx) h.append('Set-Cookie', c);
      return new Response(res.body, { status: res.status, headers: h });
    }
  }

  async logout(req: Request): Promise<Response> {
    if (req.method !== 'POST') return new Response('Use POST to sign out.', { status: 405, headers: { Allow: 'POST' } });
    if (!this.sameOrigin(req)) return new Response('Cross-site sign-out blocked.', { status: 403 });
    const cookies = parseCookies(req.headers.get('cookie'));
    const s = await this.readSession(cookies);
    if (s?.refreshToken) { try { await this.client.revoke(s.refreshToken, 'refresh_token'); } catch { /* best effort */ } }
    else if (s?.accessToken) { try { await this.client.revoke(s.accessToken, 'access_token'); } catch { /* */ } }
    const clear = clearChunked(this.sessionName, cookies, this.cookie);
    let target = new URL('/', this.origin).toString();
    if (this.o.federatedLogout) {
      target = await this.client.endSessionUrl({ ...(s?.idToken ? { idTokenHint: s.idToken } : {}), ...(this.o.postLogoutRedirectUri ? { postLogoutRedirectUri: this.o.postLogoutRedirectUri } : {}) });
    }
    return redirect(target, clear, 303);
  }

  private async sessionJson(req: Request): Promise<Response> {
    const { session, setCookies } = await this.getFreshSession(req.headers.get('cookie'));
    const h = new Headers({ 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
    for (const c of setCookies) h.append('Set-Cookie', c);
    return new Response(JSON.stringify({ user: session?.user ?? null }), { status: 200, headers: h });
  }

  // ------------------------------------------------------------- sessions
  /** Reads the session without refreshing (safe in React Server Components, which can't set cookies). */
  async getSession(source: string | null | undefined | CookieSource | Request): Promise<IdentviaSession | null> {
    return this.readSession(this.cookiesFrom(source));
  }

  /** Reads the session and refreshes the access token if it is about to expire. Apply `setCookies` to your response. */
  async getFreshSession(source: string | null | undefined | CookieSource | Request, leewaySec = 60): Promise<{ session: IdentviaSession | null; setCookies: string[] }> {
    const cookies = this.cookiesFrom(source);
    const s = await this.readSession(cookies);
    if (!s || !s.expiresAt || s.expiresAt - leewaySec * 1000 > Date.now()) return { session: s, setCookies: [] };
    if (!s.refreshToken) return { session: s, setCookies: [] };
    try {
      const { tokens, claims } = await this.client.refresh(s.refreshToken, s.user.sub);
      const next: IdentviaSession = { ...s, accessToken: tokens.accessToken, expiresAt: tokens.expiresAt, refreshToken: tokens.refreshToken ?? s.refreshToken, ...(tokens.idToken ? { idToken: tokens.idToken } : {}) };
      if (claims) next.user = pickUser(claims);
      return { session: next, setCookies: await this.sessionCookies(next, cookies) };
    } catch (e) {
      if (e instanceof TokenError && (e.error === 'invalid_grant' || e.status === 401)) {
        return { session: null, setCookies: clearChunked(this.sessionName, cookies, this.cookie) };
      }
      throw e;
    }
  }

  private cookiesFrom(source: string | null | undefined | CookieSource | Request): Record<string, string> {
    if (source === null || source === undefined) return {};
    if (typeof source === 'string') return parseCookies(source);
    if (typeof Request !== 'undefined' && source instanceof Request) return parseCookies(source.headers.get('cookie'));
    const out: Record<string, string> = {};
    const src = source as CookieSource;
    for (let i = 0; i < 20; i++) {
      const n = `${this.sessionName}.${i}`;
      const v = src.get(n);
      const s = typeof v === 'string' ? v : v?.value;
      if (s === undefined || s === null) break;
      out[n] = s;
    }
    return out;
  }

  private async readSession(cookies: Record<string, string>): Promise<IdentviaSession | null> {
    const raw = readChunked(this.sessionName, cookies);
    const s = await unseal<IdentviaSession & { iat?: number; exp?: number }>(raw, (await this.keys).session);
    if (!s || typeof s.user?.sub !== 'string') return null;
    delete s.iat; delete s.exp;
    return s;
  }

  private async sessionCookies(s: IdentviaSession, existing: Record<string, string>): Promise<string[]> {
    const max = this.o.sessionMaxAgeSec ?? 7 * 86400;
    const sealed = await seal(s as unknown as Record<string, unknown>, (await this.keys).session, max);
    return chunkCookies(this.sessionName, sealed, { ...this.cookie, maxAge: max }, existing);
  }

  private toSession(claims: IdTokenClaims, t: { accessToken: string; refreshToken?: string; idToken?: string; expiresAt: number }): IdentviaSession {
    const s: IdentviaSession = { user: pickUser(claims) };
    if (t.idToken) s.idToken = t.idToken;
    if (this.o.storeTokens !== false) {
      s.accessToken = t.accessToken;
      s.expiresAt = t.expiresAt;
      if (t.refreshToken) s.refreshToken = t.refreshToken;
    }
    return s;
  }

  private txName(state: string): string {
    return this.txPrefix + state.slice(0, 16);
  }

  private sameOrigin(req: Request): boolean {
    const site = req.headers.get('sec-fetch-site');
    if (site && site !== 'same-origin' && site !== 'none') return false;
    const origin = req.headers.get('origin');
    if (origin && origin !== this.origin) return false;
    return true;
  }

  private async error(e: unknown, req: Request): Promise<Response> {
    if (this.o.onError) return this.o.onError(e, req);
    const msg = e instanceof AuthorizationError && e.error === 'access_denied' ? 'Sign-in was cancelled.'
      : e instanceof InvalidStateError ? 'This sign-in link expired or was already used. Please start again.'
      : e instanceof IdentviaError ? 'Sign-in failed. Please try again.' : 'Something went wrong.';
    return new Response(msg, { status: 400, headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' } });
  }
}

function pickUser(c: IdTokenClaims): IdentviaSession['user'] {
  const u: Record<string, unknown> = {};
  for (const k of USER_CLAIMS) if (c[k] !== undefined) u[k] = c[k];
  return u as IdentviaSession['user'];
}

function redirect(location: string, cookies: string[], status = 302): Response {
  const h = new Headers({ Location: location, 'Cache-Control': 'no-store' });
  for (const c of cookies) h.append('Set-Cookie', c);
  return new Response(null, { status, headers: h });
}

export function createIdentviaAuth(o: IdentviaAuthOptions): IdentviaAuth { return new IdentviaAuth(o); }
