import type { IdTokenClaims } from '../core/idtoken.js';
import { OidcClient, type AuthorizeOptions, type AuthTransaction, type OidcConfig } from '../core/oidc.js';
import { AuthorizationError, ConfigurationError, IdentviaError, InvalidStateError, TokenError } from '../core/errors.js';
import { isExpired, type TokenSet } from '../core/tokens.js';
import { resolveStorage, transactionStorage, type KeyValueStorage, type TokenStorageOption } from './storage.js';

export interface IdentviaClientOptions extends OidcConfig {
  /** Where tokens are kept. Default 'memory'. See TokenStorageOption. */
  storage?: TokenStorageOption;
  /** Where the in-flight sign-in (state, nonce, PKCE verifier) is kept. Default sessionStorage. */
  transactionStorage?: KeyValueStorage;
  /** Redirect URI of the page that calls `IdentviaClient.handlePopupCallback()`. Defaults to redirectUri. */
  popupRedirectUri?: string;
  /** Refresh this many seconds before the access token expires. Default 60. */
  refreshLeewaySec?: number;
  /** Default post-logout redirect (must be registered). */
  postLogoutRedirectUri?: string;
}

export interface Session {
  user: IdTokenClaims;
  tokens: TokenSet;
}

export type AuthEvent = { type: 'signedIn'; session: Session } | { type: 'tokensRefreshed'; session: Session } | { type: 'signedOut'; reason: 'user' | 'refresh_failed' | 'other_tab' };

const MSG = 'identvia:callback';

/**
 * Browser (SPA) client for Identvia. Public client only: Authorization Code + PKCE (S256), state and nonce,
 * RFC 9207 iss check, ID token validation against the JWKS, refresh-token rotation with a cross-tab lock.
 */
export class IdentviaClient {
  readonly oidc: OidcClient;
  private readonly storage: KeyValueStorage;
  private readonly txStorage: KeyValueStorage;
  private readonly key: string;
  private readonly leewayMs: number;
  private readonly popupRedirectUri: string;
  private readonly postLogoutRedirectUri: string | undefined;
  private readonly listeners = new Set<(e: AuthEvent) => void>();
  private refreshing: Promise<Session | null> | undefined;
  private cached: Session | null | undefined;

  constructor(opts: IdentviaClientOptions) {
    if ((opts as { clientSecret?: unknown }).clientSecret !== undefined) {
      throw new ConfigurationError('Never put a client secret in browser code: anyone can read it. Register a public (SPA) client, or use @identvia/js/server on your backend.');
    }
    this.oidc = new OidcClient({ ...opts });
    this.storage = resolveStorage(opts.storage);
    this.txStorage = opts.transactionStorage ?? transactionStorage();
    this.key = `identvia:${this.oidc.clientId}`;
    this.leewayMs = (opts.refreshLeewaySec ?? 60) * 1000;
    this.popupRedirectUri = opts.popupRedirectUri ?? this.oidc.redirectUri;
    this.postLogoutRedirectUri = opts.postLogoutRedirectUri;
    const w = globalThis as { addEventListener?: (t: string, f: (e: StorageEvent) => void) => void };
    if (opts.storage === 'local' && typeof w.addEventListener === 'function') {
      w.addEventListener('storage', (e) => {
        if (e.key !== `${this.key}:session`) return;
        this.cached = undefined;
        if (e.newValue === null) this.emit({ type: 'signedOut', reason: 'other_tab' });
      });
    }
  }

  // ---------------------------------------------------------------- events
  subscribe(fn: (e: AuthEvent) => void): () => void { this.listeners.add(fn); return () => this.listeners.delete(fn); }
  private emit(e: AuthEvent) { for (const l of this.listeners) { try { l(e); } catch { /* listener errors are theirs */ } } }

  // ---------------------------------------------------------------- session storage
  async getSession(): Promise<Session | null> {
    if (this.cached !== undefined) return this.cached;
    const raw = await this.storage.getItem(`${this.key}:session`);
    let s: Session | null = null;
    if (raw) { try { s = JSON.parse(raw) as Session; } catch { s = null; } }
    this.cached = s;
    return s;
  }
  private async saveSession(s: Session | null) {
    this.cached = s;
    if (s) await this.storage.setItem(`${this.key}:session`, JSON.stringify(s));
    else await this.storage.removeItem(`${this.key}:session`);
  }
  async getUser(): Promise<IdTokenClaims | null> { return (await this.getSession())?.user ?? null; }
  async isAuthenticated(): Promise<boolean> {
    const s = await this.getSession();
    if (!s) return false;
    return !isExpired(s.tokens, 0, Date.now()) || !!s.tokens.refreshToken;
  }

  // ---------------------------------------------------------------- redirect flow
  async signInWithRedirect(opts: AuthorizeOptions = {}): Promise<void> {
    const { url, transaction } = await this.oidc.createAuthorizationRequest(opts);
    await this.txStorage.setItem(`${this.key}:tx:${transaction.state}`, JSON.stringify(transaction));
    (globalThis as unknown as { location: Location }).location.assign(url);
  }

  /** Also usable to build the URL yourself (e.g. for a native shell). Stores the transaction. */
  async buildAuthorizeUrl(opts: AuthorizeOptions = {}): Promise<string> {
    const { url, transaction } = await this.oidc.createAuthorizationRequest(opts);
    await this.txStorage.setItem(`${this.key}:tx:${transaction.state}`, JSON.stringify(transaction));
    return url;
  }

  static isRedirectCallback(url: string = (globalThis as unknown as { location: Location }).location.href): boolean {
    const u = new URL(url);
    return u.searchParams.has('state') && (u.searchParams.has('code') || u.searchParams.has('error'));
  }

  /** Call on your redirect URI page. Validates everything, stores the session, and strips the code from the address bar. */
  async handleRedirectCallback(url: string = (globalThis as unknown as { location: Location }).location.href): Promise<{ user: IdTokenClaims; returnTo?: string }> {
    const u = new URL(url);
    const state = u.searchParams.get('state') ?? '';
    const tx = await this.takeTransaction(state);
    this.cleanUrl(u);
    const r = await this.oidc.completeAuthorization(u.searchParams, tx);
    const session: Session = { user: r.claims, tokens: r.tokens };
    await this.saveSession(session);
    this.emit({ type: 'signedIn', session });
    return r.returnTo ? { user: r.claims, returnTo: r.returnTo } : { user: r.claims };
  }

  private async takeTransaction(state: string): Promise<AuthTransaction | undefined> {
    if (!/^[A-Za-z0-9_-]{16,512}$/.test(state)) return undefined;
    const k = `${this.key}:tx:${state}`;
    const raw = await this.txStorage.getItem(k);
    await this.txStorage.removeItem(k); // single use, even if validation fails later
    if (!raw) return undefined;
    try { return JSON.parse(raw) as AuthTransaction; } catch { return undefined; }
  }

  private cleanUrl(u: URL) {
    const h = (globalThis as { history?: History }).history;
    if (!h || typeof h.replaceState !== 'function') return;
    const loc = (globalThis as unknown as { location?: Location }).location;
    if (!loc || loc.href !== u.href) return;
    const clean = new URL(u.href);
    for (const k of ['code', 'state', 'iss', 'error', 'error_description', 'error_uri', 'session_state']) clean.searchParams.delete(k);
    try { h.replaceState(h.state, '', clean.pathname + clean.search + clean.hash); } catch { /* ignore */ }
  }

  // ---------------------------------------------------------------- popup flow
  /**
   * Opens Identvia in a popup. Call it directly from a click handler (browsers block popups otherwise).
   * The popup's redirect page must call `IdentviaClient.handlePopupCallback()`.
   */
  async signInWithPopup(opts: AuthorizeOptions & { timeoutSec?: number; popup?: Window } = {}): Promise<{ user: IdTokenClaims }> {
    const w = globalThis as unknown as Window;
    const width = 480, height = 720;
    const left = Math.max(0, (w.screenX ?? 0) + ((w.outerWidth ?? width) - width) / 2);
    const top = Math.max(0, (w.screenY ?? 0) + ((w.outerHeight ?? height) - height) / 2);
    const popup = opts.popup ?? w.open('', 'identvia-signin', `popup=yes,width=${width},height=${height},left=${left},top=${top}`);
    if (!popup) throw new IdentviaError('popup_blocked', 'The browser blocked the sign-in popup. Call signInWithPopup() directly from a click, or use signInWithRedirect().');
    let tx: AuthTransaction;
    try {
      const req = await this.oidc.createAuthorizationRequest({ ...opts, redirectUri: opts.redirectUri ?? this.popupRedirectUri });
      tx = req.transaction;
      popup.location.href = req.url;
    } catch (e) { try { popup.close(); } catch { /* */ } throw e; }

    const callbackUrl = await new Promise<string>((resolve, reject) => {
      const origin = w.location.origin;
      let channel: BroadcastChannel | undefined;
      const done = (fn: () => void) => { cleanup(); fn(); };
      const onMessage = (ev: MessageEvent) => {
        if (ev.origin !== origin || ev.source !== popup) return;
        const d = ev.data as { type?: string; url?: string };
        if (d?.type !== MSG || typeof d.url !== 'string') return;
        done(() => resolve(d.url!));
      };
      const onChannel = (ev: MessageEvent) => {
        const d = ev.data as { type?: string; url?: string };
        if (d?.type !== MSG || typeof d.url !== 'string') return;
        // No source to check over BroadcastChannel (same-origin only); the unguessable state binds it to this sign-in.
        try { if (new URL(d.url).searchParams.get('state') !== tx.state) return; } catch { return; }
        done(() => resolve(d.url!));
      };
      const poll = setInterval(() => { try { if (popup.closed) done(() => reject(new IdentviaError('popup_closed', 'The sign-in window was closed.'))); } catch { /* COOP */ } }, 500);
      const timeout = setTimeout(() => done(() => reject(new IdentviaError('popup_timeout', 'Sign-in timed out.'))), (opts.timeoutSec ?? 300) * 1000);
      const cleanup = () => {
        clearInterval(poll); clearTimeout(timeout);
        w.removeEventListener('message', onMessage);
        channel?.close();
        try { popup.close(); } catch { /* */ }
      };
      w.addEventListener('message', onMessage);
      if (typeof BroadcastChannel === 'function') { channel = new BroadcastChannel(`identvia:${this.oidc.clientId}`); channel.onmessage = onChannel; }
    });

    const u = new URL(callbackUrl);
    if (u.origin !== w.location.origin) throw new InvalidStateError('Popup returned to an unexpected origin.');
    const r = await this.oidc.completeAuthorization(u.searchParams, tx);
    const session: Session = { user: r.claims, tokens: r.tokens };
    await this.saveSession(session);
    this.emit({ type: 'signedIn', session });
    return { user: r.claims };
  }

  /** Run on the popup redirect page. Hands the response to the opener and closes the popup. */
  static handlePopupCallback(clientId: string): void {
    const w = globalThis as unknown as Window;
    const url = w.location.href;
    const msg = { type: MSG, url };
    try { w.opener?.postMessage(msg, w.location.origin); } catch { /* */ }
    try { const c = new BroadcastChannel(`identvia:${clientId}`); c.postMessage(msg); c.close(); } catch { /* */ }
    try { w.history.replaceState(null, '', w.location.pathname); } catch { /* */ }
    setTimeout(() => w.close(), 50);
  }

  // ---------------------------------------------------------------- tokens
  /**
   * Returns a valid access token, refreshing it (with rotation) when it is about to expire.
   * Throws TokenError('login_required') if the user must sign in again.
   */
  async getAccessToken(opts: { forceRefresh?: boolean } = {}): Promise<string> {
    let s = await this.getSession();
    if (!s) throw new TokenError('login_required', 'Not signed in.', 401);
    if (!opts.forceRefresh && !isExpired(s.tokens, this.leewayMs, Date.now())) return s.tokens.accessToken;
    s = await this.refreshSession(opts.forceRefresh ?? false);
    if (!s) throw new TokenError('login_required', 'Your session ended. Please sign in again.', 401);
    return s.tokens.accessToken;
  }

  /** Single-flight within the tab, and serialised across tabs with the Web Locks API when available. */
  refreshSession(force = false): Promise<Session | null> {
    if (!this.refreshing) {
      const run = async (): Promise<Session | null> => {
        this.cached = undefined; // another tab may have rotated already
        const s = await this.getSession();
        if (!s) return null;
        if (!force && !isExpired(s.tokens, this.leewayMs, Date.now())) return s;
        const rt = s.tokens.refreshToken;
        if (!rt) { await this.saveSession(null); this.emit({ type: 'signedOut', reason: 'refresh_failed' }); return null; }
        try {
          const { tokens, claims } = await this.oidc.refresh(rt, s.user.sub);
          if (!tokens.refreshToken) tokens.refreshToken = rt; // server chose not to rotate this time
          if (!tokens.idToken) tokens.idToken = s.tokens.idToken;
          const next: Session = { user: claims ?? s.user, tokens };
          await this.saveSession(next);
          this.emit({ type: 'tokensRefreshed', session: next });
          return next;
        } catch (e) {
          if (e instanceof TokenError && (e.error === 'invalid_grant' || e.error === 'invalid_client' || e.status === 401)) {
            await this.saveSession(null);
            this.emit({ type: 'signedOut', reason: 'refresh_failed' });
            return null;
          }
          throw e;
        }
      };
      const locks = (globalThis as { navigator?: { locks?: { request: (n: string, f: () => Promise<unknown>) => Promise<unknown> } } }).navigator?.locks;
      const p = locks ? (locks.request(`${this.key}:refresh`, run) as Promise<Session | null>) : run();
      this.refreshing = p.finally(() => { this.refreshing = undefined; });
    }
    return this.refreshing;
  }

  async fetchUserInfo(): Promise<Record<string, unknown> & { sub: string }> {
    const s = await this.getSession();
    return this.oidc.userinfo(await this.getAccessToken(), s?.user.sub);
  }

  /**
   * Signs out of this app: revokes the refresh token (best effort) and clears storage.
   * `federated: true` also ends the Identvia session via RP-initiated logout (navigates away).
   */
  async signOut(opts: { federated?: boolean; postLogoutRedirectUri?: string } = {}): Promise<void> {
    const s = await this.getSession();
    await this.saveSession(null);
    if (s) {
      try {
        if (s.tokens.refreshToken) await this.oidc.revoke(s.tokens.refreshToken, 'refresh_token');
        else await this.oidc.revoke(s.tokens.accessToken, 'access_token');
      } catch { /* the local session is gone either way */ }
    }
    this.emit({ type: 'signedOut', reason: 'user' });
    if (opts.federated) {
      const target = opts.postLogoutRedirectUri ?? this.postLogoutRedirectUri;
      const url = await this.oidc.endSessionUrl({ ...(s?.tokens.idToken ? { idTokenHint: s.tokens.idToken } : {}), ...(target ? { postLogoutRedirectUri: target } : {}) });
      (globalThis as unknown as { location: Location }).location.assign(url);
    }
  }
}

export { AuthorizationError };
