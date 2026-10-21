import { createCodeChallenge, createCodeVerifier, randomToken, timingSafeEqual } from './crypto.js';
import { DiscoveryCache, type DiscoveryDocument } from './discovery.js';
import { AuthorizationError, ConfigurationError, HttpError, InvalidStateError, TokenError, UnsupportedError, ValidationError } from './errors.js';
import { defaultFetch, postForm, requestJson, type FetchLike } from './http.js';
import { validateIdToken, type IdTokenClaims } from './idtoken.js';
import { JwksCache } from './jwks.js';
import { parseTokenResponse, type AuthorizationDetail, type TokenSet } from './tokens.js';
import { assertRedirectUri, normalizeIssuer, safeReturnTo, withQuery } from './urls.js';

export const DEFAULT_ISSUER = 'https://id.identvia.com';
export const SCOPES = ['openid', 'email', 'profile', 'offline_access', 'grants:read', 'grants:revoke', 'agent:request'] as const;

export interface OidcConfig {
  /** Default https://id.identvia.com */
  issuer?: string;
  clientId: string;
  redirectUri: string;
  /** `openid` is always added. Add `offline_access` to get a refresh token. */
  scopes?: string[];
  fetch?: FetchLike;
  clockToleranceSec?: number;
  /** Pre-fetched discovery document (skips one request; still validated). */
  discovery?: DiscoveryDocument;
  /** For tests. */
  now?: () => number;
}

export interface InternalConfig extends OidcConfig {
  clientSecret?: string;
  tokenEndpointAuthMethod?: 'client_secret_basic' | 'client_secret_post' | 'none';
  allowCustomScheme?: boolean;
}

export interface AuthorizeOptions {
  scopes?: string[];
  prompt?: 'none' | 'login' | 'consent';
  /** Seconds. The ID token's auth_time is checked against it. */
  maxAge?: number;
  loginHint?: string;
  uiLocales?: string[];
  /** Relative path to return to after sign-in ("/dashboard"). Anything else is dropped. */
  returnTo?: string;
  /** RFC 8707 resource indicator. Identvia's own MCP server is `${issuer}/mcp`. */
  resource?: string;
  /** RFC 9396 Rich Authorization Requests. Requires server 2026-10-21_5+. */
  authorizationDetails?: AuthorizationDetail[];
  /** Overrides the configured redirect URI (must be registered too), e.g. a popup callback page. */
  redirectUri?: string;
}

/** What you must keep between the redirect and the callback. Treat it as secret; single use. */
export interface AuthTransaction {
  state: string;
  nonce: string;
  codeVerifier: string;
  redirectUri: string;
  returnTo?: string;
  maxAge?: number;
  createdAt: number;
}

export interface SignInResult {
  tokens: TokenSet;
  claims: IdTokenClaims;
  returnTo?: string;
}

const TX_MAX_AGE_MS = 15 * 60_000;

export class OidcClient {
  readonly issuer: string;
  readonly clientId: string;
  readonly redirectUri: string;
  readonly scopes: string[];
  protected readonly fetchFn: FetchLike;
  protected readonly now: () => number;
  protected readonly discovery: DiscoveryCache;
  protected readonly jwks: JwksCache;
  protected readonly clientSecret: string | undefined;
  protected readonly authMethod: 'client_secret_basic' | 'client_secret_post' | 'none';
  private readonly tolerance: number;
  private readonly allowCustomScheme: boolean;

  constructor(cfg: InternalConfig) {
    if (!cfg || typeof cfg.clientId !== 'string' || cfg.clientId.trim() === '') throw new ConfigurationError('clientId is required.');
    this.issuer = normalizeIssuer(cfg.issuer ?? DEFAULT_ISSUER);
    this.clientId = cfg.clientId;
    this.allowCustomScheme = !!cfg.allowCustomScheme;
    this.redirectUri = assertRedirectUri(cfg.redirectUri, 'redirectUri', this.allowCustomScheme);
    this.scopes = uniqueScopes(cfg.scopes ?? ['email', 'profile']);
    this.fetchFn = cfg.fetch ?? defaultFetch();
    this.now = cfg.now ?? Date.now;
    this.tolerance = cfg.clockToleranceSec ?? 60;
    this.clientSecret = cfg.clientSecret;
    this.authMethod = cfg.clientSecret ? (cfg.tokenEndpointAuthMethod === 'client_secret_post' ? 'client_secret_post' : 'client_secret_basic') : 'none';
    this.discovery = new DiscoveryCache(this.issuer, this.fetchFn, 3600_000, this.now, cfg.discovery);
    this.jwks = new JwksCache(() => this.discovery.endpoint('jwks_uri'), this.fetchFn, 3600_000, 30_000, this.now);
  }

  getDiscovery(): Promise<DiscoveryDocument> { return this.discovery.get(); }

  /** Builds the authorization URL (code flow, PKCE S256, state, nonce) and the transaction to keep until the callback. */
  async createAuthorizationRequest(opts: AuthorizeOptions = {}): Promise<{ url: string; transaction: AuthTransaction }> {
    const redirectUri = opts.redirectUri ? assertRedirectUri(opts.redirectUri, 'redirectUri', this.allowCustomScheme) : this.redirectUri;
    const state = randomToken(32);
    const nonce = randomToken(32);
    const codeVerifier = createCodeVerifier();
    const scopes = opts.scopes ? uniqueScopes(opts.scopes) : this.scopes;
    if (opts.prompt !== undefined && !['none', 'login', 'consent'].includes(opts.prompt)) throw new ConfigurationError('prompt must be none, login or consent.');
    const maxAge = opts.maxAge !== undefined ? Math.max(0, Math.floor(opts.maxAge)) : undefined;
    const doc = await this.discovery.get();
    let details: string | undefined;
    if (opts.authorizationDetails !== undefined) {
      details = encodeAuthorizationDetails(opts.authorizationDetails, doc);
    }
    const url = withQuery(doc.authorization_endpoint, {
      response_type: 'code',
      client_id: this.clientId,
      redirect_uri: redirectUri,
      scope: scopes.join(' '),
      state,
      nonce,
      code_challenge: await createCodeChallenge(codeVerifier),
      code_challenge_method: 'S256',
      prompt: opts.prompt,
      max_age: maxAge !== undefined ? String(maxAge) : undefined,
      login_hint: opts.loginHint?.slice(0, 254),
      ui_locales: opts.uiLocales?.join(' '),
      resource: opts.resource,
      authorization_details: details,
    });
    const transaction: AuthTransaction = { state, nonce, codeVerifier, redirectUri, createdAt: this.now() };
    const rt = safeReturnTo(opts.returnTo);
    if (rt) transaction.returnTo = rt;
    if (maxAge !== undefined) transaction.maxAge = maxAge;
    return { url, transaction };
  }

  /**
   * Completes the code flow on the redirect URI. `params` are the callback query parameters; `tx` is the
   * transaction you stored for the returned state (look it up by `params.get('state')`, then delete it).
   */
  async completeAuthorization(params: URLSearchParams | Record<string, string>, tx: AuthTransaction | undefined): Promise<SignInResult> {
    const p = params instanceof URLSearchParams ? params : new URLSearchParams(params);
    const state = p.get('state');
    if (!state || state.length > 512) throw new InvalidStateError('The sign-in response has no state. Start again.');
    if (!tx || !timingSafeEqual(tx.state, state)) throw new InvalidStateError('This sign-in response does not match a sign-in this app started (expired, reused or forged). Start again.');
    if (this.now() - tx.createdAt > TX_MAX_AGE_MS) throw new InvalidStateError('This sign-in took too long. Start again.');
    // RFC 9207 mix-up defence
    const iss = p.get('iss');
    if (iss !== null) {
      if (iss !== this.issuer) throw new InvalidStateError('The sign-in response came from a different issuer.');
    } else if ((await this.discovery.get()).authorization_response_iss_parameter_supported) {
      throw new InvalidStateError('The sign-in response is missing the iss parameter.');
    }
    const error = p.get('error');
    if (error) throw new AuthorizationError(error.slice(0, 100), p.get('error_description')?.slice(0, 500) ?? undefined, tx.returnTo);
    const code = p.get('code');
    if (!code || code.length > 2048) throw new InvalidStateError('The sign-in response has no authorization code.');
    const tokens = await this.tokenRequest({ grant_type: 'authorization_code', code, redirect_uri: tx.redirectUri, code_verifier: tx.codeVerifier });
    if (!tokens.idToken) throw new ValidationError('Identvia did not return an ID token (is the openid scope allowed?).');
    const claims = await this.validateIdToken(tokens.idToken, { nonce: tx.nonce, requireNonce: true, maxAge: tx.maxAge, accessToken: tokens.accessToken });
    const out: SignInResult = { tokens, claims };
    if (tx.returnTo) out.returnTo = tx.returnTo;
    return out;
  }

  validateIdToken(jwt: string, opts: { nonce?: string; requireNonce?: boolean; maxAge?: number; accessToken?: string } = {}): Promise<IdTokenClaims> {
    return validateIdToken(jwt, { issuer: this.issuer, clientId: this.clientId, getKey: this.jwks.getKey, clockToleranceSec: this.tolerance, now: this.now, ...stripUndefined(opts) });
  }

  /**
   * Refresh-token grant. Identvia ROTATES refresh tokens: persist `tokens.refreshToken` and discard the old one.
   * Presenting an old one again is treated as theft and revokes the whole chain (`invalid_grant`).
   */
  async refresh(refreshToken: string, expectedSub?: string): Promise<{ tokens: TokenSet; claims?: IdTokenClaims }> {
    if (!refreshToken) throw new ConfigurationError('refreshToken is required.');
    const tokens = await this.tokenRequest({ grant_type: 'refresh_token', refresh_token: refreshToken });
    if (!tokens.idToken) return { tokens };
    const claims = await this.validateIdToken(tokens.idToken, { accessToken: tokens.accessToken });
    if (expectedSub !== undefined && claims.sub !== expectedSub) throw new ValidationError('Refreshed ID token is for a different user.');
    return { tokens, claims };
  }

  /**
   * `transport: 'body'` sends the token as a form parameter (RFC 6750 §2.2) in a CORS "simple" POST. Browsers use it
   * because an Authorization header triggers a preflight, which Identvia servers up to 2026-10-21_4 do not answer.
   */
  async userinfo(accessToken: string, expectedSub?: string, transport: 'header' | 'body' = 'header'): Promise<Record<string, unknown> & { sub: string }> {
    const ep = await this.discovery.endpoint('userinfo_endpoint');
    const init = transport === 'body'
      ? { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' }, body: new URLSearchParams({ access_token: accessToken }).toString() }
      : { headers: { Authorization: `Bearer ${accessToken}`, Accept: 'application/json' } };
    const { status, data } = await requestJson(this.fetchFn, ep, init);
    if (status === 401) throw new TokenError('invalid_token', 'The access token is invalid or expired.', 401);
    if (status !== 200) throw new HttpError(`Userinfo request failed (HTTP ${status}).`, status);
    if (typeof data.sub !== 'string') throw new ValidationError('Userinfo response has no sub.');
    if (expectedSub !== undefined && !timingSafeEqual(expectedSub, data.sub)) throw new ValidationError('Userinfo is for a different user than the ID token.');
    return data as Record<string, unknown> & { sub: string };
  }

  /** RFC 7009. Revoking a refresh token also revokes access tokens from the same grant. */
  async revoke(token: string, hint: 'refresh_token' | 'access_token' = 'refresh_token'): Promise<void> {
    const ep = await this.discovery.endpoint('revocation_endpoint');
    await this.post(ep, { token, token_type_hint: hint }, false);
  }

  /** RP-initiated logout URL. `postLogoutRedirectUri` must be registered for the app. */
  async endSessionUrl(opts: { idTokenHint?: string; postLogoutRedirectUri?: string; state?: string } = {}): Promise<string> {
    const ep = await this.discovery.endpoint('end_session_endpoint');
    if (opts.postLogoutRedirectUri) assertRedirectUri(opts.postLogoutRedirectUri, 'postLogoutRedirectUri', this.allowCustomScheme);
    return withQuery(ep, { client_id: this.clientId, id_token_hint: opts.idTokenHint, post_logout_redirect_uri: opts.postLogoutRedirectUri, state: opts.state });
  }

  protected async tokenRequest(form: Record<string, string | undefined>): Promise<TokenSet> {
    const data = await this.post(await this.discovery.endpoint('token_endpoint'), form);
    return parseTokenResponse(data, this.now());
  }

  /** POST with client authentication (RFC 6749 §2.3.1; public clients send client_id only). */
  protected post(url: string, form: Record<string, string | undefined>, expectBody = true): Promise<Record<string, unknown>> {
    const headers: Record<string, string> = {};
    const f = { ...form };
    if (this.clientSecret && this.authMethod === 'client_secret_basic') {
      headers.Authorization = 'Basic ' + btoa(`${formEncode(this.clientId)}:${formEncode(this.clientSecret)}`);
    } else {
      f.client_id = this.clientId;
      if (this.clientSecret) f.client_secret = this.clientSecret;
    }
    return postForm(this.fetchFn, url, f, headers, expectBody);
  }
}

function formEncode(s: string): string {
  return encodeURIComponent(s).replace(/%20/g, '+');
}

export function uniqueScopes(scopes: string[]): string[] {
  for (const s of scopes) if (typeof s !== 'string' || !/^[\x21\x23-\x5b\x5d-\x7e]+$/.test(s)) throw new ConfigurationError(`Invalid scope "${String(s)}".`);
  return [...new Set(['openid', ...scopes])];
}

/** Serialises RFC 9396 authorization_details and checks types against what the server advertises. */
export function encodeAuthorizationDetails(details: AuthorizationDetail[], doc: DiscoveryDocument): string {
  if (!Array.isArray(details) || details.length === 0) throw new ConfigurationError('authorizationDetails must be a non-empty array.');
  for (const d of details) if (!d || typeof d.type !== 'string' || d.type === '') throw new ConfigurationError('Every authorization detail needs a type.');
  const supported = doc.authorization_details_types_supported;
  if (!Array.isArray(supported)) {
    throw new UnsupportedError('This Identvia server does not support authorization_details (requires server 2026-10-21_5+).');
  }
  for (const d of details) if (!supported.includes(d.type)) throw new ConfigurationError(`authorization_details type "${d.type}" is not accepted by this server (accepted: ${supported.join(', ')}).`);
  return JSON.stringify(details);
}

function stripUndefined<T extends Record<string, unknown>>(o: T): Partial<T> {
  const out: Partial<T> = {};
  for (const [k, v] of Object.entries(o)) if (v !== undefined) (out as Record<string, unknown>)[k] = v;
  return out;
}
