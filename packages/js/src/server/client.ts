import { GRANT_CIBA, GRANT_TOKEN_EXCHANGE } from '../core/discovery.js';
import { ConfigurationError, TokenError, UnsupportedError } from '../core/errors.js';
import { OidcClient, encodeAuthorizationDetails, uniqueScopes, type OidcConfig } from '../core/oidc.js';
import { parseTokenResponse, type AuthorizationDetail, type TokenSet } from '../core/tokens.js';

export interface IdentviaServerOptions extends OidcConfig {
  /** Confidential clients only. Keep it in an environment variable, never in client bundles. */
  clientSecret?: string;
  tokenEndpointAuthMethod?: 'client_secret_basic' | 'client_secret_post';
}

export const TOKEN_TYPE_ACCESS = 'urn:ietf:params:oauth:token-type:access_token';
export const TOKEN_TYPE_ID = 'urn:ietf:params:oauth:token-type:id_token';
export const TOKEN_TYPE_JWT = 'urn:ietf:params:oauth:token-type:jwt';

export interface TokenExchangeRequest {
  subjectToken: string;
  subjectTokenType?: string;
  /** Token identifying the agent that will act (it ends up in the `act` claim). */
  actorToken?: string;
  actorTokenType?: string;
  requestedTokenType?: string;
  audience?: string;
  resource?: string;
  /** Must be a subset of the subject token's scopes. */
  scopes?: string[];
  authorizationDetails?: AuthorizationDetail[];
}

export interface CibaRequest {
  /** One of loginHint / idTokenHint / loginHintToken identifies the person. The pairwise `sub` works as a login_hint. */
  loginHint?: string;
  idTokenHint?: string;
  loginHintToken?: string;
  /** Short text shown on both the agent's screen and the person's approval card, so they can match them. */
  bindingMessage?: string;
  scopes?: string[];
  authorizationDetails?: AuthorizationDetail[];
  requestedExpirySec?: number;
  /** Ping mode: your notification endpoint receives this as a Bearer token. */
  clientNotificationToken?: string;
}

export interface CibaStart { authReqId: string; expiresIn: number; interval: number; expiresAt: number }

export interface Introspection { active: boolean; [k: string]: unknown }

/**
 * Server-side Identvia client (Node 18+, Bun, Deno, edge runtimes). Same flow as the browser client plus
 * confidential-client features: introspection, and the stage-5 delegation standards.
 */
export class IdentviaServerClient extends OidcClient {
  constructor(opts: IdentviaServerOptions) {
    if (opts.clientSecret !== undefined && (typeof opts.clientSecret !== 'string' || opts.clientSecret.length < 16)) throw new ConfigurationError('clientSecret looks wrong (too short).');
    super({ ...opts, tokenEndpointAuthMethod: opts.tokenEndpointAuthMethod ?? 'client_secret_basic' });
  }

  get isConfidential(): boolean { return !!this.clientSecret; }

  async introspect(token: string): Promise<Introspection> {
    if (!this.clientSecret) throw new ConfigurationError('Introspection needs a confidential client (clientSecret).');
    const ep = await this.discovery.endpoint('introspection_endpoint');
    const data = await this.post(ep, { token });
    return { ...data, active: data.active === true };
  }

  /**
   * RFC 8693 Token Exchange: swap a user's access token for a narrower, shorter-lived one, optionally naming
   * the acting agent (`act`). **Requires server 2026-10-21_5+** and an app the developer opted in.
   */
  async tokenExchange(req: TokenExchangeRequest): Promise<TokenSet> {
    const doc = await this.discovery.get();
    if (!doc.grant_types_supported?.includes(GRANT_TOKEN_EXCHANGE)) throw new UnsupportedError('Token exchange (RFC 8693) is not enabled on this Identvia server (requires server 2026-10-21_5+).');
    if (!req.subjectToken) throw new ConfigurationError('subjectToken is required.');
    if (req.actorToken && !req.actorTokenType) throw new ConfigurationError('actorTokenType is required with actorToken.');
    const data = await this.post(doc.token_endpoint, {
      grant_type: GRANT_TOKEN_EXCHANGE,
      subject_token: req.subjectToken,
      subject_token_type: req.subjectTokenType ?? TOKEN_TYPE_ACCESS,
      actor_token: req.actorToken,
      actor_token_type: req.actorToken ? req.actorTokenType : undefined,
      requested_token_type: req.requestedTokenType,
      audience: req.audience,
      resource: req.resource,
      scope: req.scopes ? req.scopes.join(' ') : undefined,
      authorization_details: req.authorizationDetails ? encodeAuthorizationDetails(req.authorizationDetails, doc) : undefined,
    });
    return parseTokenResponse(data, this.now());
  }

  /**
   * OpenID CIBA: ask a person to approve a request in their Identvia inbox, with no browser redirect.
   * **Requires server 2026-10-21_5+** and an app the developer opted in. Then call `pollCiba` / `waitForCiba`.
   */
  async startCiba(req: CibaRequest): Promise<CibaStart> {
    if (!this.clientSecret) throw new ConfigurationError('CIBA needs a confidential client (clientSecret).');
    const doc = await this.discovery.get();
    const ep = doc.backchannel_authentication_endpoint;
    if (typeof ep !== 'string' || !doc.grant_types_supported?.includes(GRANT_CIBA)) throw new UnsupportedError('CIBA is not enabled on this Identvia server (requires server 2026-10-21_5+).');
    const hints = [req.loginHint, req.idTokenHint, req.loginHintToken].filter((h) => h !== undefined);
    if (hints.length !== 1) throw new ConfigurationError('Pass exactly one of loginHint, idTokenHint or loginHintToken.');
    if (req.bindingMessage !== undefined && req.bindingMessage.length > 64) throw new ConfigurationError('bindingMessage should be short (max 64 characters).');
    const data = await this.post(ep, {
      scope: uniqueScopes(req.scopes ?? this.scopes).join(' '),
      login_hint: req.loginHint,
      id_token_hint: req.idTokenHint,
      login_hint_token: req.loginHintToken,
      binding_message: req.bindingMessage,
      requested_expiry: req.requestedExpirySec !== undefined ? String(Math.floor(req.requestedExpirySec)) : undefined,
      client_notification_token: req.clientNotificationToken,
      authorization_details: req.authorizationDetails ? encodeAuthorizationDetails(req.authorizationDetails, doc) : undefined,
    });
    if (typeof data.auth_req_id !== 'string' || data.auth_req_id === '') throw new TokenError('invalid_response', 'CIBA response has no auth_req_id.', 200);
    const expiresIn = typeof data.expires_in === 'number' ? data.expires_in : 300;
    const interval = typeof data.interval === 'number' && data.interval > 0 ? data.interval : 5;
    return { authReqId: data.auth_req_id, expiresIn, interval, expiresAt: this.now() + expiresIn * 1000 };
  }

  /** One poll. Returns tokens when approved, `null` while pending; throws TokenError(access_denied / expired_token). `slow_down` is returned as 'slow_down'. */
  async pollCiba(authReqId: string): Promise<TokenSet | null | 'slow_down'> {
    try {
      const data = await this.post(await this.discovery.endpoint('token_endpoint'), { grant_type: GRANT_CIBA, auth_req_id: authReqId });
      const tokens = parseTokenResponse(data, this.now());
      if (tokens.idToken) await this.validateIdToken(tokens.idToken, { accessToken: tokens.accessToken });
      return tokens;
    } catch (e) {
      if (e instanceof TokenError && e.error === 'authorization_pending') return null;
      if (e instanceof TokenError && e.error === 'slow_down') return 'slow_down';
      throw e;
    }
  }

  /** Polls until the person approves or denies, honouring `interval` and `slow_down` (+5 s, CIBA §11). */
  async waitForCiba(start: CibaStart, opts: { signal?: AbortSignal; sleep?: (ms: number) => Promise<void> } = {}): Promise<TokenSet> {
    const sleep = opts.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
    let interval = start.interval;
    for (;;) {
      if (opts.signal?.aborted) throw new TokenError('aborted', 'Stopped waiting for approval.', 0);
      if (this.now() >= start.expiresAt) throw new TokenError('expired_token', 'The person did not answer in time.', 400);
      await sleep(interval * 1000);
      const r = await this.pollCiba(start.authReqId);
      if (r === 'slow_down') { interval += 5; continue; }
      if (r) return r;
    }
  }
}
