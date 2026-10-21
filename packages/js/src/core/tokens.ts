import { TokenError } from './errors.js';

export interface TokenSet {
  accessToken: string;
  tokenType: 'Bearer';
  /** Epoch milliseconds. */
  expiresAt: number;
  refreshToken?: string;
  idToken?: string;
  scope?: string;
  /** RFC 9396 authorization_details the server granted (server 2026-10-21_5+). */
  authorizationDetails?: AuthorizationDetail[];
  /** RFC 8693 issued_token_type, for token-exchange responses. */
  issuedTokenType?: string;
}

/** RFC 9396 §2. Identvia accepts the types an admin allows (default: `agent_task`). */
export interface AuthorizationDetail {
  type: string;
  locations?: string[];
  actions?: string[];
  datatypes?: string[];
  identifier?: string;
  privileges?: string[];
  [k: string]: unknown;
}

export function parseTokenResponse(data: Record<string, unknown>, nowMs: number): TokenSet {
  if (typeof data.access_token !== 'string' || data.access_token === '') throw new TokenError('invalid_response', 'Token response has no access_token.', 200);
  const type = typeof data.token_type === 'string' ? data.token_type : '';
  // RFC 8693 responses may use N_A for non-access tokens; everything Identvia issues to SDKs is Bearer.
  if (type.toLowerCase() !== 'bearer') throw new TokenError('invalid_response', `Unexpected token_type "${type}".`, 200);
  const expiresIn = typeof data.expires_in === 'number' && data.expires_in > 0 ? data.expires_in : 600;
  const t: TokenSet = { accessToken: data.access_token, tokenType: 'Bearer', expiresAt: nowMs + expiresIn * 1000 };
  if (typeof data.refresh_token === 'string' && data.refresh_token !== '') t.refreshToken = data.refresh_token;
  if (typeof data.id_token === 'string' && data.id_token !== '') t.idToken = data.id_token;
  if (typeof data.scope === 'string') t.scope = data.scope;
  if (Array.isArray(data.authorization_details)) t.authorizationDetails = data.authorization_details as AuthorizationDetail[];
  if (typeof data.issued_token_type === 'string') t.issuedTokenType = data.issued_token_type;
  return t;
}

export function isExpired(t: Pick<TokenSet, 'expiresAt'>, leewayMs: number, nowMs: number): boolean {
  return t.expiresAt - leewayMs <= nowMs;
}
