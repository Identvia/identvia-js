import { decodeProtectedHeader, errors as joseErrors, jwtVerify, type JWTPayload, type JWTVerifyGetKey } from 'jose';
import { leftHalfHash, timingSafeEqual } from './crypto.js';
import { ValidationError } from './errors.js';

/** Identvia signs with RS256 today; ES256 is accepted for future key types. Never HS* or "none". */
export const ALLOWED_ALGS = ['RS256', 'ES256'] as const;

export interface IdTokenClaims extends JWTPayload {
  iss: string;
  sub: string;
  aud: string | string[];
  exp: number;
  iat: number;
  auth_time?: number;
  nonce?: string;
  azp?: string;
  amr?: string[];
  at_hash?: string;
  email?: string;
  email_verified?: boolean;
  name?: string;
  given_name?: string;
  family_name?: string;
  picture?: string;
  updated_at?: number;
}

export interface IdTokenExpectations {
  issuer: string;
  clientId: string;
  getKey: JWTVerifyGetKey;
  /** Required on sign-in responses; omit only for refresh responses (OIDC Core §12.2). */
  nonce?: string;
  requireNonce?: boolean;
  maxAge?: number;
  accessToken?: string;
  /** Seconds of allowed clock skew. Default 60. */
  clockToleranceSec?: number;
  /** Override "now" (ms) for tests. */
  now?: () => number;
}

/** Validates an ID token per OIDC Core §3.1.3.7 and returns its claims. Throws ValidationError. */
export async function validateIdToken(jwt: string, e: IdTokenExpectations): Promise<IdTokenClaims> {
  if (typeof jwt !== 'string' || jwt.split('.').length !== 3) throw new ValidationError('ID token is not a signed JWT.');
  let header;
  try { header = decodeProtectedHeader(jwt); } catch { throw new ValidationError('ID token header is invalid.'); }
  if (!header.alg || !(ALLOWED_ALGS as readonly string[]).includes(header.alg)) throw new ValidationError(`ID token algorithm ${String(header.alg)} is not allowed.`);
  const tolerance = e.clockToleranceSec ?? 60;
  const nowMs = (e.now ?? Date.now)();
  let payload: JWTPayload;
  try {
    ({ payload } = await jwtVerify(jwt, e.getKey, {
      algorithms: [...ALLOWED_ALGS],
      issuer: e.issuer,
      audience: e.clientId,
      clockTolerance: tolerance,
      currentDate: new Date(nowMs),
      requiredClaims: ['iss', 'sub', 'aud', 'exp', 'iat'],
    }));
  } catch (err) {
    if (err instanceof ValidationError) throw err;
    const msg = err instanceof joseErrors.JWTExpired ? 'ID token has expired.'
      : err instanceof joseErrors.JWTClaimValidationFailed ? `ID token ${err.claim} check failed.`
      : err instanceof joseErrors.JWSSignatureVerificationFailed ? 'ID token signature is invalid.'
      : 'ID token rejected.';
    throw new ValidationError(msg, { cause: err });
  }
  const c = payload as IdTokenClaims;
  const now = Math.floor(nowMs / 1000);
  if (typeof c.sub !== 'string' || c.sub === '' || c.sub.length > 255) throw new ValidationError('ID token has no subject.');
  if (typeof c.exp !== 'number' || typeof c.iat !== 'number') throw new ValidationError('ID token is missing exp/iat.');
  if (c.iat > now + tolerance) throw new ValidationError('ID token was issued in the future.');
  const auds = Array.isArray(c.aud) ? c.aud : [c.aud];
  if (auds.length > 1 && c.azp !== e.clientId) throw new ValidationError('ID token azp mismatch.');
  if (c.azp !== undefined && c.azp !== e.clientId) throw new ValidationError('ID token azp mismatch.');
  if (e.nonce !== undefined || e.requireNonce) {
    if (typeof c.nonce !== 'string' || e.nonce === undefined || !timingSafeEqual(c.nonce, e.nonce)) throw new ValidationError('ID token nonce mismatch (possible replay).');
  }
  if (e.maxAge !== undefined) {
    if (typeof c.auth_time !== 'number') throw new ValidationError('ID token has no auth_time but max_age was requested.');
    if (c.auth_time + e.maxAge + tolerance < now) throw new ValidationError('The user signed in too long ago for the requested max_age.');
  }
  if (c.at_hash !== undefined && e.accessToken) {
    if (!timingSafeEqual(await leftHalfHash(e.accessToken), String(c.at_hash))) throw new ValidationError('ID token at_hash does not match the access token.');
  }
  return c;
}

/** Reads claims WITHOUT verifying. Only for display of a token you already validated. */
export function unsafeDecodeClaims(jwt: string): Record<string, unknown> {
  const p = jwt.split('.')[1];
  if (!p) throw new ValidationError('Not a JWT.');
  try {
    const json = new TextDecoder().decode(Uint8Array.from(atob(p.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((p.length + 3) % 4)), (ch) => ch.charCodeAt(0)));
    return JSON.parse(json) as Record<string, unknown>;
  } catch { throw new ValidationError('Not a JWT.'); }
}
