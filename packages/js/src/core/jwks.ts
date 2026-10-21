import { createLocalJWKSet, type JSONWebKeySet, type JWTVerifyGetKey } from 'jose';
import { HttpError, ValidationError } from './errors.js';
import { requestJson, type FetchLike } from './http.js';

/**
 * JWKS with caching and key-rotation awareness: when a token names an unknown `kid` the set is
 * refetched once, at most every `cooldownMs`, so a flood of forged tokens can't hammer Identvia.
 */
export class JwksCache {
  private set: ReturnType<typeof createLocalJWKSet> | undefined;
  private kids = new Set<string>();
  private fetchedAt = 0;
  private inflight: Promise<void> | undefined;

  constructor(private readonly uri: () => Promise<string>, private readonly fetchFn: FetchLike, private readonly ttlMs = 3600_000, private readonly cooldownMs = 30_000, private readonly now: () => number = Date.now) {}

  private async load(): Promise<void> {
    if (!this.inflight) {
      this.inflight = (async () => {
        const { status, data } = await requestJson(this.fetchFn, await this.uri(), { headers: { Accept: 'application/json' } });
        if (status !== 200 || !Array.isArray((data as { keys?: unknown }).keys)) throw new HttpError(`JWKS fetch failed (HTTP ${status}).`, status);
        const jwks = data as unknown as JSONWebKeySet;
        jwks.keys = jwks.keys.filter((k) => typeof k === 'object' && k !== null && (k.use === undefined || k.use === 'sig'));
        this.set = createLocalJWKSet(jwks);
        this.kids = new Set(jwks.keys.map((k) => String(k.kid ?? '')));
        this.fetchedAt = this.now();
      })().finally(() => { this.inflight = undefined; });
    }
    return this.inflight;
  }

  /** A jose key resolver. */
  readonly getKey: JWTVerifyGetKey = async (header, token) => {
    if (!header.kid) throw new ValidationError('ID token has no key ID (kid).');
    const stale = this.now() - this.fetchedAt > this.ttlMs;
    if (!this.set || stale) await this.load();
    if (!this.kids.has(header.kid) && this.now() - this.fetchedAt >= this.cooldownMs) await this.load();
    if (!this.kids.has(header.kid)) throw new ValidationError('ID token was signed with an unknown key.');
    return this.set!(header, token);
  };
}
