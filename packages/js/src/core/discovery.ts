import { ConfigurationError, HttpError, UnsupportedError } from './errors.js';
import { requestJson, type FetchLike } from './http.js';

/** The subset of OpenID Provider Metadata the SDK uses. Unknown fields are kept. */
export interface DiscoveryDocument {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri: string;
  userinfo_endpoint?: string;
  revocation_endpoint?: string;
  introspection_endpoint?: string;
  end_session_endpoint?: string;
  scopes_supported?: string[];
  grant_types_supported?: string[];
  code_challenge_methods_supported?: string[];
  id_token_signing_alg_values_supported?: string[];
  authorization_response_iss_parameter_supported?: boolean;
  /** Stage 5 (server 2026-10-21_5+) */
  backchannel_authentication_endpoint?: string;
  backchannel_token_delivery_modes_supported?: string[];
  authorization_details_types_supported?: string[];
  [k: string]: unknown;
}

export const GRANT_TOKEN_EXCHANGE = 'urn:ietf:params:oauth:grant-type:token-exchange';
export const GRANT_CIBA = 'urn:openid:params:grant-type:ciba';

const ENDPOINTS = ['authorization_endpoint', 'token_endpoint', 'jwks_uri', 'userinfo_endpoint', 'revocation_endpoint', 'introspection_endpoint', 'end_session_endpoint', 'backchannel_authentication_endpoint'] as const;

/** OIDC Discovery §4.3: the document's issuer must equal the configured issuer exactly; endpoints must be https on the same host family. */
export function validateDiscovery(doc: Record<string, unknown>, issuer: string): DiscoveryDocument {
  if (doc.issuer !== issuer) throw new ConfigurationError(`Discovery issuer "${String(doc.issuer)}" does not match the configured issuer "${issuer}".`);
  const iss = new URL(issuer);
  for (const k of ENDPOINTS) {
    const v = doc[k];
    if (v === undefined) continue;
    if (typeof v !== 'string') throw new ConfigurationError(`Discovery ${k} is not a string.`);
    const u = new URL(v);
    if (u.protocol !== iss.protocol) throw new ConfigurationError(`Discovery ${k} must use ${iss.protocol}.`);
  }
  for (const k of ['authorization_endpoint', 'token_endpoint', 'jwks_uri'] as const) {
    if (typeof doc[k] !== 'string') throw new ConfigurationError(`Discovery document has no ${k}.`);
  }
  const methods = doc.code_challenge_methods_supported;
  if (Array.isArray(methods) && !methods.includes('S256')) throw new ConfigurationError('Identvia server does not support PKCE S256.');
  return doc as unknown as DiscoveryDocument;
}

export class DiscoveryCache {
  private doc: DiscoveryDocument | undefined;
  private fetchedAt = 0;
  private inflight: Promise<DiscoveryDocument> | undefined;

  constructor(private readonly issuer: string, private readonly fetchFn: FetchLike, private readonly ttlMs = 3600_000, private readonly now: () => number = Date.now, initial?: DiscoveryDocument) {
    if (initial) { this.doc = validateDiscovery(initial as Record<string, unknown>, issuer); this.fetchedAt = now(); }
  }

  async get(): Promise<DiscoveryDocument> {
    if (this.doc && this.now() - this.fetchedAt < this.ttlMs) return this.doc;
    if (!this.inflight) {
      this.inflight = (async () => {
        const { status, data } = await requestJson(this.fetchFn, `${this.issuer}/.well-known/openid-configuration`, { headers: { Accept: 'application/json' } });
        if (status !== 200) throw new HttpError(`Discovery failed (HTTP ${status}).`, status);
        this.doc = validateDiscovery(data, this.issuer);
        this.fetchedAt = this.now();
        return this.doc;
      })().finally(() => { this.inflight = undefined; });
    }
    return this.inflight;
  }

  async endpoint(name: keyof DiscoveryDocument & string, feature?: string): Promise<string> {
    const doc = await this.get();
    const v = doc[name];
    if (typeof v !== 'string') throw new UnsupportedError(`${feature ?? name} is not available on this Identvia server${feature ? ' (requires server 2026-10-21_5+)' : ''}.`);
    return v;
  }
}
