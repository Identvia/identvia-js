import { describe, expect, it } from 'vitest';
import { createCodeChallenge, createPkce, randomToken, timingSafeEqual } from '../src/core/crypto.js';
import { base64UrlDecode, base64UrlEncode } from '../src/core/encoding.js';
import { assertRedirectUri, normalizeIssuer, safeReturnTo } from '../src/core/urls.js';
import { validateDiscovery } from '../src/core/discovery.js';
import { OidcClient, uniqueScopes } from '../src/core/oidc.js';
import { ConfigurationError } from '../src/core/errors.js';
import { createFake, ISSUER } from './fake-identvia.js';

describe('PKCE', () => {
  it('matches the RFC 7636 Appendix B test vector', async () => {
    expect(await createCodeChallenge('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk')).toBe('E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM');
  });
  it('creates 64-char verifiers with S256 challenges, never repeating', async () => {
    const a = await createPkce(); const b = await createPkce();
    expect(a.verifier).toMatch(/^[A-Za-z0-9_-]{64}$/);
    expect(a.method).toBe('S256');
    expect(a.challenge).toBe(await createCodeChallenge(a.verifier));
    expect(a.verifier).not.toBe(b.verifier);
  });
  it('rejects malformed verifiers', async () => {
    await expect(createCodeChallenge('short')).rejects.toBeInstanceOf(ConfigurationError);
    await expect(createCodeChallenge('a'.repeat(129))).rejects.toBeInstanceOf(ConfigurationError);
  });
  it('base64url round-trips all byte lengths', () => {
    for (let n = 0; n < 40; n++) {
      const b = new Uint8Array(n).map((_, i) => (i * 37 + n) & 255);
      const s = base64UrlEncode(b);
      expect(s).toBe(Buffer.from(b).toString('base64url'));
      expect([...base64UrlDecode(s)]).toEqual([...b]);
    }
  });
  it('random tokens are 256-bit and unique', () => {
    const set = new Set(Array.from({ length: 200 }, () => randomToken()));
    expect(set.size).toBe(200);
    expect([...set][0]).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });
  it('timingSafeEqual', () => {
    expect(timingSafeEqual('abc', 'abc')).toBe(true);
    expect(timingSafeEqual('abc', 'abd')).toBe(false);
    expect(timingSafeEqual('abc', 'abcd')).toBe(false);
  });
});

describe('URL safety', () => {
  it('only same-site relative returnTo paths survive', () => {
    expect(safeReturnTo('/dashboard?tab=1')).toBe('/dashboard?tab=1');
    for (const bad of ['//evil.com', '/\\evil.com', 'https://evil.com', 'javascript:alert(1)', '/a\nb', '', 'dashboard', '/\u0000']) expect(safeReturnTo(bad)).toBeUndefined();
  });
  it('redirect URIs: https or loopback http; custom schemes only for native', () => {
    expect(assertRedirectUri('https://app.example.com/cb')).toBeTruthy();
    expect(assertRedirectUri('http://localhost:3000/cb')).toBeTruthy();
    expect(assertRedirectUri('http://127.0.0.1:8080/cb')).toBeTruthy();
    for (const bad of ['http://app.example.com/cb', 'https://app.example.com/cb#x', 'https://u:p@app.example.com/cb', 'javascript:alert(1)', 'com.example.app:/cb']) expect(() => assertRedirectUri(bad)).toThrow(ConfigurationError);
    expect(assertRedirectUri('com.example.app:/cb', 'r', true)).toBe('com.example.app:/cb');
    expect(() => assertRedirectUri('myapp:/cb', 'r', true)).toThrow(ConfigurationError);
  });
  it('issuer must be https without trailing slash/query', () => {
    expect(normalizeIssuer('https://id.identvia.com/')).toBe('https://id.identvia.com');
    expect(() => normalizeIssuer('http://id.identvia.com')).toThrow();
    expect(() => normalizeIssuer('https://id.identvia.com/?x=1')).toThrow();
    expect(normalizeIssuer('http://localhost:8080')).toBe('http://localhost:8080');
  });
  it('scopes always include openid and reject junk', () => {
    expect(uniqueScopes(['email', 'email'])).toEqual(['openid', 'email']);
    expect(() => uniqueScopes(['a b'])).toThrow();
  });
});

describe('discovery', () => {
  it('requires the exact issuer and S256', async () => {
    const f = await createFake();
    expect(() => validateDiscovery({ ...f.discovery, issuer: 'https://evil.example' }, ISSUER)).toThrow(/does not match/);
    expect(() => validateDiscovery({ ...f.discovery, code_challenge_methods_supported: ['plain'] }, ISSUER)).toThrow(/S256/);
    expect(() => validateDiscovery({ ...f.discovery, token_endpoint: 'http://id.identvia.test/oauth/token' }, ISSUER)).toThrow(/https/);
  });
  it('is fetched once and cached', async () => {
    const f = await createFake();
    const c = new OidcClient({ issuer: ISSUER, clientId: f.clientId, redirectUri: 'https://app.example.com/callback', fetch: f.fetch });
    await Promise.all([c.getDiscovery(), c.getDiscovery(), c.getDiscovery()]);
    expect(f.calls.filter((x) => x.url.endsWith('openid-configuration')).length).toBe(1);
  });
});

describe('authorization request', () => {
  it('has every parameter Identvia requires', async () => {
    const f = await createFake();
    const c = new OidcClient({ issuer: ISSUER, clientId: f.clientId, redirectUri: 'https://app.example.com/callback', scopes: ['email', 'offline_access'], fetch: f.fetch });
    const { url, transaction } = await c.createAuthorizationRequest({ prompt: 'login', maxAge: 300, returnTo: '//evil', loginHint: 'ada@example.com' });
    const p = new URL(url).searchParams;
    expect(p.get('response_type')).toBe('code');
    expect(p.get('code_challenge_method')).toBe('S256');
    expect(p.get('code_challenge')).toBe(await createCodeChallenge(transaction.codeVerifier));
    expect(p.get('state')).toBe(transaction.state);
    expect(p.get('nonce')).toBe(transaction.nonce);
    expect(p.get('scope')).toBe('openid email offline_access');
    expect(p.get('max_age')).toBe('300');
    expect(transaction.returnTo).toBeUndefined();
    await expect(c.createAuthorizationRequest({ prompt: 'select_account' as 'login' })).rejects.toThrow(/prompt/);
  });
});
