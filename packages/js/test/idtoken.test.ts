import { describe, expect, it } from 'vitest';
import { SignJWT, generateKeyPair, exportJWK, base64url } from 'jose';
import { OidcClient } from '../src/core/oidc.js';
import { ValidationError } from '../src/core/errors.js';
import { createFake, ISSUER } from './fake-identvia.js';

async function setup() {
  const f = await createFake();
  const c = new OidcClient({ issuer: ISSUER, clientId: f.clientId, redirectUri: 'https://app.example.com/callback', fetch: f.fetch });
  const t = Math.floor(Date.now() / 1000);
  const base = { iss: ISSUER, sub: 'pw_abc', aud: f.clientId, iat: t, exp: t + 600, nonce: 'n-123', auth_time: t - 10 };
  return { f, c, t, base };
}

describe('ID token validation', () => {
  it('accepts a valid token', async () => {
    const { f, c, base } = await setup();
    const claims = await c.validateIdToken(await f.signWith(base), { nonce: 'n-123', requireNonce: true });
    expect(claims.sub).toBe('pw_abc');
  });
  it.each([
    ['wrong issuer', { iss: 'https://evil.example' }, /iss/],
    ['wrong audience', { aud: 'someone-else' }, /aud/],
    ['expired', { exp: Math.floor(Date.now() / 1000) - 3600 }, /expired/],
    ['issued in the future', { iat: Math.floor(Date.now() / 1000) + 3600 }, /future|iat/],
    ['no subject', { sub: '' }, /subject/],
    ['azp mismatch', { azp: 'other' }, /azp/],
    ['multi-aud without azp', { aud: ['idv_test_client', 'other'] }, /azp/],
  ])('rejects %s', async (_n, patch, re) => {
    const { f, c, base } = await setup();
    await expect(c.validateIdToken(await f.signWith({ ...base, ...patch }), { nonce: 'n-123' })).rejects.toThrow(re as RegExp);
  });
  it('rejects nonce mismatch and missing nonce', async () => {
    const { f, c, base } = await setup();
    await expect(c.validateIdToken(await f.signWith(base), { nonce: 'other' })).rejects.toThrow(/nonce/);
    const { nonce: _, ...noNonce } = base;
    await expect(c.validateIdToken(await f.signWith(noNonce), { nonce: 'n-123' })).rejects.toThrow(/nonce/);
    await expect(c.validateIdToken(await f.signWith(noNonce), { requireNonce: true })).rejects.toThrow(/nonce/);
  });
  it('rejects alg=none', async () => {
    const { c, base } = await setup();
    const unsigned = `${base64url.encode(JSON.stringify({ alg: 'none', kid: 'k1' }))}.${base64url.encode(JSON.stringify(base))}.`;
    await expect(c.validateIdToken(unsigned, { nonce: 'n-123' })).rejects.toThrow(/algorithm none/);
  });
  it('rejects HS256 alg-confusion (public key used as HMAC secret)', async () => {
    const { f, c, base } = await setup();
    const jwkText = JSON.stringify((f as unknown as { discovery: unknown }).discovery);
    const forged = await new SignJWT(base).setProtectedHeader({ alg: 'HS256', kid: 'k1' }).sign(new TextEncoder().encode(jwkText));
    await expect(c.validateIdToken(forged, { nonce: 'n-123' })).rejects.toThrow(/HS256 is not allowed/);
  });
  it('rejects a token signed by another key with a known kid', async () => {
    const { c, base } = await setup();
    const other = await generateKeyPair('RS256');
    const forged = await new SignJWT(base).setProtectedHeader({ alg: 'RS256', kid: 'k1' }).sign(other.privateKey);
    await expect(c.validateIdToken(forged, { nonce: 'n-123' })).rejects.toThrow(/signature/);
  });
  it('checks max_age against auth_time', async () => {
    const { f, c, base, t } = await setup();
    await expect(c.validateIdToken(await f.signWith({ ...base, auth_time: t - 4000 }), { nonce: 'n-123', maxAge: 600 })).rejects.toThrow(/too long ago/);
    const { auth_time: _, ...noAuth } = base;
    await expect(c.validateIdToken(await f.signWith(noAuth), { nonce: 'n-123', maxAge: 600 })).rejects.toThrow(/auth_time/);
  });
  it('checks at_hash', async () => {
    const { f, c, base } = await setup();
    await expect(c.validateIdToken(await f.signWith({ ...base, at_hash: 'AAAAAAAAAAAAAAAAAAAAAA' }), { nonce: 'n-123', accessToken: 'at_x' })).rejects.toThrow(/at_hash/);
  });
  it('refetches JWKS once on key rotation, with a cooldown against unknown-kid floods', async () => {
    const { f, c, base } = await setup();
    await c.validateIdToken(await f.signWith(base), { nonce: 'n-123' });
    expect(f.state.jwksFetches).toBe(1);
    await f.rotateKey();
    const kp = await generateKeyPair('RS256');
    const unknown = await new SignJWT(base).setProtectedHeader({ alg: 'RS256', kid: 'nope' }).sign(kp.privateKey);
    for (let i = 0; i < 5; i++) await expect(c.validateIdToken(unknown, { nonce: 'n-123' })).rejects.toBeInstanceOf(ValidationError);
    expect(f.state.jwksFetches).toBe(1); // cooldown: no refetch within 30 s of the last one
  });
  it('picks up a rotated key after the cooldown', async () => {
    const f = await createFake();
    let now = Date.now();
    const c = new OidcClient({ issuer: ISSUER, clientId: f.clientId, redirectUri: 'https://app.example.com/callback', fetch: f.fetch, now: () => now });
    const t = Math.floor(now / 1000);
    const base = { iss: ISSUER, sub: 'pw_abc', aud: f.clientId, iat: t, exp: t + 600 };
    await c.validateIdToken(await f.signWith(base));
    await f.rotateKey();
    now += 31_000;
    const tok = await f.signWith(base, { alg: 'RS256', kid: 'k2' });
    await expect(c.validateIdToken(tok)).resolves.toMatchObject({ sub: 'pw_abc' });
    expect(f.state.jwksFetches).toBe(2);
    void exportJWK;
  });
  it('rejects garbage', async () => {
    const { c } = await setup();
    for (const g of ['', 'a.b', 'x.y.z', 'eyJhbGciOiJSUzI1NiJ9.e30']) await expect(c.validateIdToken(g)).rejects.toBeInstanceOf(ValidationError);
  });
});
