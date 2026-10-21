/**
 * End-to-end against a REAL Identvia server (stage 4 build 2026-10-21_4), no mocks.
 *   php ../../../tools/live/helper.php setup http://localhost:8180 /tmp/live-state.json
 *   IDENTVIA_LIVE_STATE=/tmp/live-state.json pnpm test:live
 */
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { OidcClient } from '../src/core/oidc.js';
import { IdentviaServerClient } from '../src/server/client.js';
import { IdentviaAuth } from '../src/server/web.js';
import { AuthorizationError, TokenError, UnsupportedError } from '../src/core/errors.js';

const statePath = process.env.IDENTVIA_LIVE_STATE;
const S = statePath ? JSON.parse(readFileSync(statePath, 'utf8')) : null;
const helper = new URL('../../../../tools/live/helper.php', import.meta.url).pathname;
const browse = (url: string, action = 'approve') => execFileSync('php', [helper, 'browse', statePath!, url, action], { encoding: 'utf8' }).trim();

describe.skipIf(!S)('live Identvia server', () => {
  it('public client: PKCE sign-in, ID token via JWKS, userinfo, refresh rotation + reuse detection, revoke', async () => {
    const c = new OidcClient({ issuer: S.base, clientId: S.publicClientId, redirectUri: S.publicRedirect, scopes: ['email', 'profile', 'offline_access'] });
    const doc = await c.getDiscovery();
    expect(doc.subject_types_supported).toEqual(['pairwise']);
    const { url, transaction } = await c.createAuthorizationRequest({ returnTo: '/home' });
    const cb = new URL(browse(url));
    expect(cb.searchParams.get('iss')).toBe(S.base);
    const r = await c.completeAuthorization(cb.searchParams, transaction);
    expect(r.claims.email).toBe(S.userEmail);
    expect(r.claims.sub).toMatch(/.+/);
    expect(r.returnTo).toBe('/home');
    expect(r.tokens.refreshToken).toBeTruthy();
    const info = await c.userinfo(r.tokens.accessToken, r.claims.sub);
    expect(info.email).toBe(S.userEmail);
    const r2 = await c.refresh(r.tokens.refreshToken!, r.claims.sub);
    expect(r2.tokens.refreshToken).toBeTruthy();
    expect(r2.tokens.refreshToken).not.toBe(r.tokens.refreshToken);
    // replaying the rotated-out token is detected and revokes the chain
    await expect(c.refresh(r.tokens.refreshToken!)).rejects.toMatchObject({ error: 'invalid_grant' });
    await expect(c.refresh(r2.tokens.refreshToken!)).rejects.toBeInstanceOf(TokenError);
    const end = new URL(await c.endSessionUrl({ idTokenHint: r.tokens.idToken!, postLogoutRedirectUri: S.publicRedirect }));
    expect(end.pathname).toBe('/oauth/logout');
  });

  it('authorization code replay is rejected and revokes what the code issued (RFC 6749 §4.1.2)', async () => {
    const c = new OidcClient({ issuer: S.base, clientId: S.publicClientId, redirectUri: S.publicRedirect, scopes: ['email'] });
    const { url, transaction } = await c.createAuthorizationRequest();
    const cb = new URL(browse(url));
    const r = await c.completeAuthorization(cb.searchParams, transaction);
    await expect(c.completeAuthorization(cb.searchParams, transaction)).rejects.toMatchObject({ error: 'invalid_grant' });
    await expect(c.userinfo(r.tokens.accessToken)).rejects.toMatchObject({ error: 'invalid_token' });
  });

  it('wrong PKCE verifier is rejected by the server', async () => {
    const c = new OidcClient({ issuer: S.base, clientId: S.publicClientId, redirectUri: S.publicRedirect });
    const { url, transaction } = await c.createAuthorizationRequest();
    const cb = new URL(browse(url));
    await expect(c.completeAuthorization(cb.searchParams, { ...transaction, codeVerifier: 'x'.repeat(64) })).rejects.toMatchObject({ error: 'invalid_grant' });
  });

  it('public client: revoke ends the grant', async () => {
    const c = new OidcClient({ issuer: S.base, clientId: S.publicClientId, redirectUri: S.publicRedirect, scopes: ['email', 'offline_access'] });
    const { url, transaction } = await c.createAuthorizationRequest();
    const r = await c.completeAuthorization(new URL(browse(url)).searchParams, transaction);
    await c.revoke(r.tokens.refreshToken!, 'refresh_token');
    await expect(c.refresh(r.tokens.refreshToken!)).rejects.toMatchObject({ error: 'invalid_grant' });
    await expect(c.userinfo(r.tokens.accessToken)).rejects.toMatchObject({ error: 'invalid_token' });
  });

  it('cancel on the consent screen → AuthorizationError(access_denied)', async () => {
    const c = new OidcClient({ issuer: S.base, clientId: S.publicClientId, redirectUri: S.publicRedirect, scopes: ['email', 'offline_access'], });
    const { url, transaction } = await c.createAuthorizationRequest({ prompt: 'consent' });
    const cb = new URL(browse(url, 'deny'));
    const e = await c.completeAuthorization(cb.searchParams, transaction).catch((x) => x);
    expect(e).toBeInstanceOf(AuthorizationError);
    expect(e.error).toBe('access_denied');
  });

  it('confidential server app through IdentviaAuth: login → callback → session → introspect → logout', async () => {
    const auth = new IdentviaAuth({ issuer: S.base, clientId: S.confClientId, clientSecret: S.confSecret, redirectUri: S.confRedirect, scopes: ['email', 'offline_access'], secret: 'live-test-secret-0123456789abcdefghijklmnop' });
    const origin = new URL(S.confRedirect).origin;
    const r1 = (await auth.handle(new Request(`${origin}/auth/login?returnTo=/account`)))!;
    expect(r1.status).toBe(302);
    const tx = r1.headers.getSetCookie()[0]!.split(';')[0]!;
    const cb = browse(r1.headers.get('location')!);
    const r2 = (await auth.handle(new Request(cb, { headers: { cookie: tx } })))!;
    expect(r2.status).toBe(302);
    expect(r2.headers.get('location')).toBe(`${origin}/account`);
    const cookie = r2.headers.getSetCookie().filter((c) => !/Max-Age=0/.test(c)).map((c) => c.split(';')[0]).join('; ');
    const s = await auth.getSession(cookie);
    expect(s?.user.email).toBe(S.userEmail);
    const intro = await auth.client.introspect(s!.accessToken!);
    expect(intro.active).toBe(true);
    // pairwise: same person, different app → different sub
    const pub = new OidcClient({ issuer: S.base, clientId: S.publicClientId, redirectUri: S.publicRedirect });
    const p = await pub.createAuthorizationRequest();
    const pr = await pub.completeAuthorization(new URL(browse(p.url)).searchParams, p.transaction);
    expect(pr.claims.sub).not.toBe(s!.user.sub);
    const out = (await auth.handle(new Request(`${origin}/auth/logout`, { method: 'POST', headers: { cookie, origin } })))!;
    expect(out.status).toBe(303);
    expect((await auth.client.introspect(s!.accessToken!)).active).toBe(false);
  });

  it('stage-5 helpers report UnsupportedError on a stage-4 server', async () => {
    const c = new IdentviaServerClient({ issuer: S.base, clientId: S.confClientId, clientSecret: S.confSecret, redirectUri: S.confRedirect });
    const doc = await c.getDiscovery();
    if (doc.backchannel_authentication_endpoint) return; // a stage-5 server: nothing to check here
    await expect(c.startCiba({ loginHint: 'x' })).rejects.toBeInstanceOf(UnsupportedError);
    await expect(c.tokenExchange({ subjectToken: 'x' })).rejects.toBeInstanceOf(UnsupportedError);
    await expect(c.createAuthorizationRequest({ authorizationDetails: [{ type: 'agent_task' }] })).rejects.toBeInstanceOf(UnsupportedError);
  });
});
