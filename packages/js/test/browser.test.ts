// @vitest-environment happy-dom
// @vitest-environment-options {"url":"https://app.example.com/"}
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { IdentviaClient } from '../src/browser/client.js';
import { AuthorizationError, ConfigurationError, InvalidStateError, TokenError } from '../src/core/errors.js';
import { MemoryStorage } from '../src/browser/storage.js';
import { createFake, ISSUER } from './fake-identvia.js';

let assigned: string[] = [];
beforeEach(() => {
  assigned = [];
  sessionStorage.clear(); localStorage.clear();
  vi.spyOn(window.location, 'assign').mockImplementation((u: string | URL) => { assigned.push(String(u)); });
});

async function setup(extra: Record<string, unknown> = {}) {
  const f = await createFake({ ...(extra.stage5 ? { stage5: true } : {}) });
  const client = new IdentviaClient({ issuer: ISSUER, clientId: f.clientId, redirectUri: 'https://app.example.com/callback', scopes: ['email', 'offline_access'], fetch: f.fetch, storage: 'session', ...extra });
  return { f, client };
}

async function signIn(f: Awaited<ReturnType<typeof createFake>>, client: IdentviaClient, opts = {}) {
  await client.signInWithRedirect(opts);
  const cb = f.authorize(assigned.pop()!);
  return client.handleRedirectCallback(cb);
}

describe('IdentviaClient (browser)', () => {
  it('refuses a client secret', () => {
    expect(() => new IdentviaClient({ clientId: 'x', redirectUri: 'https://a.example/cb', clientSecret: 's'.repeat(32) } as never)).toThrow(ConfigurationError);
  });
  it('redirect flow: PKCE + state + nonce + iss, session stored, transaction single-use', async () => {
    const { f, client } = await setup();
    await client.signInWithRedirect({ returnTo: '/dashboard' });
    const url = assigned.pop()!;
    expect(url.startsWith(`${ISSUER}/oauth/authorize?`)).toBe(true);
    const cb = f.authorize(url);
    const r = await client.handleRedirectCallback(cb);
    expect(r.user.email).toBe('ada@example.com');
    expect(r.returnTo).toBe('/dashboard');
    expect(await client.isAuthenticated()).toBe(true);
    const token = f.calls.find((c) => c.url.endsWith('/oauth/token'))!;
    expect(token.body!.get('client_id')).toBe(f.clientId);
    expect(token.body!.get('client_secret')).toBeNull();
    expect(token.body!.get('code_verifier')).toMatch(/^[A-Za-z0-9_-]{64}$/);
    await expect(client.handleRedirectCallback(cb)).rejects.toBeInstanceOf(InvalidStateError); // replay
  });
  it('rejects forged state, wrong iss, missing iss', async () => {
    const { f, client } = await setup();
    await client.signInWithRedirect();
    const cb = new URL(f.authorize(assigned.pop()!));
    cb.searchParams.set('state', 'A'.repeat(43));
    await expect(client.handleRedirectCallback(cb.toString())).rejects.toBeInstanceOf(InvalidStateError);

    f.state.wrongIss = true;
    await client.signInWithRedirect();
    await expect(client.handleRedirectCallback(f.authorize(assigned.pop()!))).rejects.toThrow(/different issuer/);
    f.state.wrongIss = false; f.state.omitIss = true;
    await client.signInWithRedirect();
    await expect(client.handleRedirectCallback(f.authorize(assigned.pop()!))).rejects.toThrow(/missing the iss/);
  });
  it('rejects an ID token replayed with another nonce', async () => {
    const { f, client } = await setup();
    f.state.issNonce = 'attacker-nonce';
    await client.signInWithRedirect();
    await expect(client.handleRedirectCallback(f.authorize(assigned.pop()!))).rejects.toThrow(/nonce/);
    expect(await client.getSession()).toBeNull();
  });
  it('surfaces cancel as AuthorizationError(access_denied)', async () => {
    const { f, client } = await setup();
    await client.signInWithRedirect({ returnTo: '/x' });
    const err = await client.handleRedirectCallback(f.authorize(assigned.pop()!, { deny: true })).catch((e) => e);
    expect(err).toBeInstanceOf(AuthorizationError);
    expect(err.error).toBe('access_denied');
    expect(err.returnTo).toBe('/x');
  });
  it('refreshes with rotation; concurrent callers share one refresh', async () => {
    const { f, client } = await setup({ refreshLeewaySec: 10_000 }); // every token counts as "about to expire"
    await signIn(f, client);
    const first = (await client.getSession())!.tokens.refreshToken!;
    const [a, b, c] = await Promise.all([client.getAccessToken(), client.getAccessToken(), client.getAccessToken()]);
    expect(a).toBe(b); expect(b).toBe(c);
    expect(f.calls.filter((x) => x.body?.get('grant_type') === 'refresh_token').length).toBe(1);
    const second = (await client.getSession())!.tokens.refreshToken!;
    expect(second).not.toBe(first);
    expect(f.refresh.get(first)!.used).toBe(true);
  });
  it('signs out locally when the refresh chain was revoked (reuse detection)', async () => {
    const { f, client } = await setup({ refreshLeewaySec: 10_000 });
    await signIn(f, client);
    const old = (await client.getSession())!.tokens.refreshToken!;
    await client.getAccessToken();
    // An attacker replays the old refresh token → Identvia revokes the whole family
    const r = await f.fetch(`${ISSUER}/oauth/token`, { method: 'POST', body: `grant_type=refresh_token&refresh_token=${old}&client_id=${f.clientId}` });
    expect(r.status).toBe(400);
    const events: string[] = [];
    client.subscribe((e) => events.push(e.type));
    const err = await client.getAccessToken().catch((e) => e);
    expect(err).toBeInstanceOf(TokenError);
    expect(err.error).toBe('login_required');
    expect(events).toContain('signedOut');
    expect(await client.getSession()).toBeNull();
  });
  it('returns the cached token while it is fresh', async () => {
    const { f, client } = await setup();
    await signIn(f, client);
    const t = await client.getAccessToken();
    expect(await client.getAccessToken()).toBe(t);
    expect(f.calls.filter((x) => x.body?.get('grant_type') === 'refresh_token').length).toBe(0);
  });
  it('userinfo checks the sub matches', async () => {
    const { f, client } = await setup();
    await signIn(f, client);
    expect((await client.fetchUserInfo()).email).toBe('ada@example.com');
  });
  it('signOut revokes the refresh token and can end the Identvia session', async () => {
    const { f, client } = await setup({ postLogoutRedirectUri: 'https://app.example.com/' });
    await signIn(f, client);
    await client.signOut({ federated: true });
    expect(f.calls.some((c) => c.url.endsWith('/oauth/revoke') && c.body?.get('token_type_hint') === 'refresh_token')).toBe(true);
    expect(f.revokedFamilies.size).toBe(1);
    const end = new URL(assigned.pop()!);
    expect(end.pathname).toBe('/oauth/logout');
    expect(end.searchParams.get('id_token_hint')).toBeTruthy();
    expect(end.searchParams.get('post_logout_redirect_uri')).toBe('https://app.example.com/');
    expect(await client.getSession()).toBeNull();
  });
  it('memory storage keeps nothing in Web Storage', async () => {
    const { f, client } = await setup({ storage: 'memory' });
    await signIn(f, client);
    expect(Object.keys(sessionStorage).filter((k) => k.endsWith(':session'))).toEqual([]);
    expect(Object.keys(localStorage)).toEqual([]);
  });
  it('custom storage works', async () => {
    const store = new MemoryStorage();
    const { f, client } = await setup({ storage: store });
    await signIn(f, client);
    expect(store.getItem(`identvia:${f.clientId}:session`)).toContain('accessToken');
  });
  it('popup flow accepts only same-origin messages from its popup', async () => {
    const { f, client } = await setup({ popupRedirectUri: 'https://app.example.com/popup.html' });
    let popupHref = '';
    const popup = { closed: false, close(this: { closed: boolean }) { this.closed = true; }, location: { set href(v: string) { popupHref = v; }, get href() { return popupHref; } } } as unknown as Window;
    const p = client.signInWithPopup({ popup });
    await vi.waitFor(() => expect(popupHref).toContain('/oauth/authorize'));
    expect(new URL(popupHref).searchParams.get('redirect_uri')).toBe('https://app.example.com/popup.html');
    const cb = f.authorize(popupHref);
    // A message from another origin, or from another window, is ignored
    window.dispatchEvent(new MessageEvent('message', { origin: 'https://evil.example', source: popup, data: { type: 'identvia:callback', url: cb } }));
    window.dispatchEvent(new MessageEvent('message', { origin: window.location.origin, source: window, data: { type: 'identvia:callback', url: cb } }));
    await new Promise((r) => setTimeout(r, 20));
    window.dispatchEvent(new MessageEvent('message', { origin: window.location.origin, source: popup, data: { type: 'identvia:callback', url: cb } }));
    const r = await p;
    expect(r.user.sub).toBe(f.state.userSub);
    expect((popup as unknown as { closed: boolean }).closed).toBe(true);
  });
  it('sends authorization_details (RAR) only when the server supports it', async () => {
    const { f, client } = await setup({ stage5: true });
    const r = await signIn(f, client, { authorizationDetails: [{ type: 'agent_task', description: 'Book a table' }] });
    expect(r.user.sub).toBeTruthy();
    expect((await client.getSession())!.tokens.authorizationDetails).toEqual([{ type: 'agent_task', description: 'Book a table' }]);
    const old = await setup();
    await expect(old.client.signInWithRedirect({ authorizationDetails: [{ type: 'agent_task' }] })).rejects.toThrow(/2026-10-21_5/);
    await expect(client.signInWithRedirect({ authorizationDetails: [{ type: 'payment' }] })).rejects.toThrow(/not accepted/);
  });
});
