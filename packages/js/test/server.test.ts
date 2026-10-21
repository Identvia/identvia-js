import { afterEach, describe, expect, it } from 'vitest';
import express from 'express';
import type { AddressInfo } from 'node:net';
import type { Server } from 'node:http';
import { identvia } from '../src/server/express.js';
import { createIdentviaNext } from '../src/server/next.js';
import { IdentviaServerClient } from '../src/server/client.js';
import { IdentviaAuth } from '../src/server/web.js';
import { ConfigurationError, TokenError, UnsupportedError } from '../src/core/errors.js';
import { createFake, ISSUER } from './fake-identvia.js';

const SECRET = 'test-session-secret-0123456789-abcdefghijkl';
const CLIENT_SECRET = 'cs_' + 'x'.repeat(40);
let servers: Server[] = [];
afterEach(() => { for (const s of servers) s.close(); servers = []; });

function jar() {
  const m = new Map<string, string>();
  return {
    store(res: Response) { for (const c of res.headers.getSetCookie()) { const [kv] = c.split(';'); const i = kv!.indexOf('='); const k = kv!.slice(0, i); const v = kv!.slice(i + 1); if (/Max-Age=0/.test(c)) m.delete(k); else m.set(k, v); } },
    header() { return [...m].map(([k, v]) => `${k}=${v}`).join('; '); },
    m,
  };
}

async function app(opts: { federated?: boolean; accessTtl?: number } = {}) {
  const f = await createFake({ secret: CLIENT_SECRET, redirectUris: ['http://localhost:3000/auth/callback'], ...(opts.accessTtl ? { accessTtl: opts.accessTtl } : {}) });
  const a = express();
  const mw = identvia({ issuer: ISSUER, clientId: f.clientId, clientSecret: CLIENT_SECRET, redirectUri: 'http://localhost:3000/auth/callback', scopes: ['email', 'offline_access'], secret: SECRET, fetch: f.fetch, federatedLogout: !!opts.federated });
  a.use(mw);
  a.get('/', (req, res) => res.json({ user: req.identvia?.user ?? null }));
  a.get('/private', mw.requireAuth(), (req, res) => res.json({ hello: req.identvia!.user!.sub }));
  const server = await new Promise<Server>((r) => { const s = a.listen(0, () => r(s)); });
  servers.push(server);
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  const j = jar();
  const get = async (path: string, init: RequestInit = {}) => { const res = await fetch(base + path, { redirect: 'manual', ...init, headers: { cookie: j.header(), ...(init.headers as Record<string, string> ?? {}) } }); j.store(res); return res; };
  /** Follows the sign-in through the fake Identvia; returns the response of our callback route. */
  const login = async (returnTo = '/private', deny = false) => {
    const r1 = await get(`/auth/login?returnTo=${encodeURIComponent(returnTo)}`);
    expect(r1.status).toBe(302);
    const cb = new URL(f.authorize(r1.headers.get('location')!, { deny }));
    return get(cb.pathname + cb.search);
  };
  return { f, base, get, login, j, mw };
}

describe('Express middleware', () => {
  it('full sign-in: cookies are HttpOnly, the code is exchanged with client_secret_basic', async () => {
    const { f, get, login, j } = await app();
    const r = await login('/private');
    expect(r.status).toBe(302);
    expect(new URL(r.headers.get('location')!).pathname).toBe('/private');
    for (const c of r.headers.getSetCookie()) expect(c).toMatch(/HttpOnly; SameSite=Lax/);
    expect([...j.m.keys()].some((k) => k.startsWith('idv_session.'))).toBe(true);
    expect([...j.m.keys()].some((k) => k.startsWith('idv_tx_'))).toBe(false); // transaction cookie cleared
    const tok = f.calls.find((c) => c.url.endsWith('/oauth/token'))!;
    expect(tok.headers.authorization).toMatch(/^Basic /);
    expect(tok.body!.get('client_secret')).toBeNull();
    const p = await get('/private', { headers: { accept: 'application/json' } });
    expect(await p.json()).toEqual({ hello: f.state.userSub });
  });
  it('requireAuth: 302 to login for pages, 401 for APIs', async () => {
    const { get } = await app();
    const html = await get('/private', { headers: { accept: 'text/html' } });
    expect(html.status).toBe(302);
    expect(html.headers.get('location')).toBe('/auth/login?returnTo=%2Fprivate');
    const api = await get('/private', { headers: { accept: 'application/json' } });
    expect(api.status).toBe(401);
  });
  it('drops open-redirect returnTo values', async () => {
    const { login } = await app();
    const r = await login('//evil.example/x');
    expect(r.headers.get('location')).toBe('http://localhost:3000/');
  });
  it('rejects a callback without the transaction cookie (login CSRF / replay)', async () => {
    const { f, get, j } = await app();
    const r1 = await get('/auth/login');
    j.m.clear();
    const cb = new URL(f.authorize(r1.headers.get('location')!));
    const r = await get(cb.pathname + cb.search);
    expect(r.status).toBe(400);
    expect(await r.text()).toMatch(/expired or was already used/);
  });
  it('a tampered session cookie is ignored', async () => {
    const { login, get, j } = await app();
    await login();
    const k = [...j.m.keys()].find((x) => x.startsWith('idv_session.'))!;
    const v = j.m.get(k)!;
    j.m.set(k, v.slice(0, -4) + (v.endsWith('AAAA') ? 'BBBB' : 'AAAA'));
    expect(await (await get('/', { headers: { accept: 'application/json' } })).json()).toEqual({ user: null });
  });
  it('cancel shows a friendly error', async () => {
    const { login } = await app();
    const r = await login('/', true);
    expect(r.status).toBe(400);
    expect(await r.text()).toBe('Sign-in was cancelled.');
  });
  it('logout: POST only, same-origin only, revokes the refresh token', async () => {
    const { f, login, get, j } = await app();
    await login();
    expect((await get('/auth/logout')).status).toBe(405);
    expect((await get('/auth/logout', { method: 'POST', headers: { origin: 'https://evil.example' } })).status).toBe(403);
    expect((await get('/auth/logout', { method: 'POST', headers: { 'sec-fetch-site': 'cross-site' } })).status).toBe(403);
    const r = await get('/auth/logout', { method: 'POST', headers: { origin: 'http://localhost:3000' } });
    expect(r.status).toBe(303);
    expect(f.revokedFamilies.size).toBe(1);
    expect([...j.m.keys()].some((k) => k.startsWith('idv_session'))).toBe(false);
  });
  it('federated logout goes to end_session with id_token_hint', async () => {
    const { login, get } = await app({ federated: true });
    await login();
    const r = await get('/auth/logout', { method: 'POST', headers: { origin: 'http://localhost:3000' } });
    const u = new URL(r.headers.get('location')!);
    expect(u.origin + u.pathname).toBe(`${ISSUER}/oauth/logout`);
    expect(u.searchParams.get('id_token_hint')).toBeTruthy();
  });
  it('refreshes expiring access tokens with rotation and rewrites the cookie', async () => {
    const { f, login, get } = await app({ accessTtl: 30 }); // inside the 60 s leeway
    await login();
    const before = f.calls.filter((c) => c.body?.get('grant_type') === 'refresh_token').length;
    const r = await get('/auth/session');
    expect((await r.json()).user.sub).toBe(f.state.userSub);
    expect(f.calls.filter((c) => c.body?.get('grant_type') === 'refresh_token').length).toBe(before + 1);
    expect(r.headers.getSetCookie().some((c) => c.startsWith('idv_session.0='))).toBe(true);
    expect([...f.refresh.values()].filter((x) => x.used).length).toBe(1);
  });
});

describe('Next.js / Web handler', () => {
  it('handlers + getSession with a cookies() store', async () => {
    const f = await createFake({ redirectUris: ['https://app.example.com/auth/callback'] });
    const n = createIdentviaNext({ issuer: ISSUER, clientId: f.clientId, redirectUri: 'https://app.example.com/auth/callback', secret: SECRET, fetch: f.fetch });
    const r1 = await n.handlers.GET(new Request('https://app.example.com/auth/login?returnTo=/settings'));
    const tx = r1.headers.getSetCookie()[0]!;
    expect(tx).toMatch(/^__Host-idv_tx_.*; Path=\/; HttpOnly; SameSite=Lax; Secure/);
    const cb = f.authorize(r1.headers.get('location')!);
    const r2 = await n.handlers.GET(new Request(cb, { headers: { cookie: tx.split(';')[0]! } }));
    expect(r2.headers.get('location')).toBe('https://app.example.com/settings');
    const store = new Map<string, string>();
    for (const c of r2.headers.getSetCookie()) { const [kv] = c.split(';'); const i = kv!.indexOf('='); if (!/Max-Age=0/.test(c)) store.set(kv!.slice(0, i), decodeURIComponent(kv!.slice(i + 1))); }
    const s = await n.getSession({ get: (k: string) => (store.has(k) ? { value: store.get(k)! } : undefined) });
    expect(s?.user.sub).toBe(f.state.userSub);
    const mwRes = await n.middleware(new Request('https://app.example.com/settings'));
    expect(mwRes?.status).toBe(302);
    expect(mwRes?.headers.get('location')).toBe('https://app.example.com/auth/login?returnTo=%2Fsettings');
  });
  it('requires a strong secret', () => {
    expect(() => new IdentviaAuth({ clientId: 'x', redirectUri: 'https://a.example/cb', secret: 'short' })).toThrow(ConfigurationError);
  });
});

describe('Delegation standards (server 2026-10-21_5+)', () => {
  async function client(stage5: boolean) {
    const f = await createFake({ secret: CLIENT_SECRET, stage5 });
    const c = new IdentviaServerClient({ issuer: ISSUER, clientId: f.clientId, clientSecret: CLIENT_SECRET, redirectUri: 'https://app.example.com/callback', fetch: f.fetch });
    return { f, c };
  }
  it('throw UnsupportedError on older servers', async () => {
    const { c } = await client(false);
    await expect(c.tokenExchange({ subjectToken: 'x' })).rejects.toBeInstanceOf(UnsupportedError);
    await expect(c.startCiba({ loginHint: 'pw_x' })).rejects.toBeInstanceOf(UnsupportedError);
  });
  it('RFC 8693 token exchange narrows scope', async () => {
    const { f, c } = await client(true);
    const tokenRes = await f.fetch(`${ISSUER}/oauth/token`, { method: 'POST', body: '' });
    void tokenRes;
    // get a user access token via the code flow
    const { url, transaction } = await c.createAuthorizationRequest({ scopes: ['email'] });
    const signIn = await c.completeAuthorization(new URL(f.authorize(url)).searchParams, transaction);
    const t = await c.tokenExchange({ subjectToken: signIn.tokens.accessToken, scopes: ['openid'], actorToken: 'agent-jwt', actorTokenType: 'urn:ietf:params:oauth:token-type:jwt' });
    expect(t.issuedTokenType).toBe('urn:ietf:params:oauth:token-type:access_token');
    expect(t.scope).toBe('openid');
    const body = f.calls.at(-1)!.body!;
    expect(body.get('grant_type')).toBe('urn:ietf:params:oauth:grant-type:token-exchange');
    expect(body.get('actor_token_type')).toBe('urn:ietf:params:oauth:token-type:jwt');
    await expect(c.tokenExchange({ subjectToken: signIn.tokens.accessToken, scopes: ['offline_access'] })).rejects.toMatchObject({ error: 'invalid_scope' });
    await expect(c.tokenExchange({ subjectToken: 'x', actorToken: 'y' })).rejects.toBeInstanceOf(ConfigurationError);
  });
  it('CIBA: start, pending, slow_down (+5 s), approve', async () => {
    const { f, c } = await client(true);
    const start = await c.startCiba({ loginHint: 'pw_user', bindingMessage: 'Code 42', authorizationDetails: [{ type: 'agent_task', description: 'Pay invoice #12' }] });
    expect(start.interval).toBe(2);
    const req = f.ciba.get(start.authReqId)!;
    req.slowDownOnce = true;
    const sleeps: number[] = [];
    const p = c.waitForCiba(start, { sleep: async (ms) => { sleeps.push(ms); if (sleeps.length === 3) req.status = 'approved'; } });
    const tokens = await p;
    expect(tokens.accessToken).toBeTruthy();
    expect(sleeps).toEqual([2000, 7000, 7000]);
    expect(f.calls.find((x) => x.url.endsWith('/bc-authorize'))!.body!.get('binding_message')).toBe('Code 42');
  });
  it('CIBA: denial surfaces access_denied; exactly one hint required; public clients refused', async () => {
    const { f, c } = await client(true);
    const start = await c.startCiba({ loginHint: 'pw_user' });
    f.ciba.get(start.authReqId)!.status = 'denied';
    await expect(c.waitForCiba(start, { sleep: async () => {} })).rejects.toMatchObject({ error: 'access_denied' });
    await expect(c.startCiba({})).rejects.toThrow(/exactly one/);
    const pub = new IdentviaServerClient({ issuer: ISSUER, clientId: f.clientId, redirectUri: 'https://app.example.com/callback', fetch: f.fetch });
    await expect(pub.startCiba({ loginHint: 'x' })).rejects.toBeInstanceOf(ConfigurationError);
    void TokenError;
  });
  it('introspection needs a confidential client', async () => {
    const { f, c } = await client(false);
    const { url, transaction } = await c.createAuthorizationRequest();
    const s = await c.completeAuthorization(new URL(f.authorize(url)).searchParams, transaction);
    expect((await c.introspect(s.tokens.accessToken)).active).toBe(true);
    expect((await c.introspect('nope')).active).toBe(false);
  });
});
