import type { IncomingMessage, ServerResponse } from 'node:http';
import { IdentviaAuth, type IdentviaAuthOptions, type IdentviaSession } from './web.js';

type Next = (err?: unknown) => void;
interface Req extends IncomingMessage { identvia?: { session: IdentviaSession | null; user: IdentviaSession['user'] | null }; originalUrl?: string; body?: unknown }

declare module 'node:http' {
  interface IncomingMessage { identvia?: { session: IdentviaSession | null; user: IdentviaSession['user'] | null } }
}

/** Builds a Web Request from a Node request. The origin comes from your redirectUri, never from the Host header. */
function toRequest(req: Req, origin: string): Request {
  const headers = new Headers();
  for (const [k, v] of Object.entries(req.headers)) {
    if (v === undefined) continue;
    if (Array.isArray(v)) for (const x of v) headers.append(k, x); else headers.set(k, String(v));
  }
  return new Request(new URL(req.originalUrl ?? req.url ?? '/', origin), { method: req.method ?? 'GET', headers });
}

async function send(res: ServerResponse, r: Response): Promise<void> {
  res.statusCode = r.status;
  r.headers.forEach((v, k) => { if (k.toLowerCase() !== 'set-cookie') res.setHeader(k, v); });
  const cookies = typeof (r.headers as Headers & { getSetCookie?: () => string[] }).getSetCookie === 'function' ? (r.headers as Headers & { getSetCookie: () => string[] }).getSetCookie() : [];
  if (cookies.length) appendCookies(res, cookies);
  res.end(r.body ? Buffer.from(await r.arrayBuffer()) : undefined);
}

function appendCookies(res: ServerResponse, cookies: string[]) {
  if (!cookies.length) return;
  const prev = res.getHeader('Set-Cookie');
  const list = prev === undefined ? [] : Array.isArray(prev) ? prev : [String(prev)];
  res.setHeader('Set-Cookie', [...list, ...cookies]);
}

export interface ExpressIdentvia {
  (req: IncomingMessage, res: ServerResponse, next: Next): void;
  auth: IdentviaAuth;
  /** Redirects browsers to sign-in (HTML) or answers 401 JSON (API calls). */
  requireAuth(): (req: IncomingMessage, res: ServerResponse, next: Next) => void;
}

/**
 * Express / Connect middleware. Mount once: `app.use(identvia({...}))`. Adds /auth/login, the callback,
 * POST /auth/logout and /auth/session, and sets `req.identvia.user` on every request (refreshing tokens when needed).
 */
export function identvia(options: IdentviaAuthOptions): ExpressIdentvia {
  const auth = new IdentviaAuth(options);
  const origin = new URL(auth.client.redirectUri).origin;
  const mw = ((req: Req, res: ServerResponse, next: Next) => {
    (async () => {
      const r = await auth.handle(toRequest(req, origin));
      if (r) return send(res, r);
      const { session, setCookies } = await auth.getFreshSession(req.headers.cookie);
      appendCookies(res, setCookies);
      req.identvia = { session, user: session?.user ?? null };
      next();
    })().catch(next);
  }) as ExpressIdentvia;
  mw.auth = auth;
  mw.requireAuth = () => (req: Req, res: ServerResponse, next: Next) => {
    if (req.identvia?.user) return next();
    const accept = String(req.headers.accept ?? '');
    if (accept.includes('text/html')) {
      const here = req.originalUrl ?? req.url ?? '/';
      res.statusCode = 302;
      res.setHeader('Location', `${auth.routes.login}?returnTo=${encodeURIComponent(here)}`);
      res.end();
      return;
    }
    res.statusCode = 401;
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('WWW-Authenticate', 'Bearer');
    res.end(JSON.stringify({ error: 'unauthenticated' }));
  };
  return mw;
}

export { IdentviaAuth };
export type { IdentviaAuthOptions, IdentviaSession };
