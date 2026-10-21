import { IdentviaAuth, type CookieSource, type IdentviaAuthOptions, type IdentviaSession } from './web.js';

export interface NextIdentvia {
  auth: IdentviaAuth;
  /** `export const { GET, POST } = identvia.handlers` in app/auth/[...identvia]/route.ts (or wherever basePath points). */
  handlers: { GET: (req: Request) => Promise<Response>; POST: (req: Request) => Promise<Response> };
  /** In Server Components / Route Handlers: `await identvia.getSession(await cookies())`. Does not refresh. */
  getSession(cookies: CookieSource | Request): Promise<IdentviaSession | null>;
  /** In Route Handlers: returns a fresh access token and cookies to set (refresh rotation). */
  getAccessToken(req: Request): Promise<{ accessToken: string | null; setCookies: string[] }>;
  /** For middleware.ts: redirects to sign-in when there is no session on protected paths. */
  middleware(req: Request, opts?: { protect?: (pathname: string) => boolean }): Promise<Response | undefined>;
}

/** Next.js App Router integration (also works in any Web-standard runtime: Remix, Hono, SvelteKit endpoints, Bun). */
export function createIdentviaNext(options: IdentviaAuthOptions): NextIdentvia {
  const auth = new IdentviaAuth(options);
  const handle = async (req: Request) => (await auth.handle(req)) ?? new Response('Not found', { status: 404 });
  return {
    auth,
    handlers: { GET: handle, POST: handle },
    getSession: (c) => auth.getSession(c),
    async getAccessToken(req) {
      const { session, setCookies } = await auth.getFreshSession(req);
      return { accessToken: session?.accessToken ?? null, setCookies };
    },
    async middleware(req, opts = {}) {
      const url = new URL(req.url);
      const r = auth.routes;
      if ([r.login, r.logout, r.callback, r.session].includes(url.pathname)) return undefined;
      if (opts.protect && !opts.protect(url.pathname)) return undefined;
      const s = await auth.getSession(req);
      if (s) return undefined;
      const login = new URL(r.login, url.origin);
      login.searchParams.set('returnTo', url.pathname + url.search);
      return Response.redirect(login.toString(), 302);
    },
  };
}

export { IdentviaAuth };
export type { IdentviaAuthOptions, IdentviaSession };
