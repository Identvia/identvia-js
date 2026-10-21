import { identvia } from './lib/identvia';

export async function middleware(req: Request) {
  return identvia.middleware(req, { protect: (p) => p.startsWith('/dashboard') });
}
export const config = { matcher: ['/dashboard/:path*'] };
