import { createIdentviaNext } from '@identvia/js/next';

export const identvia = createIdentviaNext({
  issuer: process.env.IDENTVIA_ISSUER ?? 'https://id.identvia.com',
  clientId: process.env.IDENTVIA_CLIENT_ID!,
  clientSecret: process.env.IDENTVIA_CLIENT_SECRET,     // server-only env var (no NEXT_PUBLIC_ prefix!)
  redirectUri: process.env.IDENTVIA_REDIRECT_URI ?? 'http://localhost:3000/auth/callback',
  scopes: ['email', 'profile', 'offline_access'],
  secret: process.env.IDENTVIA_SESSION_SECRET!,
});
