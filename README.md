# Identvia for JavaScript & TypeScript

Sign in with Identvia for browsers, Node.js, Express, Next.js and React.

| Package | What it is |
|---|---|
| [`@identvia/js`](packages/js) | Browser SPA client (`IdentviaClient`): redirect and popup sign-in, silent refresh. Also includes `@identvia/js/server`, `/express` and `/next` |
| [`@identvia/react`](packages/react) | `IdentviaProvider`, `useIdentvia()`, `<SignInWithIdentvia/>`, `<SignedIn/>`, `<SignedOut/>` |

```bash
npm install @identvia/js            # + @identvia/react for React
```

## Quickstart: single-page app (public client, no secret)

```ts
import { IdentviaClient } from '@identvia/js';

const identvia = new IdentviaClient({
  clientId: 'oid_…',                                   // a *public* client from the developer portal
  redirectUri: `${location.origin}/callback`,
  scopes: ['email', 'profile', 'offline_access'],       // offline_access → refresh tokens
  storage: 'session',                                   // 'memory' (default) | 'session' | 'local' | custom
});

button.onclick = () => identvia.signInWithRedirect({ returnTo: '/dashboard' });

// on /callback
if (IdentviaClient.isRedirectCallback()) {
  const { user, returnTo } = await identvia.handleRedirectCallback();
}

const token = await identvia.getAccessToken();         // refreshes with rotation when needed
await identvia.signOut();                              // revokes the refresh token
```

## Quickstart: Express (confidential client)

```ts
import express from 'express';
import { identvia } from '@identvia/js/express';

const app = express();
const auth = identvia({
  clientId: process.env.IDENTVIA_CLIENT_ID,
  clientSecret: process.env.IDENTVIA_CLIENT_SECRET,
  redirectUri: 'https://app.example.com/auth/callback',
  secret: process.env.SESSION_SECRET,                  // ≥ 32 random chars; encrypts the session cookie
});
app.use(auth);                                          // /auth/login, /auth/callback, POST /auth/logout, /auth/session
app.get('/account', auth.requireAuth(), (req, res) => res.json(req.identvia.user));
```

## Quickstart: Next.js App Router

```ts
// lib/identvia.ts
export const identvia = createIdentviaNext({ clientId, clientSecret, redirectUri: 'https://app.example.com/auth/callback', secret });
// app/auth/[...identvia]/route.ts
export const { GET, POST } = identvia.handlers;
// any Server Component
const session = await identvia.getSession(await cookies());
```

## Quickstart: React

```tsx
<IdentviaProvider clientId="oid_…" redirectUri={`${location.origin}/callback`}>
  <SignedOut><SignInWithIdentvia theme="dark" /></SignedOut>
  <SignedIn><Profile /></SignedIn>
</IdentviaProvider>
```

## What the SDK enforces

* Authorization Code with **PKCE S256** on every request, plus `state` and `nonce`. The transaction can be used once and expires after 15 minutes.
* **RFC 9207** `iss` is checked on the callback, which stops mix-up attacks.
* **ID tokens** are checked for signature (JWKS, `RS256`/`ES256` only), `iss`, `aud`, `azp`, `exp`, `iat`, `nonce`, `auth_time`/`max_age` and `at_hash`. Verification uses [jose](https://github.com/panva/jose). An unknown `kid` triggers at most one JWKS refetch every 30 s.
* **Refresh rotation:** the new refresh token is always stored. Refreshes are single-flight within a tab and serialised across tabs with Web Locks. A reused-token `invalid_grant` signs the user out.
* **Public clients in the browser:** `IdentviaClient` refuses a `clientSecret`.
* **Redirect URIs:** https only (http only for loopback). `returnTo` must be a same-site relative path, so it can't be used as an open redirect.
* **Server sessions:** the cookie is AES-256-GCM encrypted (JWE `dir`), `HttpOnly`, `SameSite=Lax` and `__Host-` prefixed on https. Logout is POST-only and same-origin only.
* `sub` is **pairwise**: it is stable for your app and different in every other app. Store `sub`, not the email.

## Delegation standards (optional, requires server 2026-10-21_5+)

```ts
import { IdentviaServerClient, agentTask } from '@identvia/js/server';
// RFC 9396 Rich Authorization Requests (browser or server)
await identvia.signInWithRedirect({ authorizationDetails: [agentTask({ description: 'Book a table for 2 on Friday' })] });
// RFC 8693 Token Exchange: narrower, shorter token naming the acting agent
await server.tokenExchange({ subjectToken, scopes: ['email'], actorToken, actorTokenType: 'urn:ietf:params:oauth:token-type:jwt' });
// OpenID CIBA: approval in the person's Identvia inbox, no redirect
const start = await server.startCiba({ loginHint: user.sub, bindingMessage: 'Code 4821' });
const tokens = await server.waitForCiba(start);
```

On older servers these throw `UnsupportedError`. The SDK reads discovery and never guesses endpoints.

## Development

```bash
pnpm install && pnpm build && pnpm test        # unit tests (fake Identvia with real RSA keys)
# against a real Identvia server:
php tools/live/helper.php setup http://localhost:8180 /tmp/live-state.json
IDENTVIA_LIVE_STATE=/tmp/live-state.json pnpm -C packages/js test:live
```

MIT licensed. Security issues: security@identvia.com.
