# Changelog

## 0.1.0 (2026-10-21)

### @identvia/js
* `IdentviaClient` for browser SPAs: redirect and popup sign-in, PKCE S256, state, nonce and RFC 9207 iss checks. Refresh-token rotation is single-flight and cross-tab. Token storage options, `fetchUserInfo` (CORS-simple POST) and `signOut` with revocation and optional RP-initiated logout.
* `@identvia/js/server`: `IdentviaServerClient` (confidential or public), introspection and `IdentviaAuth` (Web Request/Response).
* `@identvia/js/express`: middleware with `requireAuth()`.
* `@identvia/js/next`: App Router handlers, `getSession`, `getAccessToken` and `middleware`.
* Delegation standards (requires server 2026-10-21_5+): RFC 9396 `authorization_details` with `agentTask()`, RFC 8693 `tokenExchange` and OpenID CIBA (`startCiba`, `pollCiba`, `waitForCiba`).

### @identvia/react
* `IdentviaProvider`, `useIdentvia`, `SignedIn` and `SignedOut`.
* `<SignInWithIdentvia/>`, which looks and behaves like button.js v1.0.0.
