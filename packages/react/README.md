# @identvia/react

```tsx
import { IdentviaProvider, SignInWithIdentvia, SignedIn, SignedOut, useIdentvia } from '@identvia/react';
```

* `<IdentviaProvider clientId redirectUri scopes storage>` handles the redirect callback automatically.
* `useIdentvia()` → `{ isLoading, isAuthenticated, user, error, signIn, signInWithPopup, signOut, getAccessToken }`
* `<SignInWithIdentvia theme="light|dark|brand|auto" size="small|medium|large" shape="rect|rounded|pill" text="signin|continue|signup|icon" mode="redirect|popup" href?>`. It's the official button, with the same CSS as button.js. Pass `href="/auth/login"` for server-rendered apps.

MIT
