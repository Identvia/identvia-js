// Express + @identvia/js/express. Confidential client: the secret stays on the server.
//   IDENTVIA_CLIENT_ID=… IDENTVIA_CLIENT_SECRET=… SESSION_SECRET=$(openssl rand -base64 48) node server.mjs
import express from 'express';
import { identvia } from '@identvia/js/express';

const app = express();
const auth = identvia({
  issuer: process.env.IDENTVIA_ISSUER ?? 'https://id.identvia.com',
  clientId: process.env.IDENTVIA_CLIENT_ID,
  clientSecret: process.env.IDENTVIA_CLIENT_SECRET,
  redirectUri: process.env.IDENTVIA_REDIRECT_URI ?? 'http://localhost:4301/auth/callback',
  scopes: ['email', 'profile', 'offline_access'],
  secret: process.env.SESSION_SECRET,   // ≥ 32 random characters
});
app.use(auth); // /auth/login, /auth/callback, POST /auth/logout, /auth/session; sets req.identvia

const page = (body) => `<!doctype html><meta charset=utf-8><title>Identvia Express example</title>
<script src="https://id.identvia.com/sdk/v1/button.js" defer></script>
<main style="font-family:system-ui;max-width:560px;margin:10vh auto">${body}</main>`;

app.get('/', (req, res) => {
  const user = req.identvia.user;
  res.send(page(user
    ? `<p>Signed in as <b>${escape(user.email ?? user.sub)}</b>. <a href="/account">Account</a></p>
       <form method="post" action="/auth/logout"><button>Sign out</button></form>`
    : `<a class="identvia-btn" href="/auth/login?returnTo=/account" data-theme="dark">Sign in with Identvia</a>`));
});

app.get('/account', auth.requireAuth(), (req, res) => {
  res.send(page(`<h1>Account</h1><p>Your app-specific user ID (pairwise sub): <code>${escape(req.identvia.user.sub)}</code></p><p><a href="/">Home</a></p>`));
});

app.get('/api/me', auth.requireAuth(), (req, res) => res.json(req.identvia.user));

app.listen(4301, () => console.log('http://localhost:4301'));

function escape(s) { return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]); }
