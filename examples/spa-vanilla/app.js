import { IdentviaClient } from '@identvia/js';

const cfg = await (await fetch('/config.json')).json();
const identvia = new IdentviaClient({
  issuer: cfg.issuer,                       // default https://id.identvia.com
  clientId: cfg.clientId,                   // a PUBLIC client (no secret)
  redirectUri: `${location.origin}/callback`,
  popupRedirectUri: `${location.origin}/popup-callback`,
  postLogoutRedirectUri: `${location.origin}/`,
  scopes: ['email', 'profile', 'offline_access'],
  storage: 'session',
});

const $ = (id) => document.getElementById(id);
const show = async () => {
  const user = await identvia.getUser();
  $('signed-in').hidden = !user;
  $('signed-out').hidden = !!user;
  if (user) { $('who').textContent = user.email ?? user.name ?? 'you'; $('sub').textContent = `sub: ${user.sub}`; }
};

try {
  if (location.pathname === '/popup-callback') {
    IdentviaClient.handlePopupCallback(cfg.clientId);
  } else if (location.pathname === '/callback' && IdentviaClient.isRedirectCallback()) {
    const { returnTo } = await identvia.handleRedirectCallback();
    history.replaceState(null, '', returnTo ?? '/');
  }
} catch (e) {
  $('error').textContent = e.message;
  history.replaceState(null, '', '/');
}
await show();
identvia.subscribe(show);

$('signin').addEventListener('click', () => identvia.signInWithRedirect({ returnTo: '/' }));
$('signin-popup').addEventListener('click', () => identvia.signInWithPopup().catch((e) => { $('error').textContent = e.message; }));
$('userinfo').addEventListener('click', async () => { $('out').textContent = JSON.stringify(await identvia.fetchUserInfo(), null, 2); });
$('refresh').addEventListener('click', async () => { await identvia.getAccessToken({ forceRefresh: true }); $('out').textContent = 'Refreshed (rotated refresh token).'; });
$('signout').addEventListener('click', () => identvia.signOut());
