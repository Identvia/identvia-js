/**
 * Real Chrome + real Identvia (stage 4) + examples/spa-vanilla served from http://localhost:4300.
 * Proves the SPA client works cross-origin (CORS on token/userinfo/revoke), under a strict CSP, with redirect and popup.
 *   IDENTVIA_LIVE_STATE=./live-spa.json IDENTVIA_MAILDIR=<dev server mail dir> node test-live/spa-browser.cjs   (needs playwright)
 */
const { chromium } = require('playwright');
const { spawn } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const S = JSON.parse(fs.readFileSync(process.env.IDENTVIA_LIVE_STATE, 'utf8'));
const MAIL = process.env.IDENTVIA_MAILDIR;
if (!MAIL) throw new Error('Set IDENTVIA_MAILDIR to the dev server mail directory');
let pass = 0, fail = 0;
const check = (n, ok, d = '') => { ok ? pass++ : fail++; console.log(`${ok ? '  PASS' : '  FAIL'} ${n}${d ? `  [${d}]` : ''}`); };

(async () => {
  const srv = spawn('node', [path.join(__dirname, '../../../examples/spa-vanilla/server.mjs')], { env: { ...process.env, IDENTVIA_ISSUER: S.base, IDENTVIA_CLIENT_ID: S.publicClientId, PORT: '4300' }, stdio: 'pipe' });
  await new Promise((r) => srv.stdout.once('data', r));
  const browser = await chromium.launch({ channel: 'chrome', args: ['--no-sandbox'] });
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  const errors = [];
  page.on('console', (m) => { if (m.type() === 'error') errors.push(m.text()); });
  page.on('pageerror', (e) => errors.push(String(e)));
  try {
    // Sign the user in to Identvia itself (magic link from the file mailer)
    await page.goto(`${S.base}/login`);
    await page.fill('#email', S.userEmail);
    await Promise.all([page.waitForLoadState(), page.press('#email', 'Enter')]);
    await page.waitForTimeout(400);
    const files = fs.readdirSync(MAIL).filter((f) => f.endsWith('-magic_link.eml')).sort().reverse();
    let link = '';
    for (const f of files) { const raw = fs.readFileSync(path.join(MAIL, f), 'latin1').replace(/=\r?\n/g, '').replace(/=3D/g, '='); if (raw.includes(`To: ${S.userEmail}`)) { link = (raw.match(/https?:\/\/[^\s"<]+\/auth\/magic\?token=[A-Za-z0-9_\-%]+/) || [''])[0]; break; } }
    await page.goto(link);
    await Promise.all([page.waitForLoadState(), page.click('button[type=submit]')]);
    check('signed in to Identvia', !page.url().includes('/login'), page.url());

    // SPA: redirect sign-in
    await page.goto('http://localhost:4300/');
    await page.waitForSelector('#signin[data-identvia-ready]');
    check('button.js rendered the brand button', (await page.textContent('#signin')).includes('Sign in with Identvia'));
    const [authReq] = await Promise.all([page.waitForRequest(/\/oauth\/authorize\?/), page.click('#signin')]);
    const authUrl = new URL(authReq.url());
    await page.waitForLoadState();
    check('authorize request has PKCE S256 + state + nonce', authUrl.searchParams.get('code_challenge_method') === 'S256' && !!authUrl.searchParams.get('state') && !!authUrl.searchParams.get('nonce'));
    if (page.url().includes('/oauth/authorize') && await page.$('button[name=action][value=approve]')) await page.click('button[name=action][value=approve]');
    await page.waitForURL('http://localhost:4300/');
    await page.waitForSelector('#signed-in:not([hidden])', { timeout: 10000 });
    check('signed in to the SPA', (await page.textContent('#who')) === S.userEmail, await page.textContent('#who'));
    check('code and state stripped from the address bar', !page.url().includes('code='));
    await page.click('#userinfo');
    await page.waitForFunction(() => document.getElementById('out').textContent.includes('sub'));
    check('userinfo cross-origin (CORS) works', (await page.textContent('#out')).includes(S.userEmail));
    const rt1 = await page.evaluate(() => { const k = Object.keys(sessionStorage).find((x) => x.endsWith(':session')); return JSON.parse(sessionStorage.getItem(k)).tokens.refreshToken; });
    await page.click('#refresh');
    await page.waitForFunction(() => document.getElementById('out').textContent.includes('Refreshed'));
    const rt2 = await page.evaluate(() => { const k = Object.keys(sessionStorage).find((x) => x.endsWith(':session')); return JSON.parse(sessionStorage.getItem(k)).tokens.refreshToken; });
    check('refresh token rotated in the browser', rt1 && rt2 && rt1 !== rt2);
    const tx = await page.evaluate(() => Object.keys(sessionStorage).filter((k) => k.includes(':tx:')).length);
    check('no sign-in transaction left behind', tx === 0);
    // Sign out: revokes; the old refresh token no longer works
    await page.click('#signout');
    await page.waitForSelector('#signed-out:not([hidden])');
    const res = await fetch(`${S.base}/oauth/token`, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: rt2, client_id: S.publicClientId }) });
    check('sign-out revoked the refresh token', res.status === 400 || res.status === 401, String(res.status));

    // Popup sign-in
    const [popup] = await Promise.all([page.waitForEvent('popup'), page.click('#signin-popup')]);
    await Promise.race([
      popup.waitForSelector('button[name=action][value=approve]', { timeout: 8000 }).then((b) => b.click()).catch(() => {}),
      page.waitForSelector('#signed-in:not([hidden])', { timeout: 8000 }).catch(() => {}),
    ]);
    await page.waitForSelector('#signed-in:not([hidden])', { timeout: 10000 });
    check('popup sign-in completed in the opener', (await page.textContent('#who')) === S.userEmail);
    await popup.waitForEvent('close', { timeout: 5000 }).catch(() => {});
    check('popup closed itself', popup.isClosed());

    // Forged callback is rejected
    await page.goto('http://localhost:4300/callback?code=abc&state=' + 'A'.repeat(43) + '&iss=' + encodeURIComponent(S.base));
    await page.waitForFunction(() => document.getElementById('error').textContent.length > 0);
    check('forged callback rejected', /does not match a sign-in/.test(await page.textContent('#error')));
    const csp = errors.filter((e) => /Content Security Policy|Refused/.test(e));
    check('no CSP violations', csp.length === 0, csp.join(' | '));
  } catch (e) {
    check('unexpected error', false, e.stack);
  } finally {
    await browser.close();
    srv.kill();
    console.log(`\n${pass} passed, ${fail} failed`);
    process.exit(fail ? 1 : 0);
  }
})();
