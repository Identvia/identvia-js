// Tiny static server for the example (no build step). `IDENTVIA_ISSUER=… IDENTVIA_CLIENT_ID=… node server.mjs`
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { extname, join, normalize } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = fileURLToPath(new URL('.', import.meta.url));
const pkg = join(here, '../../packages/js');
const port = Number(process.env.PORT ?? 4300);
const types = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.css': 'text/css', '.json': 'application/json', '.map': 'application/json' };
const config = { issuer: process.env.IDENTVIA_ISSUER ?? 'https://id.identvia.com', clientId: process.env.IDENTVIA_CLIENT_ID ?? 'oid_your_public_client_id' };

createServer(async (req, res) => {
  const path = new URL(req.url, 'http://x').pathname;
  let file;
  if (path === '/' || path === '/callback' || path === '/popup-callback') file = join(here, 'index.html');
  else if (path === '/config.json') return send(res, 200, '.json', JSON.stringify(config));
  else if (path === '/button.js') file = join(here, 'button.js');
  else if (path.startsWith('/sdk/')) file = join(pkg, 'dist', normalize(path.slice(5)));
  else if (path.startsWith('/jose/')) file = join(pkg, 'node_modules/jose/dist/browser', normalize(path.slice(6)));
  else file = join(here, normalize(path));
  if (!file.startsWith(here) && !file.startsWith(pkg)) return send(res, 403, '.html', 'Forbidden');
  try {
    let body = await readFile(file);
    // No bundler: point bare imports at the files we serve.
    if (extname(file) === '.js') body = body.toString().replace(/from ['"]@identvia\/js['"]/g, "from '/sdk/index.js'").replace(/from ['"]jose['"]/g, "from '/jose/index.js'");
    send(res, 200, extname(file), body);
  } catch { send(res, 404, '.html', 'Not found'); }
}).listen(port, () => console.log(`SPA example on http://localhost:${port}`));

function send(res, status, ext, body) {
  res.writeHead(status, { 'Content-Type': types[ext] ?? 'application/octet-stream', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' });
  res.end(body);
}
