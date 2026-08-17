/**
 * UI host. A deliberately dumb static file server: it holds no credentials,
 * no domain logic, and no privileged path to the control plane. The browser
 * talks to the defense-validation API directly over its private ingress.
 */
import http from 'node:http';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const PORT = Number(process.env.UI_PORT ?? 5173);
const API_BASE_URL = process.env.API_BASE_URL ?? `http://localhost:${process.env.API_PORT ?? 8088}`;
const SIM_BASE_URL = process.env.SIM_BASE_URL ?? `http://localhost:${process.env.SIM_PORT ?? 8099}`;
const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), 'public');

const TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.json': 'application/json; charset=utf-8',
};

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://localhost:${PORT}`);

  if (url.pathname === '/config.js') {
    res.writeHead(200, { 'Content-Type': TYPES['.js'], 'Cache-Control': 'no-store' });
    res.end(`window.__DV_CONFIG__ = ${JSON.stringify({ apiBaseUrl: API_BASE_URL, simBaseUrl: SIM_BASE_URL })};`);
    return;
  }

  const requested = url.pathname === '/' ? '/index.html' : url.pathname;
  const resolved = path.join(ROOT, path.normalize(requested).replace(/^(\.\.[/\\])+/, ''));
  if (!resolved.startsWith(ROOT)) {
    res.writeHead(403).end('forbidden');
    return;
  }

  try {
    const file = await readFile(resolved);
    res.writeHead(200, { 'Content-Type': TYPES[path.extname(resolved)] ?? 'application/octet-stream', 'Cache-Control': 'no-store' });
    res.end(file);
  } catch {
    // Single-page app: unknown paths fall back to the shell.
    const shell = await readFile(path.join(ROOT, 'index.html'));
    res.writeHead(200, { 'Content-Type': TYPES['.html'] }).end(shell);
  }
});

server.listen(PORT, () => {
  // eslint-disable-next-line no-console
  console.log(`[ui]   defense-validation console on http://localhost:${PORT}  (api: ${API_BASE_URL})`);
});
