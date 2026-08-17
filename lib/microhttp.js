/**
 * Minimal dependency-free HTTP server + router shared by the API and the
 * external-execution simulator. Not a general framework: just enough routing,
 * JSON handling, and CORS for a private, JSON-only service surface.
 */
import http from 'node:http';

const MAX_BODY_BYTES = 1024 * 1024; // §13.7 payload size limit

function compilePath(pattern) {
  const names = [];
  const source = pattern
    .split('/')
    .map((segment) => {
      if (segment.startsWith(':')) {
        names.push(segment.slice(1));
        return '([^/]+)';
      }
      return segment.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    })
    .join('/');
  return { regex: new RegExp(`^${source}/?$`), names };
}

export function createApp({ name, cors = true }) {
  const routes = [];

  const register = (method, pattern, handler) => {
    routes.push({ method, pattern, handler, ...compilePath(pattern) });
  };

  const app = {
    name,
    get: (p, h) => register('GET', p, h),
    post: (p, h) => register('POST', p, h),
    put: (p, h) => register('PUT', p, h),
    del: (p, h) => register('DELETE', p, h),
    routes,
  };

  app.handler = async (req, res) => {
    const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);

    if (cors) {
      res.setHeader('Access-Control-Allow-Origin', '*');
      res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, Idempotency-Key');
      res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    }
    if (req.method === 'OPTIONS') {
      res.writeHead(204).end();
      return;
    }

    const match = routes
      .map((route) => ({ route, m: route.method === req.method ? route.regex.exec(url.pathname) : null }))
      .find((candidate) => candidate.m);

    if (!match) {
      send(res, 404, { error: { code: 'not-found', message: `no route for ${req.method} ${url.pathname}` } });
      return;
    }

    const params = {};
    match.route.names.forEach((n, i) => {
      params[n] = decodeURIComponent(match.m[i + 1]);
    });

    let body = null;
    if (req.method === 'POST' || req.method === 'PUT') {
      try {
        body = await readJsonBody(req);
      } catch (err) {
        send(res, 400, { error: { code: 'invalid-input', message: err.message } });
        return;
      }
    }

    const ctx = {
      params,
      query: Object.fromEntries(url.searchParams.entries()),
      body,
      headers: req.headers,
      path: url.pathname,
      method: req.method,
    };

    try {
      const result = await match.route.handler(ctx);
      if (result === undefined) {
        send(res, 204, null);
        return;
      }
      const { status = 200, body: payload = null, headers = {} } = result;
      send(res, status, payload, headers);
    } catch (err) {
      // Never leak stack traces or payloads to callers (§9.5).
      const status = err.httpStatus || 500;
      const code = err.code || 'internal-error';
      // eslint-disable-next-line no-console
      console.error(`[${name}] ${code}:`, err.message);
      send(res, status, { error: { code, message: err.publicMessage || err.message || 'internal error' } });
    }
  };

  app.listen = (port) =>
    new Promise((resolve) => {
      const server = http.createServer(app.handler);
      server.listen(port, () => resolve(server));
    });

  return app;
}

export function send(res, status, payload, headers = {}) {
  const text = payload === null ? '' : JSON.stringify(payload, null, 2);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    ...headers,
  });
  res.end(text);
}

function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        reject(new Error('request body exceeds size limit'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf8');
      if (!raw.trim()) {
        resolve({});
        return;
      }
      try {
        resolve(JSON.parse(raw));
      } catch {
        reject(new Error('body is not valid JSON'));
      }
    });
    req.on('error', reject);
  });
}

export function httpError(code, message, httpStatus = 400) {
  const err = new Error(message);
  err.code = code;
  err.httpStatus = httpStatus;
  return err;
}
