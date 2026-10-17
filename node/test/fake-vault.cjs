'use strict';
// A scriptable stand-in for Vault, run as its own process so that tests can
// exercise loadSync() (which blocks the parent's event loop).
//
//   node fake-vault.cjs <scenario.json>
// prints "PORT <n>" once listening. GET /_requests returns what it has seen.
//
// Scenario: { "token": "t", "routes": { "<path after /v1/>": response | [response, ...] } }
// A response is { "status": 200, "body": {...} } or { "delayMs": n, ... }. With an
// array, each request takes the next entry and the last one repeats.
// "approle": { "role_id": "r", "secret_id": "s" } answers POST auth/approle/login
// with "token" when the body matches (400 otherwise); a route for the login path
// takes precedence. Login needs no token. Recorded bodies mask secret_id.

const fs = require('fs');
const http = require('http');

const scenario = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const seen = [];
const counters = {};

const server = http.createServer((req, res) => {
  const url = new URL(req.url, 'http://x');
  if (url.pathname === '/_requests') {
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify(seen));
    return;
  }
  const p = decodeURIComponent(url.pathname.replace(/^\/v1\//, ''));
  let raw = '';
  req.on('data', (c) => (raw += c));
  req.on('end', () => handle(req, res, p, raw));
});

function handle(req, res, p, raw) {
  let body = null;
  try {
    body = raw ? JSON.parse(raw) : null;
  } catch (e) {
    body = 'unparseable';
  }
  const shown = body && typeof body === 'object' && 'secret_id' in body ? Object.assign({}, body, { secret_id: '***' }) : body;
  seen.push({ method: req.method, path: p, token: req.headers['x-vault-token'] || null, ua: req.headers['user-agent'] || null, ns: req.headers['x-vault-namespace'] || null, body: shown });
  const send = (status, b) => {
    res.statusCode = status;
    res.setHeader('content-type', 'application/json');
    res.end(b === undefined ? undefined : JSON.stringify(b));
  };
  const login = req.method === 'POST' && /^auth\/.+\/login$/.test(p);
  if (login && scenario.routes[p] === undefined && scenario.approle) {
    const a = scenario.approle;
    if (p !== `auth/${a.mount || 'approle'}/login`) return send(404, { errors: [] });
    if (!body || body.role_id !== a.role_id || (a.secret_id !== undefined && body.secret_id !== a.secret_id)) return send(400, { errors: ['invalid role or secret ID'] });
    return send(200, { auth: { client_token: scenario.token, accessor: 'acc', policies: ['default'], token_policies: ['default'], lease_duration: 3600, renewable: true, metadata: { role_name: 'r' } } });
  }
  if (!login && scenario.token && req.headers['x-vault-token'] !== scenario.token) return send(403, { errors: ['permission denied'] });
  let r = scenario.routes[p];
  if (r === undefined) return send(404, { errors: [] });
  if (Array.isArray(r)) {
    const i = counters[p] || 0;
    counters[p] = i + 1;
    r = r[Math.min(i, r.length - 1)];
  }
  if (r.hang) return; // never answers: exercises the client timeout
  setTimeout(() => send(r.status || 200, r.body), r.delayMs || 0);
}

server.listen(0, '127.0.0.1', () => {
  process.stdout.write(`PORT ${server.address().port}\n`);
});
