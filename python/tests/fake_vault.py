"""A scriptable stand-in for Vault, served from a background thread.

    with FakeVault({'secret/data/a/b': {'status': 200, 'body': {...}}}, token='t') as v:
        v.addr, v.requests

Routes are keyed by the path after /v1/. A response is {"status", "body"}, or
{"hang": true} to never answer, or {"redirect": url} for a 307. With a list,
each request takes the next entry and the last one repeats. The same shape as
node/test/fake-vault.cjs. `approle={'role_id', 'secret_id'[, 'mount']}` answers
POST auth/approle/login with `token` when the body matches (400 otherwise); a
route for the login path takes precedence. Login needs no token. Recorded
bodies mask secret_id.
"""

import json
import socketserver
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer


class _Server(socketserver.ThreadingMixIn, HTTPServer):
    daemon_threads = True


class FakeVault(object):
    def __init__(self, routes, token=None, approle=None):
        self.routes = routes
        self.token = token
        self.approle = approle
        self.requests = []
        self._counters = {}
        self._stop = threading.Event()
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                fake._handle(self)

            def do_POST(self):
                fake._handle(self)

        self._server = _Server(('127.0.0.1', 0), Handler)
        self.addr = 'http://127.0.0.1:%d' % self._server.server_address[1]
        threading.Thread(target=self._server.serve_forever, kwargs={'poll_interval': 0.05}, daemon=True).start()

    def _handle(self, h):
        p = urllib.parse.unquote(urllib.parse.urlsplit(h.path).path)
        p = p[len('/v1/'):] if p.startswith('/v1/') else p
        length = int(h.headers.get('Content-Length') or 0)
        raw = h.rfile.read(length) if length else b''
        try:
            body = json.loads(raw.decode()) if raw else None
        except ValueError:
            body = 'unparseable'
        shown = dict(body, secret_id='***') if isinstance(body, dict) and 'secret_id' in body else body
        self.requests.append({'method': h.command, 'path': p, 'token': h.headers.get('X-Vault-Token'),
                              'ua': h.headers.get('User-Agent'), 'ns': h.headers.get('X-Vault-Namespace'), 'body': shown})

        def send(status, body=None, headers=None):
            data = json.dumps(body).encode() if body is not None else b''
            h.send_response(status)
            h.send_header('Content-Type', 'application/json')
            h.send_header('Content-Length', str(len(data)))
            for k, v in (headers or {}).items():
                h.send_header(k, v)
            h.end_headers()
            h.wfile.write(data)

        login = h.command == 'POST' and p.startswith('auth/') and p.endswith('/login')
        if login and p not in self.routes and self.approle:
            a = self.approle
            if p != 'auth/%s/login' % a.get('mount', 'approle'):
                return send(404, {'errors': []})
            if not isinstance(body, dict) or body.get('role_id') != a['role_id'] or ('secret_id' in a and body.get('secret_id') != a['secret_id']):
                return send(400, {'errors': ['invalid role or secret ID']})
            return send(200, {'auth': {'client_token': self.token, 'accessor': 'acc', 'policies': ['default'], 'token_policies': ['default'],
                                       'lease_duration': 3600, 'renewable': True, 'metadata': {'role_name': 'r'}}})
        if not login and self.token and h.headers.get('X-Vault-Token') != self.token:
            return send(403, {'errors': ['permission denied']})
        r = self.routes.get(p)
        if r is None:
            return send(404, {'errors': []})
        if isinstance(r, list):
            i = self._counters.get(p, 0)
            self._counters[p] = i + 1
            r = r[min(i, len(r) - 1)]
        if r.get('hang'):
            self._stop.wait(30)  # never answers: exercises the client timeout
            return
        if r.get('redirect'):
            return send(307, None, {'Location': r['redirect']})
        if r.get('delay'):
            time.sleep(r['delay'])
        return send(r.get('status', 200), r.get('body'))

    def paths(self):
        return [r['path'] for r in self.requests]

    def close(self):
        self._stop.set()
        self._server.shutdown()
        self._server.server_close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
