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

`jwt={'role', 'certificate' (PEM)[, 'mount']}` answers POST auth/<mount>/login like a
Vault JWT role bound to that certificate: it checks the header fields, x5t#S256, the
signature, iss/sub/aud, the lifetime and that the jti is new (400 otherwise); it
needs the cryptography package. A route entry {"verify": true} hands one request to
it. Recorded bodies mask jwt and carry the decoded header and claims instead.
"""

import base64
import hashlib
import re

import json
import socketserver
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer


class _Server(socketserver.ThreadingMixIn, HTTPServer):
    daemon_threads = True


class FakeVault(object):
    def __init__(self, routes, token=None, approle=None, jwt=None):
        self.routes = routes
        self.token = token
        self.approle = approle
        self.jwt = jwt
        self._jtis = set()
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
        if isinstance(body, dict) and isinstance(body.get('jwt'), str):
            shown = dict(body, jwt='***', assertion=_decoded(body['jwt']))
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

        def jwt_login():
            j = self.jwt
            if p != 'auth/%s/login' % j.get('mount', 'jwt'):
                return send(404, {'errors': []})
            if self._check_assertion(body, j):
                return send(400, {'errors': ['invalid role or JWT']})
            return send(200, {'auth': {'client_token': self.token, 'accessor': 'acc', 'policies': ['default'], 'token_policies': ['default'],
                                       'lease_duration': 3600, 'renewable': True, 'metadata': {'role': j['role']}}})

        if login and p not in self.routes and self.jwt:
            return jwt_login()
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
        if r.get('verify'):
            return jwt_login()
        if r.get('redirect'):
            return send(307, None, {'Location': r['redirect']})
        if r.get('delay'):
            time.sleep(r['delay'])
        return send(r.get('status', 200), r.get('body'))

    def _check_assertion(self, body, j):
        """Like a Vault JWT role: None when the assertion is accepted, else why not."""
        from cryptography import x509
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec, padding, utils
        if not isinstance(body, dict) or body.get('role') != j['role'] or not isinstance(body.get('jwt'), str):
            return 'role'
        parts = body['jwt'].split('.')
        d = _decoded(body['jwt'])
        if len(parts) != 3 or d is None:
            return 'malformed'
        header, claims = d['header'], d['claims']
        if sorted(header) != ['alg', 'typ', 'x5t#S256'] or header['typ'] != 'JWT':
            return 'header'
        der = base64.b64decode(re.sub(r'\s+', '', re.search(r'-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----', j['certificate'], re.S).group(1)))
        if header['x5t#S256'] != _b64url(hashlib.sha256(der).digest()):
            return 'x5t'
        pub = x509.load_der_x509_certificate(der).public_key()
        data = ('%s.%s' % (parts[0], parts[1])).encode()
        sig = _unb64url(parts[2])
        try:
            if header['alg'] == 'RS256':
                pub.verify(sig, data, padding.PKCS1v15(), hashes.SHA256())
            elif header['alg'] in ('ES256', 'ES384'):
                n = 32 if header['alg'] == 'ES256' else 48
                if len(sig) != 2 * n:
                    return 'signature'
                pub.verify(utils.encode_dss_signature(int.from_bytes(sig[:n], 'big'), int.from_bytes(sig[n:], 'big')), data,
                           ec.ECDSA(hashes.SHA256() if n == 32 else hashes.SHA384()))
            else:
                return 'alg'
        except (InvalidSignature, TypeError, ValueError):
            return 'signature'
        now = time.time()
        if claims.get('iss') != j['role'] or claims.get('sub') != j['role']:
            return 'issuer'
        if claims.get('aud') != '%s/v1/auth/%s/login' % (self.addr, j.get('mount', 'jwt')):
            return 'audience'
        if not (claims['exp'] > now - 60 and claims['iat'] <= now + 60 and claims['exp'] - claims['iat'] <= 300):
            return 'time'
        if not isinstance(claims.get('jti'), str) or len(claims['jti']) < 16 or claims['jti'] in self._jtis:
            return 'jti'
        self._jtis.add(claims['jti'])
        return None

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


def _b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


def _unb64url(s):
    return base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))


def _decoded(jwt):
    try:
        h, p = jwt.split('.')[:2]
        return {'header': json.loads(_unb64url(h).decode()), 'claims': json.loads(_unb64url(p).decode())}
    except (ValueError, TypeError):
        return None
