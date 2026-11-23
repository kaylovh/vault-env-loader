"""Runs the shared conformance cases in ../../spec/cases.json."""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
import vault_env_loader as V  # noqa: E402

with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'spec', 'cases.json'), encoding='utf-8') as f:
    CASES = json.load(f)


def code_of(fn):
    try:
        fn()
    except V.VaultEnvError as e:
        return e.code
    return None


class Spec(unittest.TestCase):
    def test_env_name(self):
        for c in CASES['envName']:
            self.assertEqual(V.env_name(c['key'], c['mode']), c['expect'], '%s (%s)' % (c['key'], c['mode']))

    def test_map_entries(self):
        for c in CASES['mapEntries']:
            imp = {'raw': 'test', 'prefix': c['prefix'], 'name': c['mode']}
            ci = bool(c.get('caseInsensitive'))
            if 'error' in c:
                self.assertEqual(code_of(lambda: V.map_entries(c['data'], imp, ci)), c['error'], c['name'])
            else:
                got = {e['name']: e['value'] for e in V.map_entries(c['data'], imp, ci)}
                self.assertEqual(got, c['expect'], c['name'])

    def test_merge(self):
        for c in CASES['merge']:
            results = [{'entries': [{'key': k, 'name': k, 'value': v} for k, v in m.items()]} for m in c['imports']]
            got = V.merge_imports(results, bool(c.get('caseInsensitive')))
            self.assertEqual(got['values'], c['expect'], c['name'])
            self.assertEqual(got['overridden'], c['overridden'], c['name'])

    def test_plan(self):
        for c in CASES['plan']:
            got = V.plan(c['values'], c['env'], c['override'])
            self.assertEqual(got['set'], c['set'], c['name'])
            self.assertEqual(got['kept'], c['kept'], c['name'])

    def test_parse_import(self):
        for c in CASES['parseImport']:
            if 'error' in c:
                self.assertEqual(code_of(lambda: V.parse_import(c['raw'])), c['error'], c['raw'])
                continue
            got = V.parse_import(c['raw'])
            for k, v in c['expect'].items():
                self.assertEqual(got[k], v, '%s: %s' % (c['raw'], k))

    def test_auth_selection(self):
        import shutil
        import tempfile
        d = tempfile.mkdtemp()
        try:
            n = 0
            for c in CASES['authSelection']:
                if 'name' not in c:
                    continue  # the section's $comment
                env = {'VAULT_ADDR': 'https://vault.example.com', 'VAULT_ENV_IMPORT': 'db'}
                for k, v in c['env'].items():
                    if v.startswith('<file:') and v.endswith('>'):
                        path = os.path.join(d, 'f%d' % n)
                        n += 1
                        with open(path, 'w', encoding='utf-8', newline='') as fh:
                            fh.write(v[len('<file:'):-1])
                        env[k] = path
                    else:
                        env[k] = v
                if 'error' in c:
                    self.assertEqual(code_of(lambda: V.read_config({}, env)), c['error'], c['name'])
                    if 'message' in c:
                        with self.assertRaises(V.VaultEnvError) as cm:
                            V.read_config({}, env)
                        self.assertEqual(cm.exception.message, c['message'], c['name'])
                    continue
                cfg = V.read_config({}, env)
                e = c['expect']
                for key, ours in (('certificatePath', 'certificate_path'), ('keyPath', 'key_path'), ('password', 'certificate_password'), ('jwtMount', 'jwt_mount')):
                    if key in e:
                        self.assertEqual(cfg[ours], e[key], c['name'])
                if 'note' in e:
                    self.assertEqual(cfg['notes'], [e['note']], c['name'])
                self.assertEqual(cfg['auth'], e['auth'], c['name'])
                if 'roleId' in e:
                    self.assertEqual(cfg['role_id'], e['roleId'], c['name'])
                if 'secretId' in e:
                    self.assertEqual(cfg['secret_id'], e['secretId'], c['name'])
                if 'mount' in e:
                    self.assertEqual(cfg['approle_mount'], e['mount'], c['name'])
                if 'used' in e:
                    self.assertEqual(cfg['approle_vars_used'], e['used'], c['name'])
                if 'ignoredNote' in e:
                    self.assertEqual(any('ignored' in s for s in cfg['notes']), e['ignoredNote'], c['name'])
        finally:
            shutil.rmtree(d)

    def test_enabled_switch(self):
        for c in CASES['enabledSwitch']:
            if 'name' not in c:
                continue  # the section's $comment
            env = dict(c['env'])
            if 'error' in c:
                with self.assertRaises(V.VaultEnvError, msg=c['name']) as cm:
                    V.read_config({}, env)
                self.assertEqual(cm.exception.code, c['error'], c['name'])
                self.assertEqual(cm.exception.message, c['message'], c['name'])
                continue
            cfg = V.read_config({}, env)
            state = 'disabled' if cfg.get('disabled') else 'configured' if cfg['configured'] else 'unconfigured'
            self.assertEqual(state, c['expect']['state'], c['name'])
            if state != 'disabled':
                continue
            V.strip_credentials(env, cfg)
            removed = sorted(k for k in c['env'] if k not in env)
            self.assertEqual(removed, sorted(c['expect']['removed']), c['name'])
            self.assertNotIn('VAULT_ENV_LOADED', env, c['name'])


# ---------------------------------------------------------------------------
# Certificate login (0.4)

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'spec', 'fixtures')
import importlib.util  # noqa: E402

HAVE_CRYPTOGRAPHY = importlib.util.find_spec('cryptography') is not None


def _iso(sec):
    import time
    return time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(sec))


def _parse_iso(s):
    import calendar
    import time
    return calendar.timegm(time.strptime(s, '%Y-%m-%dT%H:%M:%SZ'))


def _b64(s):
    import base64
    return base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))


class CertificateSpec(unittest.TestCase):
    def test_audience(self):
        for c in CASES['audience']:
            if 'addr' in c:
                self.assertEqual(V.audience(c['addr'], c['mount']), c['expect'], c['addr'])

    def test_certificate_status(self):
        for c in CASES['certificateStatus']:
            if 'now' not in c:
                continue
            st = V.certificate_status(_parse_iso(c['notAfter']), _parse_iso(c['now']))
            self.assertEqual(st['days'], c['expect']['days'], c['notAfter'])
            self.assertEqual(st['warning'], c['expect']['warning'], c['notAfter'])
            if 'checkLine' in c['expect']:
                self.assertEqual(V.certificate_check_line('7f3c2a1e-0000-4000-8000-000000000000', 'q3Z1Ab12cdEF', st, 'jwt'),
                                 c['expect']['checkLine'], c['notAfter'])

    def _load(self, c):
        return V.load_client_certificate(os.path.join(FIXTURES, c['file']),
                                         os.path.join(FIXTURES, c['keyFile']) if c.get('keyFile') else None, c.get('password'))

    @unittest.skipUnless(HAVE_CRYPTOGRAPHY, 'cryptography is not installed')
    def test_certificates(self):
        for c in CASES['certificates']:
            if 'name' not in c:
                continue
            if 'error' in c:
                with self.assertRaises(V.VaultEnvError, msg=c['name']) as cm:
                    self._load(c)
                self.assertEqual(cm.exception.code, c['error'], c['name'])
                self.assertIn(c['message'], cm.exception.message, c['name'])
                continue
            cred = self._load(c)
            self.assertEqual(cred['alg'], c['expect']['alg'], c['name'])
            if 'x5t' in c['expect']:
                self.assertEqual(cred['x5t'], c['expect']['x5t'], c['name'])
            if 'notAfter' in c['expect']:
                self.assertEqual(_iso(cred['not_after']), c['expect']['notAfter'], c['name'])

    @unittest.skipUnless(HAVE_CRYPTOGRAPHY, 'cryptography is not installed')
    def test_assertion(self):
        from cryptography import x509
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec, padding, utils
        a = CASES['assertion']
        for c in CASES['certificates']:
            if 'name' not in c or 'error' in c or 'x5t' not in c['expect']:
                continue
            cred = self._load(c)
            aud = 'https://vault.example.com/v1/auth/jwt/login'
            jwt = V.sign_assertion(cred, 'role-1', aud, 1800000000)
            h, p, sig = jwt.split('.')
            for part in (h, p, sig):
                self.assertRegex(part, r'^[A-Za-z0-9_-]+$')
            header = json.loads(_b64(h).decode('utf-8'))
            claims = json.loads(_b64(p).decode('utf-8'))
            self.assertEqual(list(header), a['header']['fields'], c['name'])
            self.assertEqual(header, {'alg': c['expect']['alg'], 'typ': a['header']['typ'], 'x5t#S256': c['expect']['x5t']}, c['name'])
            self.assertEqual(list(claims), a['claims'], c['name'])
            self.assertEqual((claims['iss'], claims['sub'], claims['aud'], claims['iat']), ('role-1', 'role-1', aud, 1800000000))
            self.assertEqual(claims['exp'] - claims['iat'], a['lifetime'])
            self.assertRegex(claims['jti'], r'^[0-9a-f]{32}$')
            self.assertNotEqual(json.loads(_b64(V.sign_assertion(cred, 'role-1', aud).split('.')[1]).decode())['jti'], claims['jti'])
            with open(os.path.join(FIXTURES, c['file']), 'rb') as f:
                pem = f.read()
            start = pem.index(b'-----BEGIN CERTIFICATE-----')
            pub = x509.load_pem_x509_certificate(pem[start:pem.index(b'-----END CERTIFICATE-----') + 25]).public_key()
            data = ('%s.%s' % (h, p)).encode()
            raw = _b64(sig)
            try:
                if c['expect']['alg'] == 'RS256':
                    pub.verify(raw, data, padding.PKCS1v15(), hashes.SHA256())
                else:
                    n = 32 if c['expect']['alg'] == 'ES256' else 48
                    self.assertEqual(len(raw), 2 * n)
                    der = utils.encode_dss_signature(int.from_bytes(raw[:n], 'big'), int.from_bytes(raw[n:], 'big'))
                    pub.verify(der, data, ec.ECDSA(hashes.SHA256() if n == 32 else hashes.SHA384()))
            except InvalidSignature:
                self.fail('%s: bad signature' % c['name'])

    def test_missing_cryptography(self):
        saved = {k: v for k, v in sys.modules.items() if k == 'cryptography' or k.startswith('cryptography.')}
        for k in saved:
            del sys.modules[k]
        sys.modules['cryptography'] = None
        try:
            with self.assertRaises(V.VaultEnvError) as cm:
                V.load_client_certificate(os.path.join(FIXTURES, 'rsa.pem'))
            self.assertEqual(cm.exception.code, 'config')
            self.assertEqual(cm.exception.message, V.CERT_NEEDS_CRYPTOGRAPHY)
            self.assertIn('pip install "vault-env-loader[cert]"', cm.exception.message)
        finally:
            del sys.modules['cryptography']
            sys.modules.update(saved)


if __name__ == '__main__':
    unittest.main()
