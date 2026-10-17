"""Against a real HashiCorp Vault dev server. Runs only when VAULT_IT_ADDR and
VAULT_IT_ROOT_TOKEN are set (CI starts hashicorp/vault as a service):

    VAULT_IT_ADDR=http://127.0.0.1:8200 VAULT_IT_ROOT_TOKEN=root python -m unittest tests/test_vault.py
"""

import json
import os
import subprocess
import sys
import unittest
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, '..'))
import vault_env_loader as V  # noqa: E402

ADDR = os.environ.get('VAULT_IT_ADDR')
ROOT = os.environ.get('VAULT_IT_ROOT_TOKEN')
MODULE = os.path.join(HERE, '..', 'vault_env_loader.py')


def api(method, path, body=None, token=None):
    req = urllib.request.Request('%s/v1/%s' % (ADDR, path), method=method,
                                 data=json.dumps(body).encode() if body is not None else None,
                                 headers={'X-Vault-Token': token or ROOT, 'Content-Type': 'application/json'})
    try:
        with urllib.request.urlopen(req) as r:
            data = r.read()
            return r.getcode(), json.loads(data) if data else None
    except urllib.error.HTTPError as e:
        return e.code, None  # e.g. 400 when the kv1 mount already exists


@unittest.skipUnless(ADDR and ROOT, 'VAULT_IT_ADDR / VAULT_IT_ROOT_TOKEN not set')
class RealVault(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        api('POST', 'sys/mounts/kv1', {'type': 'kv', 'options': {'version': '1'}})
        api('POST', 'secret/data/app/prod/db', {'data': {'db.password': 's3cr3t', 'DB_USER': 'app'}})
        api('POST', 'secret/data/app/prod', {'data': {'DEFAULT_KEY': 'd'}})
        api('POST', 'kv1/app/legacy', {'LEGACY': '1'})
        policy = '\n'.join([
            'path "secret/data/app/prod" { capabilities = ["read"] }',
            'path "secret/data/app/prod/*" { capabilities = ["read"] }',
            'path "kv1/app/*" { capabilities = ["read"] }',
            'path "sys/internal/ui/mounts/*" { capabilities = ["read"] }',
        ])
        api('PUT', 'sys/policies/acl/vel-reader', {'policy': policy})
        _, t = api('POST', 'auth/token/create', {'policies': ['vel-reader'], 'ttl': '1h',
                                                 'meta': {'application': 'app', 'environment': 'prod'}})
        cls.reader = t['auth']['client_token']
        _, s = api('POST', 'auth/token/create', {'policies': ['default'], 'ttl': '1h'})
        cls.stranger = s['auth']['client_token']
        api('POST', 'sys/auth/approle', {'type': 'approle'})  # 400 if already enabled: fine
        api('POST', 'auth/approle/role/vel', {'token_policies': ['vel-reader'], 'token_ttl': '10m', 'token_max_ttl': '30m'})
        cls.role_id = api('GET', 'auth/approle/role/vel/role-id')[1]['data']['role_id']
        cls.secret_id = api('POST', 'auth/approle/role/vel/secret-id', {})[1]['data']['secret_id']
        cls.once_secret_id = api('POST', 'auth/approle/role/vel/secret-id', {'num_uses': 1})[1]['data']['secret_id']

    def role_env(self, **extra):
        # AppRole tokens carry only role_name as metadata, so relative imports need VAULT_ENV_BASE.
        e = {'VAULT_ADDR': ADDR, 'VAULT_ROLE_ID': self.role_id, 'VAULT_SECRET_ID': self.secret_id, 'VAULT_ENV_BASE': 'secret/app/prod'}
        e.update(extra)
        return e

    def test_approle_login(self):
        self.assertEqual(V.fetch(env=self.role_env(VAULT_ENV_IMPORT='db'), retry_delay=0.001), {'DB_PASSWORD': 's3cr3t', 'DB_USER': 'app'})

    def test_approle_single_use_secret_id(self):
        env = lambda: self.role_env(VAULT_SECRET_ID=self.once_secret_id, VAULT_ENV_IMPORT='db')  # noqa: E731
        self.assertEqual(V.fetch(env=env(), retry_delay=0.001)['DB_USER'], 'app')
        with self.assertRaises(V.VaultEnvError) as cm:
            V.fetch(env=env(), retry_delay=0.001)
        self.assertEqual(cm.exception.code, 'auth')

    def test_approle_wrong_secret_id(self):
        with self.assertRaises(V.VaultEnvError) as cm:
            V.fetch(env=self.role_env(VAULT_SECRET_ID='nope', VAULT_ENV_IMPORT='db'), retry_delay=0.001)
        self.assertEqual(cm.exception.code, 'auth')

    def env(self, **extra):
        e = {'VAULT_ADDR': ADDR, 'VAULT_TOKEN': self.reader}
        e.update(extra)
        return e

    def test_relative_imports_via_token_metadata_kv2(self):
        values = V.fetch(env=self.env(VAULT_ENV_IMPORT='db, vault://'), retry_delay=0.001)
        self.assertEqual(values, {'DB_PASSWORD': 's3cr3t', 'DB_USER': 'app', 'DEFAULT_KEY': 'd'})

    def test_kv1_detected(self):
        self.assertEqual(V.fetch(env=self.env(VAULT_ENV_IMPORT='vault://kv1/app/legacy'), retry_delay=0.001), {'LEGACY': '1'})

    def test_policy_does_not_cover_path(self):
        with self.assertRaises(V.VaultEnvError) as cm:
            V.fetch(env=self.env(VAULT_TOKEN=self.stranger, VAULT_ENV_IMPORT='vault://secret/app/prod/db'), retry_delay=0.001)
        self.assertEqual(cm.exception.code, 'auth')

    def test_missing_path(self):
        with self.assertRaises(V.VaultEnvError) as cm:
            V.fetch(env=self.env(VAULT_ENV_IMPORT='nosuch'), retry_delay=0.001)
        self.assertIn(cm.exception.code, ('not_found', 'auth'))
        values = V.fetch(env=self.env(VAULT_ENV_IMPORT='db, optional:vault://secret/app/prod/nosuch'), retry_delay=0.001)
        self.assertEqual(values['DB_USER'], 'app')

    def test_cli_wrapper_and_check(self):
        env = dict(os.environ, **self.env(VAULT_ENV_IMPORT='db'))
        out = subprocess.check_output([sys.executable, MODULE, '--', sys.executable, '-c',
                                       'import os; print(os.environ["DB_PASSWORD"] + "|" + os.environ.get("VAULT_TOKEN", ""))'], env=env)
        self.assertEqual(out.decode().strip(), 's3cr3t|')
        out = subprocess.check_output([sys.executable, MODULE, 'check'], env=env).decode()
        self.assertIn('secret/app/prod/db', out)
        self.assertNotIn('s3cr3t', out)


if __name__ == '__main__':
    unittest.main()
