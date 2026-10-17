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
                        with open(path, 'w', encoding='utf-8') as fh:
                            fh.write(v[len('<file:'):-1])
                        env[k] = path
                    else:
                        env[k] = v
                if 'error' in c:
                    self.assertEqual(code_of(lambda: V.read_config({}, env)), c['error'], c['name'])
                    continue
                cfg = V.read_config({}, env)
                e = c['expect']
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


if __name__ == '__main__':
    unittest.main()
