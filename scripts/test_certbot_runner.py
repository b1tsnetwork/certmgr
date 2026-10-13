import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('certbot_runner', Path(__file__).with_name('certbot-runner.py'))
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)

class RunnerTests(unittest.TestCase):
    def test_profiles_have_separate_certbot_stores(self):
        base = {
            'email': 'acme@example.test',
            'challenge': 'cloudflare',
            'credentials_file': '/run/secrets/cloudflare.ini',
        }
        cert = {'name': 'wildcard-test', 'expected_dns_names': ['*.example.test', 'example.test']}
        with patch.object(runner, 'restricted_file', return_value='/run/secrets/cloudflare.ini'):
            prod, _ = runner.build_command({**base, 'id': 'production', 'directory_url': 'https://acme.example.test/directory'}, cert)
            stage, _ = runner.build_command({**base, 'id': 'staging', 'directory_url': 'https://staging.example.test/directory'}, cert)
        self.assertIn('/etc/letsencrypt/profiles/production', prod)
        self.assertIn('/etc/letsencrypt/profiles/staging', stage)
        self.assertNotEqual(prod[prod.index('--config-dir') + 1], stage[stage.index('--config-dir') + 1])
        self.assertEqual(prod.count('-d'), 2)
        self.assertIn('https://staging.example.test/directory', stage)

    def test_eab_env_and_hook_controls(self):
        p = {'id': 'internal', 'directory_url': 'https://internal.test/acme/directory',
             'email': 'ops@example.test', 'challenge': 'manual-dns-hooks',
             'auth_hook': '/hooks/auth.sh', 'cleanup_hook': '/hooks/cleanup.sh',
             'eab_kid_env': 'ACME_INTERNAL_KID', 'eab_hmac_env': 'ACME_INTERNAL_HMAC'}
        with patch.object(runner, 'restricted_file', side_effect=lambda value, root: value), \
             patch.dict(os.environ, {'ACME_INTERNAL_KID': 'kid', 'ACME_INTERNAL_HMAC': 'mac'}):
            cmd, env = runner.build_command(p, {'name': 'test', 'expected_dns_names': ['example.test']})
        self.assertIn('--manual-auth-hook', cmd)
        self.assertEqual(cmd[cmd.index('--eab-kid') + 1], 'kid')
        self.assertEqual(env['UCNG_ACME_PROFILE'], 'internal')

    def test_invalid_issuer_or_profile_rejected(self):
        cert = {'name': 'test', 'expected_dns_names': ['example.test']}
        p = {'id': 'test', 'directory_url': 'http://internal.test/acme', 'email': 'a@b.test',
             'challenge': 'cloudflare', 'credentials_file': '/run/secrets/cf.ini'}
        with self.assertRaises(ValueError): runner.build_command(p, cert)
        p['directory_url'] = 'https://internal.test/acme'
        cert['name'] = '../not-safe'
        with self.assertRaises(ValueError): runner.build_command(p, cert)

if __name__ == '__main__':
    unittest.main()
