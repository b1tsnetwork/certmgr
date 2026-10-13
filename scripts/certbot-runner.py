#!/usr/bin/env python3
"""ACME profile worker. A separate, root-only Certbot container owns issuance.

Read-only catalog comes from the Go CMS, never execute shell strings from JSON.
Certbot state is stored separately per ACME profile so staging/internal account
state cannot accidentally replace production state.
"""
import json
import logging
import os
from pathlib import Path
import re
import subprocess
import sys
import time
from urllib.parse import urlsplit

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
CATALOG = Path(os.getenv('ACME_CATALOG', '/catalog/catalog.json'))
INTERVAL = int(os.getenv('ACME_RUN_INTERVAL', '43200'))
NAME = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$')
ENV = re.compile(r'^[A-Z][A-Z0-9_]{0,79}$')


def restricted_file(value, prefix):
    if not value or not value.startswith(prefix) or '..' in value or '\x00' in value:
        raise ValueError(f'Invalid or missing path under {prefix}')
    path = Path(value)
    if not path.is_file():
        raise ValueError(f'Missing file: {value}')
    return value


def build_command(profile, cert):
    pid, cname = profile['id'], cert['name']
    if not NAME.fullmatch(pid) or not NAME.fullmatch(cname):
        raise ValueError('Invalid ID / cert-name')
    domains = cert.get('expected_dns_names', [])
    if not domains or len(domains) > 50 or not all(isinstance(d, str) and len(d) < 254 and ('/' not in d) and (' ' not in d) for d in domains):
        raise ValueError('Invalid SAN configuration')
    server = profile['directory_url']
    parsed = urlsplit(server)
    if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or parsed.fragment or parsed.query:
        raise ValueError('ACME Directory must be HTTPS')
    email = profile.get('email', '')
    if not email or '@' not in email:
        raise ValueError('Profile requires a contact email')
    base = Path('/etc/letsencrypt/profiles') / pid
    opts = ['certbot', 'certonly', '--non-interactive', '--agree-tos',
            '--keep-until-expiring', '--server', server,
            '--email', email, '--cert-name', cname,
            '--config-dir', str(base),
            '--work-dir', '/var/lib/letsencrypt/profiles/' + pid,
            '--logs-dir', '/var/log/letsencrypt/profiles/' + pid,
            '--deploy-hook', '/opt/ucng/certbot-deploy-hook.sh']
    if profile['challenge'] == 'cloudflare':
        creds = restricted_file(profile.get('credentials_file'), '/run/secrets/')
        opts.extend(['--dns-cloudflare', '--dns-cloudflare-credentials', creds])
    elif profile['challenge'] == 'manual-dns-hooks':
        auth = restricted_file(profile.get('auth_hook'), '/hooks/')
        cleanup = restricted_file(profile.get('cleanup_hook'), '/hooks/')
        opts.extend(['--manual', '--preferred-challenges', 'dns',
                     '--manual-auth-hook', auth, '--manual-cleanup-hook', cleanup])
    else:
        raise ValueError('Unsupported DNS-01 method')
    kid_ref = profile.get('eab_kid_env', '')
    mac_ref = profile.get('eab_hmac_env', '')
    if bool(kid_ref) != bool(mac_ref):
        raise ValueError('EAB needs both KID and MAC')
    if kid_ref:
        if not ENV.fullmatch(kid_ref) or not ENV.fullmatch(mac_ref):
            raise ValueError('Invalid EAB env variable name')
        if not os.getenv(kid_ref) or not os.getenv(mac_ref):
            raise ValueError('Missing EAB secrets in worker environment')
        opts.extend(['--eab-kid', os.environ[kid_ref], '--eab-hmac-key', os.environ[mac_ref]])
    ca = profile.get('ca_bundle_file', '')
    env = os.environ.copy()
    if ca:
        env['REQUESTS_CA_BUNDLE'] = restricted_file(ca, '/run/acme-ca/')
    env['UCNG_ACME_PROFILE'] = pid
    for d in domains:
        opts.extend(['-d', d])
    return opts, env


def once():
    if not CATALOG.is_file():
        logging.info('Catalog does not exist; waiting for CMS initialization')
        return 0
    doc = json.loads(CATALOG.read_text(encoding='utf-8'))
    profiles = {p['id']: p for p in doc.get('acme_profiles', [])}
    failures = 0
    for cert in doc.get('certificates', []):
        if not cert.get('enabled') or not cert.get('profile'):
            continue
        name = cert.get('name', '<unknown>')
        profile_id = cert['profile']
        try:
            profile = profiles[profile_id]
            command, environment = build_command(profile, cert)
            # Do NOT log command args: EAB HMAC secret is among them.
            logging.info('Checking certificate %s using profile %s', name, profile_id)
            completed = subprocess.run(command, env=environment, check=False)
            if completed.returncode:
                failures += 1
                logging.error('Certbot %s / %s exited %d', profile_id, name, completed.returncode)
        except (ValueError, KeyError, TypeError, OSError) as exc:
            failures += 1
            logging.error('Certbot profile=%s certificate=%s: %s', profile_id, name, exc)
    return failures


if __name__ == '__main__':
    if '--once' in sys.argv:
        sys.exit(1 if once() else 0)
    if INTERVAL < 3600:
        sys.exit('ACME_RUN_INTERVAL must be >= 3600')
    while True:
        try:
            once()
        except Exception:
            logging.exception('Failed to read ACME catalog')
        time.sleep(INTERVAL)
