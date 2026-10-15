#!/usr/bin/env python3
"""ACME profile worker. A separate, root-only Certbot container owns issuance.

Read-only catalog comes from the Go CMS, never execute shell strings from JSON.
Certbot state is stored separately per ACME profile so staging/internal account
state cannot accidentally replace production state.
"""
import json
import hashlib
import configparser
import ipaddress
import tempfile
import logging
import os
from pathlib import Path
from datetime import datetime, timezone
from cryptography import x509
import re
import subprocess
import sys
import time
from urllib.parse import urlsplit

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
CATALOG = Path(os.getenv('ACME_CATALOG', '/catalog/catalog.json'))
STATUS = Path(os.getenv('ACME_STATUS', '/status/status.json'))
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



def prepare_rfc2136_credentials(profile, source_file, profile_dir):
    """Create a private, per-profile credential file containing the UI DNS IP.

    The TSIG key stays within the isolated worker; never expose it to Go/WebUI.
    """
    try:
        server = str(ipaddress.ip_address(profile['dns_server']))
    except (KeyError, ValueError) as exc:
        raise ValueError('RFC2136 requires a DNS server IP') from exc
    if ipaddress.ip_address(server).is_unspecified or ipaddress.ip_address(server).is_multicast:
        raise ValueError('Invalid RFC2136 DNS server IP')
    try:
        port = int(profile.get('dns_port') or 53)
        propagation = int(profile.get('dns_propagation_seconds') or 60)
    except (ValueError, TypeError) as exc:
        raise ValueError('Invalid RFC2136 DNS port / propagation time') from exc
    if not 1 <= port <= 65535 or not 1 <= propagation <= 3600:
        raise ValueError('RFC2136 port or propagation time out of range')

    conf = configparser.ConfigParser(interpolation=None)
    try:
        conf.read_string('[credentials]\n' + Path(source_file).read_text(encoding='utf-8'))
    except (configparser.Error, UnicodeError) as exc:
        raise ValueError('Invalid RFC2136 TSIG credentials INI') from exc
    data = conf['credentials']
    keyname = data.get('dns_rfc2136_name', '').strip()
    secret = data.get('dns_rfc2136_secret', '').strip()
    algorithm = data.get('dns_rfc2136_algorithm', 'HMAC-SHA256').strip().upper()
    if not keyname or any(c in keyname for c in '\r\n') or len(keyname) > 253:
        raise ValueError('Missing/invalid RFC2136 TSIG key name')
    if not secret or any(c in secret for c in '\r\n') or len(secret) > 4096:
        raise ValueError('Missing/invalid RFC2136 TSIG secret')
    if algorithm not in {'HMAC-SHA1', 'HMAC-SHA224', 'HMAC-SHA256', 'HMAC-SHA384', 'HMAC-SHA512'}:
        raise ValueError('RFC2136 requires supported TSIG HMAC algorithm')
    sign_query = data.get('dns_rfc2136_sign_query', 'false').strip().lower()
    if sign_query not in {'true', 'false'}:
        raise ValueError('Invalid RFC2136 sign_query value')
    profile_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    output = profile_dir / 'rfc2136.ini'
    fd, temp_path = tempfile.mkstemp(prefix='.rfc2136-', dir=profile_dir)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as temp:
            temp.write(f'dns_rfc2136_server = {server}\n')
            temp.write(f'dns_rfc2136_port = {port}\n')
            temp.write(f'dns_rfc2136_name = {keyname}\n')
            temp.write(f'dns_rfc2136_secret = {secret}\n')
            temp.write(f'dns_rfc2136_algorithm = {algorithm}\n')
            temp.write(f'dns_rfc2136_sign_query = {sign_query}\n')
        os.chmod(temp_path, 0o600)
        os.replace(temp_path, output)
    finally:
        if os.path.exists(temp_path):
            os.unlink(temp_path)
    return str(output), propagation


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
            '--deploy-hook', '/opt/certwatch/certbot-deploy-hook.sh']
    if profile['challenge'] == 'cloudflare':
        creds = restricted_file(profile.get('credentials_file'), '/run/secrets/')
        opts.extend(['--dns-cloudflare', '--dns-cloudflare-credentials', creds])
    elif profile['challenge'] == 'rfc2136':
        source = restricted_file(profile.get('credentials_file'), '/run/secrets/')
        combined, propagation = prepare_rfc2136_credentials(profile, source, base)
        opts.extend(['--dns-rfc2136', '--dns-rfc2136-credentials', combined,
                     '--dns-rfc2136-propagation-seconds', str(propagation)])
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
    env['CERTWATCH_ACME_PROFILE'] = pid
    for d in domains:
        opts.extend(['-d', d])
    return opts, env


def write_status(items):
    """Expose only non-sensitive certificate status, never private keys."""
    STATUS.parent.mkdir(parents=True, exist_ok=True)
    tmp = STATUS.with_name('.status-incoming.json')
    tmp.write_text(json.dumps(items, indent=2), encoding='utf-8')
    tmp.chmod(0o644)
    tmp.replace(STATUS)


def cert_status(profile_id, name, error=None):
    base = {'name': name, 'profile': profile_id,
            'updated_at': datetime.now(timezone.utc).isoformat()}
    path = Path('/etc/letsencrypt/profiles') / profile_id / 'live' / name / 'cert.pem'
    if path.is_file():
        try:
            cert = x509.load_pem_x509_certificate(path.read_bytes())
            expiry = getattr(cert, 'not_valid_after_utc', None)
            if expiry is None:
                expiry = cert.not_valid_after.replace(tzinfo=timezone.utc)
            base['not_after'] = expiry.isoformat()
            if error is None and expiry > datetime.now(timezone.utc):
                base.update(status='ok', message='Zertifikat vorhanden / gültig')
                return base
        except Exception as exc:
            error = str(exc)
    base.update(status='error', message=(str(error) if error else 'Kein gültiges Zertifikat vorhanden')[:250])
    return base


def ensure_handoff(profile_id, name):
    """Publish pre-existing Certbot lineages even if --keep-until-expiring skips renew.

    The deploy hook ordinarily publishes on renewal. On an upgrade, a valid
    pre-existing lineage may not trigger the hook for months.
    """
    if not NAME.fullmatch(profile_id) or not NAME.fullmatch(name):
        raise ValueError('Invalid handoff target')
    live = Path('/etc/letsencrypt/profiles') / profile_id / 'live' / name
    source = live / 'fullchain.pem'
    key = live / 'privkey.pem'
    if not source.is_file() or not key.is_file():
        return
    current = Path('/handoff') / profile_id / name / 'current'
    try:
        published = current / 'fullchain.pem'
        published_key = current / 'privkey.pem'
        if published.is_file() and published_key.is_file():
            # A previous installation may have published root-only (0700/0600)
            # handoff content. Force a fresh, group-readable publication once.
            shareable = all(
                p.stat().st_gid == 65532 and (p.stat().st_mode & mode)
                for p, mode in (
                    (Path('/handoff'), 0o050),
                    (current.parent.parent, 0o050),
                    (current.parent, 0o050),
                    (current.parent / 'releases', 0o050),
                    (current.resolve(), 0o050),
                    (published, 0o040),
                    (published_key, 0o040),
                )
            )
            if shareable and hashlib.sha256(published.read_bytes()).digest() == hashlib.sha256(source.read_bytes()).digest() and \
               hashlib.sha256(published_key.read_bytes()).digest() == hashlib.sha256(key.read_bytes()).digest():
                return
    except OSError:
        pass
    environment = os.environ.copy()
    environment['CERTWATCH_ACME_PROFILE'] = profile_id
    environment['RENEWED_LINEAGE'] = str(live)
    subprocess.run(['/opt/certwatch/certbot-deploy-hook.sh'], check=True, env=environment)


def once():
    if not CATALOG.is_file():
        logging.info('Catalog does not exist; waiting for CMS initialization')
        write_status([])
        return 0
    doc = json.loads(CATALOG.read_text(encoding='utf-8'))
    profiles = {p['id']: p for p in doc.get('acme_profiles', [])}
    failures = 0
    statuses = []
    for cert in doc.get('certificates', []):
        if not cert.get('enabled') or not cert.get('profile'):
            continue
        name = cert.get('name', '<unknown>')
        profile_id = cert['profile']
        issue_error = None
        try:
            profile = profiles[profile_id]
            command, environment = build_command(profile, cert)
            # Do NOT log command args: EAB HMAC secret is among them.
            logging.info('Checking certificate %s using profile %s', name, profile_id)
            completed = subprocess.run(command, env=environment, check=False)
            if completed.returncode:
                failures += 1
                logging.error('Certbot %s / %s exited %d', profile_id, name, completed.returncode)
                issue_error = 'Certbot exited with code %d' % completed.returncode
        except (ValueError, KeyError, TypeError, OSError) as exc:
            failures += 1
            logging.error('Certbot profile=%s certificate=%s: %s', profile_id, name, exc)
            issue_error = str(exc)
        if NAME.fullmatch(str(profile_id)) and NAME.fullmatch(str(name)):
            if issue_error is None:
                try:
                    ensure_handoff(profile_id, name)
                except (OSError, ValueError, subprocess.CalledProcessError) as exc:
                    issue_error = 'Certificate handoff failed: %s' % exc
                    failures += 1
            statuses.append(cert_status(profile_id, name, issue_error))
    write_status(statuses)
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
