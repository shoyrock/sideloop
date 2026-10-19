"""Renew installed provisioning profiles without copying or changing the app.

The Apple exchange is delegated to AltSign. Device work uses the same lockdown,
installation_proxy and misagent services as AltServer. Failed checks never infer
that an application is absent, and never authorize a replacement IPA.
"""
import contextlib
import datetime as dt
import hashlib
import json
import os
import plistlib
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from . import accounts, config, ipa, store
from .lockdown import Lockdown

REPAIR = 42


class NeedsRepair(Exception):
    pass


def atomic_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(mode='w', dir=path.parent, delete=False, encoding='utf-8') as f:
        tmp = Path(f.name)
        json.dump(data, f)
    try:
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)


def read_json(path):
    try:
        data = json.loads(path.read_text())
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def fingerprint(path):
    with path.open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def epoch(value):
    if not isinstance(value, dt.datetime):
        raise NeedsRepair('a provisioning profile has an invalid date')
    return int(value.replace(tzinfo=dt.timezone.utc).timestamp())


def decode_profile(raw):
    result = subprocess.run(['openssl', 'smime', '-verify', '-noverify', '-inform', 'DER'],
                            input=raw, capture_output=True, timeout=15)
    if result.returncode:
        raise NeedsRepair('a provisioning profile could not be verified')
    profile = plistlib.loads(result.stdout)
    if not isinstance(profile, dict):
        raise NeedsRepair('invalid provisioning profile')
    return profile


def profile_bundle(profile):
    identifier = profile.get('Entitlements', {}).get('application-identifier', '')
    team = profile.get('TeamIdentifier', [])
    if len(team) != 1 or not isinstance(team[0], str) or not identifier.startswith(team[0] + '.'):
        raise NeedsRepair('the installed signing team could not be identified')
    return identifier[len(team[0]) + 1:]


def cert_hashes(profile):
    return {hashlib.sha1(c).hexdigest(): c for c in profile.get('DeveloperCertificates', []) if isinstance(c, bytes)}


class Phone:
    def __init__(self, udid):
        self.udid = udid

    @contextlib.contextmanager
    def service(self, name):
        with contextlib.closing(Lockdown(self.udid, os.environ.get('USBMUXD_SOCKET_ADDRESS', '/var/run/usbmuxd'))) as ld:
            with contextlib.closing(ld.service(name)) as service:
                yield service

    def applications(self):
        with self.service('com.apple.mobile.installation_proxy') as service:
            service.send({'Command': 'Browse', 'ClientOptions': {'ApplicationType': 'User'}})
            apps = {}
            for _ in range(10000):
                reply = service.receive()
                if reply.get('Error'):
                    raise ConnectionError('the phone could not list installed apps')
                for app in reply.get('CurrentList', []):
                    apps[app['CFBundleIdentifier']] = app
                if reply.get('Status') == 'Complete':
                    return apps
            raise ConnectionError('installed-app listing did not complete')

    def misagent(self, operation, **values):
        with self.service('com.apple.misagent') as service:
            service.send({'MessageType': operation, 'ProfileType': 'Provisioning', **values})
            reply = service.receive()
            if reply.get('Status') != 0:
                raise ConnectionError(f"device profile {operation.lower()} failed (status {reply.get('Status', 'missing')})")
            return reply.get('Payload')

    def profiles(self):
        payload = self.misagent('CopyAll')
        if not isinstance(payload, list):
            raise ConnectionError('the phone returned an invalid profile list')
        return [(raw, decode_profile(raw)) for raw in payload]

    def install(self, raw):
        self.misagent('Install', Profile=raw)

    def remove(self, uuid):
        self.misagent('Remove', ProfileID=uuid)


def matching_apps(apps, original):
    # Upstream app IDs are <original>.<team>; AltStore itself has a special prefix.
    return {b: a for b, a in apps.items()
            if b == original or re.fullmatch(re.escape(original) + r'\.[A-Za-z0-9]+', b)
            or (original == 'com.rileytestut.AltStore' and re.fullmatch(r'com\.[A-Za-z0-9]+\.' + re.escape(original), b))}


def snapshot(phone, original):
    apps = matching_apps(phone.applications(), original)
    if len(apps) > 1:
        raise NeedsRepair('multiple installed copies use this bundle identifier; choose the intended signing account')
    return next(iter(apps.values()), None)


def select_profiles(profiles, installed, expected_cert, udid):
    if not expected_cert:
        raise NeedsRepair('the signing certificate has not been recorded; use Install / Update once')
    main = installed['CFBundleIdentifier']
    selected = {}
    for raw, p in profiles:
        bundle = profile_bundle(p)
        if bundle != main and not bundle.startswith(main + '.'):
            continue
        if expected_cert not in cert_hashes(p):
            # A newer certificate for the same bundle must not be silently ignored.
            raise NeedsRepair('the installed profile uses a different signing certificate')
        if udid.casefold() not in [str(u).casefold() for u in p.get('ProvisionedDevices', [])]:
            raise NeedsRepair('the installed profile does not include this device')
        if bundle not in selected or epoch(p['CreationDate']) > epoch(selected[bundle][1]['CreationDate']):
            selected[bundle] = (raw, p)
    if main not in selected:
        raise NeedsRepair('the installed app has no matching provisioning profile')
    # iOS can include installed extensions in the browse response. Require every
    # reported extension, including nested ones, to have its own matching profile.
    plugins = installed.get('PluginKitPlugins', {})
    if isinstance(plugins, dict):
        for key, info in plugins.items():
            bundle = info.get('CFBundleIdentifier', key) if isinstance(info, dict) else key
            if bundle not in selected:
                raise NeedsRepair('an installed extension has no matching provisioning profile')
    teams = {p['TeamIdentifier'][0] for _, p in selected.values()}
    if len(teams) != 1:
        raise NeedsRepair('the installed app and extensions use different signing teams')
    return selected


def validate_replacement(old, new, expected_cert, udid, now):
    if profile_bundle(old) != profile_bundle(new) or old['TeamIdentifier'] != new['TeamIdentifier']:
        raise NeedsRepair('Apple returned a profile for a different app or signing team')
    if expected_cert not in cert_hashes(new):
        raise NeedsRepair('the renewed profile does not contain the installed signing certificate')
    if old.get('Entitlements') != new.get('Entitlements'):
        raise NeedsRepair('the app permissions changed; a full re-sign is required')
    if udid.casefold() not in [str(u).casefold() for u in new.get('ProvisionedDevices', [])]:
        raise NeedsRepair('the renewed profile does not include this device')
    if epoch(new.get('ExpirationDate')) <= now or epoch(new['ExpirationDate']) < epoch(old['ExpirationDate']):
        raise NeedsRepair('Apple did not return a usable renewed expiry')
    if epoch(new.get('CreationDate')) > now + 300:
        raise NeedsRepair('the renewed profile is dated in the future')


def save_observed(state, installed):
    atomic_json(state / 'installed.json', {'bundle': installed['CFBundleIdentifier'],
                'version': installed.get('CFBundleShortVersionString', ''),
                'build': installed.get('CFBundleVersion', ''), 'checked_at': int(time.time())})


def save_expiry(state, profiles, expected_cert):
    expiry = min(epoch(p['ExpirationDate']) for _, p in profiles.values())
    state.mkdir(parents=True, exist_ok=True)
    for name, value in [('expiry', str(expiry)), ('certificate', expected_cert), ('consecutive_failures', '0')]:
        tmp = state / (name + '.tmp')
        tmp.write_text(value)
        os.replace(tmp, state / name)
    return expiry


def renew(app_id, udid, phone=None, signer=subprocess.run):
    phone = phone or Phone(udid)
    state = accounts.state_folder(app_id, udid)
    installed = snapshot(phone, store.app_meta(app_id)['BUNDLE_ID'])
    if installed is None:
        raise NeedsRepair('the app is not installed; use Install / Update to install it')
    save_observed(state, installed)
    try:
        expected_cert = (state / 'certificate').read_text().strip()
    except FileNotFoundError:
        expected_cert = ''
    selected = select_profiles(phone.profiles(), installed, expected_cert, udid)
    main_profile = selected[installed['CFBundleIdentifier']][1]
    certificate = cert_hashes(main_profile)[expected_cert]
    cert = subprocess.run(['openssl', 'x509', '-inform', 'DER', '-noout', '-serial', '-checkend', '0'],
                          input=certificate, capture_output=True, timeout=15)
    serial = re.search(rb'^serial=([0-9A-Fa-f]+)$', cert.stdout, re.M)
    if cert.returncode or not serial:
        raise NeedsRepair('the installed signing certificate has expired')
    with tempfile.TemporaryDirectory(prefix='sideloop-renew-') as work:
        work = Path(work)
        request = {'team': main_profile['TeamIdentifier'][0], 'certificate_serial': serial[1].decode(),
                   'bundles': list(selected), 'output': str(work)}
        atomic_json(work / 'request.json', request)
        print('Renewing installed app profiles; no app transfer...', flush=True)
        result = signer([os.environ.get('ALTSERVER_BIN', '/usr/local/bin/AltServer'),
                         '--refresh-profiles', str(work / 'request.json')], timeout=600)
        if result.returncode:
            return result.returncode
        replacements = {}
        for i, (bundle, (_, old)) in enumerate(selected.items()):
            raw = (work / f'{i}.mobileprovision').read_bytes()
            new = decode_profile(raw)
            validate_replacement(old, new, expected_cert, udid, int(time.time()))
            replacements[bundle] = (raw, new)
        # Validate ALL profiles before changing ANY. Keep old profiles in place
        # until all replacements have been installed and read back successfully.
        print('Installing renewal profiles...', flush=True)
        for raw, _ in replacements.values():
            phone.install(raw)
        actual = {p['UUID']: raw for raw, p in phone.profiles()}
        for raw, p in replacements.values():
            if actual.get(p['UUID']) != raw:
                raise ConnectionError('the phone did not retain all renewed profiles; retry renewal')
        save_expiry(state, replacements, expected_cert)
        # Remove only the old versions we just replaced. Keep the new UUID even
        # if Apple used the same creation timestamp, and leave other apps alone.
        for bundle, (_, old) in selected.items():
            if old['UUID'] != replacements[bundle][1]['UUID']:
                try:
                    phone.remove(old['UUID'])
                except (OSError, ConnectionError):
                    print('Renewal succeeded; an old profile could not be cleaned up.', flush=True)
        print('Profile renewal succeeded. No app was copied.', flush=True)
    return 0


def install_guard(app_id, udid, confirmed=False, phone=None):
    state = accounts.state_folder(app_id, udid)
    installed = snapshot(phone or Phone(udid), store.app_meta(app_id)['BUNDLE_ID'])
    if installed:
        save_observed(state, installed)
        if not confirmed:
            raise NeedsRepair('an app is already installed; confirm Install / Update to replace it with the saved IPA')
    return 0


def record_install(app_id, udid, phone=None):
    folder = config.APPS / app_id
    state = accounts.state_folder(app_id, udid)
    installed = snapshot(phone or Phone(udid), store.app_meta(app_id)['BUNDLE_ID'])
    if not installed:
        raise ConnectionError('installation could not be confirmed on the phone')
    info = ipa.cached(folder) or {}
    if any(str(installed.get(k, '')) != str(info.get(v, '')) for k, v in
           [('CFBundleShortVersionString', 'version'), ('CFBundleVersion', 'build')]):
        raise ConnectionError('the installed version does not match the saved IPA')
    save_observed(state, installed)
    atomic_json(state / 'installation.json', {**read_json(state / 'installed.json'),
                'ipa_sha256': fingerprint(folder / 'app.ipa'),
                'keep_extensions': store.app_meta(app_id)['KEEP_EXTENSIONS'] == '1'})


def can_reinstall(app_id, udid, phone=None):
    """Automatic repair may reinstall only the exact IPA previously installed.

    Missing legacy receipts, changed library IPAs, and externally updated apps
    require an explicit Install / Update. Version strings alone are not proof.
    """
    state = accounts.state_folder(app_id, udid)
    receipt = read_json(state / 'installation.json')
    if not receipt.get('ipa_sha256'):
        return False
    installed = snapshot(phone or Phone(udid), store.app_meta(app_id)['BUNDLE_ID'])
    if not installed:
        return False
    if any(str(installed.get(k, '')) != str(receipt.get(v, '')) for k, v in
           [('CFBundleIdentifier','bundle'), ('CFBundleShortVersionString','version'), ('CFBundleVersion','build')]):
        return False
    if receipt.get('keep_extensions') != (store.app_meta(app_id)['KEEP_EXTENSIONS'] == '1'):
        return False
    return receipt['ipa_sha256'] == fingerprint(config.APPS / app_id / 'app.ipa')


def check(app_id, udid, phone=None):
    phone = phone or Phone(udid)
    state = accounts.state_folder(app_id, udid)
    installed = snapshot(phone, store.app_meta(app_id)['BUNDLE_ID'])
    if installed is None:
        (state / 'expiry').unlink(missing_ok=True)
        (state / 'installed.json').unlink(missing_ok=True)
        print('App is not installed on this device.')
        return
    save_observed(state, installed)
    try:
        cert = (state / 'certificate').read_text().strip()
    except FileNotFoundError:
        cert = ''
    selected = select_profiles(phone.profiles(), installed, cert, udid)
    # A read-only check must not clear failure history.
    failures = (state / 'consecutive_failures').read_text() if (state / 'consecutive_failures').exists() else None
    expiry = save_expiry(state, selected, cert)
    if failures is not None:
        (state / 'consecutive_failures').write_text(failures)
    print('Installed app checked; expiry ' + str(expiry))


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('operation', choices=['renew', 'guard', 'record', 'check', 'can-reinstall'])
    parser.add_argument('app')
    parser.add_argument('device')
    parser.add_argument('--confirmed', action='store_true')
    parser.add_argument('--repair', action='store_true')
    args = parser.parse_args()
    try:
        if args.operation == 'renew':
            return renew(args.app, args.device)
        if args.operation == 'guard':
            if args.repair and not can_reinstall(args.app, args.device):
                raise NeedsRepair('the installed app or saved IPA changed; review Install / Update')
            return install_guard(args.app, args.device, args.confirmed)
        if args.operation == 'can-reinstall':
            return 0 if can_reinstall(args.app, args.device) else REPAIR
        if args.operation == 'check':
            check(args.app, args.device)
            return 0
        record_install(args.app, args.device)
        return 0
    except NeedsRepair as error:
        print(f'Renewal requires repair: {error}.', flush=True)
        return REPAIR
    except Exception as error:
        # No Apple response bodies or account credentials in error output.
        print(f'Device renewal check failed ({type(error).__name__}); no replacement app was authorized.', flush=True)
        return 1


if __name__ == '__main__':
    sys.exit(main())
