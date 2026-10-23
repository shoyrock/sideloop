"""Real signed profiles + fake phone/Apple transport; no Apple or device access."""
import copy
import datetime as dt
import hashlib
import json
import os
import plistlib
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from sideloop import accounts, config, renewal, store, uploads, jobs

UDID = '1234567890abcdef1234567890abcdef12345678'
TEAM = 'TEAM123456'
BUNDLE = 'test.app.' + TEAM


class Phone:
    def __init__(self, app, profiles):
        self.apps, self.items = {BUNDLE: app}, list(profiles)
        self.writes, self.removes = [], []
        self.fail_after = None
        self.drop_write = False
    def applications(self): return self.apps
    def profiles(self): return list(self.items)
    def install(self, raw):
        if self.fail_after is not None and len(self.writes) >= self.fail_after:
            raise ConnectionError('synthetic lost connection')
        self.writes.append(raw)
        if not self.drop_write: self.items.append((raw, renewal.decode_profile(raw)))
    def remove(self, uuid):
        self.removes.append(uuid)
        self.items = [(raw, p) for raw, p in self.items if p['UUID'] != uuid]


class RenewalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.certs = tempfile.TemporaryDirectory()
        cls.certdir = Path(cls.certs.name)
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                        '-subj', '/CN=Renewal test', '-keyout', str(cls.certdir/'key'), '-out', str(cls.certdir/'cert')],
                       check=True, capture_output=True)
        cls.der = subprocess.check_output(['openssl', 'x509', '-in', str(cls.certdir/'cert'), '-outform', 'DER'])
        cls.cert_hash = hashlib.sha1(cls.der).hexdigest()

    @classmethod
    def tearDownClass(cls): cls.certs.cleanup()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.patches = [patch.object(config, 'DATA', self.root), patch.object(config, 'APPS', self.root/'apps'),
                        patch.object(accounts, 'state_folder', return_value=self.root/'state'),
                        patch.object(store, 'app_meta', return_value={'BUNDLE_ID':'test.app', 'KEEP_EXTENSIONS':''})]
        for p in self.patches: p.start()
        self.state = self.root/'state'; self.state.mkdir()
        (self.state/'certificate').write_text(self.cert_hash)
        (self.state/'expiry').write_text('123')
        self.now = dt.datetime.now(dt.timezone.utc).replace(tzinfo=None, microsecond=0)
        self.app = {'CFBundleIdentifier':BUNDLE, 'CFBundleShortVersionString':'5.2', 'CFBundleVersion':'501'}
        self.old = self.profile(BUNDLE, 'old', 1)
        self.phone = Phone(self.app, [(self.encode(self.old), self.old)])
        self.created = []

    def tearDown(self):
        for p in reversed(self.patches): p.stop()
        self.temp.cleanup()

    def profile(self, bundle, uuid, days):
        return {'UUID':uuid, 'TeamIdentifier':[TEAM], 'ProvisionedDevices':[UDID],
                'DeveloperCertificates':[self.der], 'CreationDate':self.now,
                'ExpirationDate':self.now+dt.timedelta(days=days),
                'Entitlements':{'application-identifier':TEAM+'.'+bundle, 'get-task-allow':True}}

    def encode(self, p):
        return subprocess.run(['openssl','smime','-sign','-signer',str(self.certdir/'cert'),
                               '-inkey',str(self.certdir/'key'),'-outform','DER','-nodetach'],
                              input=plistlib.dumps(p),capture_output=True,check=True).stdout

    def signer(self, argv, timeout):
        self.assertEqual(argv[-2], '--refresh-profiles')
        request = json.loads(Path(argv[-1]).read_text())
        self.assertEqual(request['team'], TEAM)
        self.assertTrue(request['certificate_serial'])
        for i, bundle in enumerate(request['bundles']):
            p = self.profile(bundle, 'new'+str(i), 7-i)
            if hasattr(self, 'alter'): self.alter(p, i)
            raw = self.encode(p); self.created.append((raw,p))
            (Path(request['output'])/f'{i}.mobileprovision').write_bytes(raw)
        return SimpleNamespace(returncode=0)

    def test_renews_installed_newer_app_without_reading_or_copying_library_ipa(self):
        with patch.object(renewal.ipa, 'signing_copy', side_effect=AssertionError('must not read IPA')):
            self.assertEqual(renewal.renew('test.app', UDID, self.phone, self.signer), 0)
        self.assertEqual(self.phone.apps[BUNDLE]['CFBundleVersion'], '501')
        self.assertEqual(len(self.phone.writes), 1)
        self.assertEqual(self.phone.removes, ['old'])
        self.assertGreater(int((self.state/'expiry').read_text()), time.time()+6*86400)
        self.assertEqual(json.loads((self.state/'installed.json').read_text())['version'], '5.2')

    def add_extension(self):
        ext = BUNDLE+'.share'
        self.app['PluginKitPlugins'] = {ext:{'CFBundleIdentifier':ext}}
        p = self.profile(ext, 'old-extension', 1)
        self.phone.items.append((self.encode(p),p))

    def test_extensions_are_renewed_and_earliest_expiry_is_reported(self):
        self.add_extension()
        renewal.renew('test.app',UDID,self.phone,self.signer)
        self.assertEqual(len(self.phone.writes),2)
        self.assertEqual(int((self.state/'expiry').read_text()), renewal.epoch(self.created[1][1]['ExpirationDate']))

    def test_all_profiles_are_validated_before_any_install(self):
        self.add_extension()
        self.alter = lambda p,i: p['Entitlements'].update({'changed':True}) if i else None
        with self.assertRaises(renewal.NeedsRepair): renewal.renew('test.app',UDID,self.phone,self.signer)
        self.assertFalse(self.phone.writes)
        self.assertEqual((self.state/'expiry').read_text(),'123')

    def test_partial_failure_keeps_old_profiles_and_does_not_report_success(self):
        self.add_extension(); self.phone.fail_after = 1
        with self.assertRaises(ConnectionError): renewal.renew('test.app',UDID,self.phone,self.signer)
        self.assertFalse(self.phone.removes)
        self.assertEqual((self.state/'expiry').read_text(),'123')

    def test_missing_readback_does_not_report_success(self):
        self.phone.drop_write = True
        with self.assertRaises(ConnectionError): renewal.renew('test.app',UDID,self.phone,self.signer)
        self.assertEqual((self.state/'expiry').read_text(),'123')

    def test_invalid_new_profiles_are_rejected(self):
        for alter in [lambda p: p.update(TeamIdentifier=['OTHER']),
                      lambda p: p.update(DeveloperCertificates=[b'other']),
                      lambda p: p.update(ProvisionedDevices=['other']),
                      lambda p: p.update(ExpirationDate=self.now-dt.timedelta(seconds=1)),
                      lambda p: p['Entitlements'].update({'extra':True})]:
            p=copy.deepcopy(self.profile(BUNDLE,'new',7)); alter(p)
            with self.assertRaises(renewal.NeedsRepair):
                renewal.validate_replacement(self.old,p,self.cert_hash,UDID,int(time.time()))

    def test_missing_or_different_certificate_never_calls_signer(self):
        (self.state/'certificate').write_text('other')
        with self.assertRaises(renewal.NeedsRepair):
            renewal.renew('test.app',UDID,self.phone,lambda *a,**k:self.fail('Apple must not be called'))

    def test_offline_check_preserves_known_expiry(self):
        self.phone.applications = lambda: (_ for _ in ()).throw(ConnectionError('offline'))
        with self.assertRaises(ConnectionError): renewal.check('test.app',UDID,self.phone)
        self.assertEqual((self.state/'expiry').read_text(),'123')

    def test_uninstalled_app_is_not_renewed_or_installed(self):
        self.phone.apps = {}
        with self.assertRaises(renewal.NeedsRepair): renewal.renew('test.app',UDID,self.phone,self.signer)
        renewal.check('test.app',UDID,self.phone)
        self.assertFalse((self.state/'expiry').exists())
        self.assertFalse(self.phone.writes)

    def test_replacement_requires_explicit_confirmation_even_for_same_version(self):
        with self.assertRaises(renewal.NeedsRepair): renewal.install_guard('test.app',UDID,False,self.phone)
        self.assertEqual(renewal.install_guard('test.app',UDID,True,self.phone),0)

    def test_apple_refusal_does_not_change_device_or_expiry(self):
        self.assertEqual(renewal.renew('test.app',UDID,self.phone,lambda *a,**k:SimpleNamespace(returncode=42)),42)
        self.assertFalse(self.phone.writes)
        self.assertEqual((self.state/'expiry').read_text(),'123')

    def test_upload_previews_are_isolated_and_can_only_be_claimed_once_by_owner(self):
        a,pa=uploads.create('session-a'); pa.write_bytes(b'app A'); uploads.complete(a,'session-a')
        b,pb=uploads.create('session-a'); pb.write_bytes(b'app B'); uploads.complete(b,'session-a')
        with self.assertRaises(ValueError): uploads.claim(a,'session-b')
        self.assertEqual(uploads.claim(a,'session-a').read_bytes(),b'app A')
        with self.assertRaises(ValueError): uploads.claim(a,'session-a')
        self.assertEqual(uploads.claim(b,'session-a').read_bytes(),b'app B')

    def test_quiet_process_timeout_is_enforced(self):
        import sys
        job=jobs.Job('test','quiet child'); started=time.monotonic()
        jobs.run_capture(job,[sys.executable,'-c','import time; time.sleep(10)'],timeout=.1)
        self.assertEqual(job.rc,124)
        self.assertLess(time.monotonic()-started,2)

    def test_quiet_process_success_is_reaped(self):
        import sys
        job=jobs.Job('test','quiet child')
        jobs.run_capture(job,[sys.executable,'-c','pass'],timeout=2)
        self.assertEqual(job.rc,0)

    def test_timeout_still_applies_after_child_closes_output(self):
        import sys
        job=jobs.Job('test','closed output'); started=time.monotonic()
        jobs.run_capture(job,[sys.executable,'-c','import os,time; os.close(1); os.close(2); time.sleep(10)'],timeout=.1)
        self.assertEqual(job.rc,124)
        self.assertLess(time.monotonic()-started,2)

    def test_automatic_reinstall_requires_matching_receipt_ipa_and_installed_version(self):
        folder=config.APPS/'test.app'; folder.mkdir(parents=True); (folder/'app.ipa').write_bytes(b'original IPA')
        receipt={'bundle':BUNDLE,'version':'5.2','build':'501','keep_extensions':False,
                 'ipa_sha256':renewal.fingerprint(folder/'app.ipa')}
        self.assertFalse(renewal.can_reinstall('test.app',UDID,self.phone))
        renewal.atomic_json(self.state/'installation.json',receipt)
        self.assertTrue(renewal.can_reinstall('test.app',UDID,self.phone))
        self.app['CFBundleVersion']='502'
        self.assertFalse(renewal.can_reinstall('test.app',UDID,self.phone))
        self.app['CFBundleVersion']='501'; (folder/'app.ipa').write_bytes(b'uploaded update')
        self.assertFalse(renewal.can_reinstall('test.app',UDID,self.phone))

    def test_corrupt_verification_status_is_quarantined_without_touching_credentials(self):
        path=self.root/'account-verification.json'
        secret=self.root/'credentials.env'; secret.write_text('preserve')
        for value in ('{','[]','{"default": null}','{"default":{"status":"verified","checked_at":"wrong"}}'):
            path.write_text(value)
            self.assertEqual(accounts.verification('default'),{'status':'unverified'})
            self.assertFalse(path.exists())
        self.assertEqual(len(list(self.root.glob('account-verification.json.invalid-*'))),4)
        self.assertEqual(secret.read_text(),'preserve')

    def test_long_identifiers_do_not_overwrite_each_other_and_existing_legacy_path_is_reused(self):
        with patch.object(store,'APPS',config.APPS), patch.object(store,'app_meta',side_effect=lambda a:
                config.read_env(config.APPS/a/'meta.env',store.APP_KEYS)):
            prefix='com.'+'a'*120
            ids=[]
            for suffix in ('one','two'):
                source=self.root/(suffix+'.ipa'); source.write_bytes(suffix.encode())
                ids.append(store.add_app(source,{'bundle_id':prefix+suffix,'version':'1'},suffix+'.ipa'))
            self.assertNotEqual(*ids)
            self.assertEqual((config.APPS/ids[0]/'app.ipa').read_bytes(),b'one')
            original=ids[0]; legacy=(prefix+'one')[:120]
            (config.APPS/original).rename(config.APPS/legacy)
            source=self.root/'update.ipa'; source.write_bytes(b'update')
            self.assertEqual(store.add_app(source,{'bundle_id':prefix+'one','version':'2'},'update.ipa'),legacy)


if __name__ == '__main__': unittest.main()
