import base64
import contextlib
import io
import json
from pathlib import Path
import plistlib
import tempfile
import threading
import unittest
import urllib.request

from sideloop.anisette import Identity, ProviderError, provider_url, serve


PRIMARY = 'https://primary.example'
BACKUP = 'https://backup.example'
CLIENT = {
    'client_info': '<MacBookPro13,3> <Mac OS X;10.12.6;16G29> <com.apple.akd>',
    'user_agent': 'akd/1.0 CFNetwork/811.5.4 Darwin/16.7.0',
}
BLOB = base64.b64encode(b'synthetic-provisioning-material').decode()


class ProviderFixture:
    def __init__(self):
        self.requests = []
        self.down = set()
        self.clients = {PRIMARY: CLIENT, BACKUP: CLIENT}
        self.provisions = 0
        self.replies = []
        self.closed = 0
        self.reject_headers = False
        self.bad_bag = False

    def request(self, url, data=None, headers=None):
        self.requests.append((url, data, headers))
        origin = '/'.join(url.split('/')[:3])
        if origin in self.down:
            raise OSError('provider offline, synthetic-private-data')
        if url.endswith('/v3/client_info'):
            return json.dumps(self.clients[origin]).encode()
        if url.endswith('/v3/get_headers'):
            body = json.loads(data)
            if body['adi_pb'] != BLOB:
                raise AssertionError('wrong saved identity')
            result = (
                {'result': 'GetHeadersError', 'message': 'synthetic-private-data'}
                if self.reject_headers
                else {
                    'result': 'Headers',
                    'X-Apple-I-MD': 'synthetic-otp',
                    'X-Apple-I-MD-M': 'synthetic-machine',
                    'X-Apple-I-MD-RINFO': '17106176',
                }
            )
            return json.dumps(result).encode()
        if url.endswith('/lookup'):
            host = 'https://attacker.example' if self.bad_bag else 'https://gsa.apple.com'
            response = {
                'urls': {
                    'midStartProvisioning': host + '/start',
                    'midFinishProvisioning': 'https://gsa.apple.com/finish',
                }
            }
        elif url.endswith('/start'):
            response = {'spim': 'synthetic-start'}
        elif url.endswith('/finish'):
            if plistlib.loads(data)['Request'] != {'cpim': 'synthetic-cpim'}:
                raise AssertionError('incorrect provisioning exchange')
            response = {'ptm': 'synthetic-ptm', 'tk': 'synthetic-tk'}
        else:
            raise AssertionError(url)
        return plistlib.dumps(response if url.endswith('/lookup') else {'Response': response})

    @contextlib.contextmanager
    def connect(self, url):
        self.provisions += 1
        self.messages = iter(
            [
                {'result': 'GiveIdentifier'},
                {'result': 'GiveStartProvisioningData'},
                {'result': 'GiveEndProvisioningData', 'cpim': 'synthetic-cpim'},
                {'result': 'ProvisioningSuccess', 'adi_pb': BLOB},
            ]
        )
        try:
            yield self
        finally:
            self.closed += 1

    def recv(self):
        return json.dumps(next(self.messages))

    def send(self, value):
        self.replies.append(json.loads(value))


class AnisetteTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.path = Path(self.folder.name) / 'identity.json'
        self.transport = ProviderFixture()

    def identity(self):
        return Identity(self.path, [PRIMARY, BACKUP], self.transport)

    def test_provisioned_identity_survives_restart_and_fresh_otp_requests(self):
        first = self.identity().headers()
        saved = self.path.read_bytes()
        second = self.identity().headers()
        self.assertEqual(first['X-Mme-Device-Id'], second['X-Mme-Device-Id'])
        self.assertEqual(first['X-Apple-I-MD-LU'], second['X-Apple-I-MD-LU'])
        self.assertEqual(self.path.read_bytes(), saved)
        self.assertEqual(self.transport.provisions, 1)
        self.assertEqual(self.transport.closed, 1)
        self.assertEqual(
            len([r for r in self.transport.requests if r[0].endswith('/get_headers')]), 2
        )
        self.assertEqual(
            self.transport.replies[1:],
            [{'spim': 'synthetic-start'}, {'ptm': 'synthetic-ptm', 'tk': 'synthetic-tk'}],
        )

    def test_same_platform_failover_preserves_identity_and_remembers_provider(self):
        first = self.identity().headers()
        self.transport.down.add(PRIMARY)
        second = self.identity().headers()
        self.assertEqual(first['X-Mme-Device-Id'], second['X-Mme-Device-Id'])
        self.assertEqual(json.loads(self.path.read_text())['provider'], BACKUP)
        self.transport.requests.clear()
        self.identity().headers()
        self.assertTrue(self.transport.requests[0][0].startswith(BACKUP))
        self.assertEqual(self.transport.provisions, 1)

    def test_provider_outage_preserves_trusted_state_and_recovers(self):
        first = self.identity().headers()
        saved = self.path.read_bytes()
        self.transport.down.update([PRIMARY, BACKUP])
        with self.assertRaisesRegex(ProviderError, 'identity preserved'):
            self.identity().headers()
        self.assertEqual(self.path.read_bytes(), saved)
        self.transport.down.clear()
        self.assertEqual(self.identity().headers()['X-Mme-Device-Id'], first['X-Mme-Device-Id'])
        self.assertEqual(self.transport.provisions, 1)

    def test_incompatible_provider_never_receives_saved_blob(self):
        self.identity().headers()
        saved = self.path.read_bytes()
        self.transport.down.add(PRIMARY)
        self.transport.clients[BACKUP] = {**CLIENT, 'client_info': '<Android;14>'}
        self.transport.requests.clear()
        with self.assertRaises(ProviderError):
            self.identity().headers()
        self.assertFalse(any(r[0] == BACKUP + '/v3/get_headers' for r in self.transport.requests))
        self.assertEqual(self.path.read_bytes(), saved)

    def test_rejected_identity_is_not_silently_reprovisioned(self):
        self.identity().headers()
        saved = self.path.read_bytes()
        self.transport.reject_headers = True
        with self.assertRaises(ProviderError) as error:
            self.identity().headers()
        self.assertNotIn('synthetic-private-data', str(error.exception))
        self.assertEqual(self.path.read_bytes(), saved)
        self.assertEqual(self.transport.provisions, 1)

    def test_damaged_state_is_preserved_without_network_or_identity_reset(self):
        self.path.write_text('{broken')
        with self.assertRaisesRegex(ProviderError, 'restore its backup'):
            self.identity().headers()
        self.assertEqual(self.path.read_text(), '{broken')
        self.assertEqual(self.transport.requests, [])

    def test_provisioning_urls_cannot_send_material_away_from_apple(self):
        self.transport.bad_bag = True
        with self.assertRaises(ProviderError):
            self.identity().headers()
        self.assertFalse(
            any(r[0].startswith('https://attacker.example') for r in self.transport.requests)
        )
        self.assertFalse(self.path.exists())
        self.assertEqual(self.transport.closed, 2)

    def test_loopback_health_does_not_contact_providers_and_errors_hide_material(self):
        server = serve(self.identity(), port=0)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        base = 'http://127.0.0.1:' + str(server.server_port)
        with urllib.request.urlopen(base + '/health') as response:
            self.assertEqual(json.load(response), {'status': 'running'})
        self.assertEqual(self.transport.requests, [])
        self.transport.down.update([PRIMARY, BACKUP])
        with contextlib.redirect_stderr(io.StringIO()) as log:
            with self.assertRaises(urllib.error.HTTPError) as error:
                urllib.request.urlopen(base + '/')
            self.assertEqual(error.exception.code, 503)
            self.assertNotIn(b'synthetic-private-data', error.exception.read())
        self.assertEqual(log.getvalue(), '')

    def test_provider_configuration_rejects_credentials_http_and_query_strings(self):
        for value in [
            'http://remote.example',
            'https://u:p@remote.example',
            'https://remote.example/?token=x',
        ]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                provider_url(value)


if __name__ == '__main__':
    unittest.main()
