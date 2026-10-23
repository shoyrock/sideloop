"""Persistent Omnisette v3 identity, exposed locally for the existing AltServer API.

Only virtual-device provisioning material goes to configured providers. Apple
credentials are never accepted here; AltSign still owns account authentication.
"""

import base64
import contextlib
import datetime as dt
import hashlib
import http.server
import json
import os
from pathlib import Path
import plistlib
import ssl
import threading
import urllib.parse
import urllib.request
import uuid


MAX_RESPONSE = 1024 * 1024
LOOKUP = 'https://gsa.apple.com/grandslam/GsService2/lookup'


class ProviderError(Exception):
    """A safe fixed message, without remote response bodies or identity material."""


def provider_url(value):
    parsed = urllib.parse.urlsplit(value.strip().rstrip('/'))
    if (
        parsed.scheme != 'https'
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.path not in ('', '/')
    ):
        raise ValueError('Anisette v3 providers must be HTTPS origin URLs')
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, '', '', ''))


def encoded_bytes(value):
    if not isinstance(value, str) or not value:
        raise ValueError('missing encoded identity data')
    return base64.b64decode(value, validate=True)


def json_object(body):
    value = json.loads(body)
    if not isinstance(value, dict):
        raise ProviderError('Anisette provider returned an invalid protocol object')
    return value


class Transport:
    def __init__(self):
        self.context = ssl.create_default_context()
        certificate = Path('/usr/local/share/ca-certificates/apple-root-ca.crt')
        if not certificate.exists():
            certificate = Path(__file__).resolve().parents[1] / 'container/apple-root-ca.crt'
        self.context.load_verify_locations(cafile=str(certificate))

    def request(self, url, data=None, headers=None):
        request = urllib.request.Request(url, data=data, headers=headers or {})

        # Redirects must not forward provisioning material to a different host.
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, hdrs, newurl):
                return None

        opener = urllib.request.build_opener(
            NoRedirect(), urllib.request.HTTPSHandler(context=self.context)
        )
        with opener.open(request, timeout=15) as response:
            body = response.read(MAX_RESPONSE + 1)
        if len(body) > MAX_RESPONSE:
            raise ProviderError('Anisette response exceeded the size limit')
        return body

    @contextlib.contextmanager
    def connect(self, url):
        # Debian's websocket-client handles framing, TLS and control messages.
        import websocket

        socket = None
        try:
            socket = websocket.create_connection(url, timeout=15, sslopt={'context': self.context})
            yield socket
        except websocket.WebSocketException as error:
            raise ProviderError('Anisette provisioning connection failed') from error
        finally:
            if socket is not None:
                socket.close()


class Identity:
    def __init__(self, path, providers, transport=None):
        self.path = Path(path)
        self.providers = list(dict.fromkeys(provider_url(url) for url in providers))
        if not 1 <= len(self.providers) <= 3:
            raise ValueError('configure between one and three Anisette providers')
        self.transport = transport or Transport()
        self.lock = threading.Lock()

    def load(self):
        try:
            state = json.loads(self.path.read_text(encoding='utf-8'))
        except FileNotFoundError:
            return {'identifier': base64.b64encode(os.urandom(16)).decode()}
        except (ValueError, UnicodeError) as error:
            raise ProviderError('Saved Anisette identity is damaged; restore its backup') from error
        except OSError as error:
            raise ProviderError(
                'Cannot read saved Anisette identity; check appdata permissions'
            ) from error
        try:
            if len(encoded_bytes(state['identifier'])) != 16:
                raise ValueError('invalid identifier')
            if 'adi_pb' in state:
                encoded_bytes(state['adi_pb'])
                self.client_headers(state['client'])
            return state
        except (KeyError, TypeError, ValueError) as error:
            raise ProviderError('Saved Anisette identity is damaged; restore its backup') from error

    def save(self, state):
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        temporary = self.path.with_suffix('.tmp')
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as output:
            json.dump(state, output)
        os.replace(temporary, self.path)

    @staticmethod
    def client_headers(client):
        for key in ('client_info', 'user_agent'):
            value = client[key]
            if (
                not isinstance(value, str)
                or not value
                or len(value) > 1024
                or '\r' in value
                or '\n' in value
            ):
                raise ProviderError('Anisette provider returned invalid client metadata')
        return {
            'X-Mme-Client-Info': client['client_info'],
            'User-Agent': client['user_agent'],
            'Content-Type': 'text/x-xml-plist',
            'Accept': 'text/x-xml-plist',
            'X-Apple-App-Info': 'com.apple.gs.xcode.auth',
            'X-Xcode-Version': '14.2 (14C18)',
        }

    def apple(self, url, client, request=None, identity=None):
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme != 'https' or parsed.netloc != 'gsa.apple.com':
            raise ProviderError('Apple provisioning URL was not an expected Apple HTTPS endpoint')
        headers = self.client_headers(client)
        if identity:
            raw = encoded_bytes(identity['identifier'])
            headers.update(
                {
                    'X-Apple-I-MD-LU': hashlib.sha256(raw).hexdigest(),
                    'X-Mme-Device-Id': str(uuid.UUID(bytes=raw)),
                }
            )
        body = None if request is None else plistlib.dumps({'Header': {}, 'Request': request})
        result = plistlib.loads(self.transport.request(url, body, headers))
        return result if request is None else result['Response']

    def provision(self, url, client, state):
        bag = self.apple(LOOKUP, client)['urls']
        with self.transport.connect(
            url.replace('https://', 'wss://', 1) + '/v3/provisioning_session'
        ) as socket:
            for _ in range(8):
                raw = socket.recv()
                if not isinstance(raw, str) or len(raw) > MAX_RESPONSE:
                    raise ProviderError(
                        'Anisette provisioning connection ended or returned invalid data'
                    )
                message = json_object(raw)
                result = message.get('result')
                if result == 'GiveIdentifier':
                    reply = {'identifier': state['identifier']}
                elif result == 'GiveStartProvisioningData':
                    data = self.apple(bag['midStartProvisioning'], client, {}, state)
                    reply = {'spim': data['spim']}
                elif result == 'GiveEndProvisioningData':
                    data = self.apple(
                        bag['midFinishProvisioning'], client, {'cpim': message['cpim']}, state
                    )
                    reply = {'ptm': data['ptm'], 'tk': data['tk']}
                elif result == 'ProvisioningSuccess':
                    encoded_bytes(message['adi_pb'])
                    return {**state, 'adi_pb': message['adi_pb'], 'client': client}
                else:
                    raise ProviderError('Anisette provider refused virtual-device provisioning')
                socket.send(json.dumps(reply))
            raise ProviderError('Anisette provisioning exceeded the protocol step limit')

    def headers(self):
        with self.lock:
            state = self.load()
            preferred = state.get('provider')
            providers = sorted(self.providers, key=lambda url: url != preferred)
            for url in providers:
                try:
                    client = json_object(self.transport.request(url + '/v3/client_info'))
                    self.client_headers(client)
                    client = {key: client[key] for key in ('client_info', 'user_agent')}
                    # Never send an established identity to a different ADI platform.
                    if 'client' in state and client != state['client']:
                        continue
                    candidate = (
                        dict(state) if 'adi_pb' in state else self.provision(url, client, state)
                    )
                    body = json.dumps(
                        {key: candidate[key] for key in ('identifier', 'adi_pb')}
                    ).encode()
                    response = json_object(
                        self.transport.request(
                            url + '/v3/get_headers', body, {'Content-Type': 'application/json'}
                        )
                    )
                    if response.get('result') != 'Headers':
                        raise ProviderError('Provider could not use the saved Anisette identity')
                    keys = ('X-Apple-I-MD', 'X-Apple-I-MD-M', 'X-Apple-I-MD-RINFO')
                    if any(
                        not isinstance(response.get(key), str)
                        or not response[key]
                        or len(response[key]) > 8192
                        or '\r' in response[key]
                        or '\n' in response[key]
                        for key in keys
                    ):
                        raise ProviderError('Provider returned incomplete Anisette headers')
                    if not response['X-Apple-I-MD-RINFO'].isdecimal():
                        raise ProviderError('Provider returned invalid Anisette routing info')
                except (OSError, ValueError, KeyError, TypeError, ProviderError):
                    continue
                # Persist only after the provider proves the identity works. Outages
                # never rotate it or replace a previously trusted identity.
                candidate['provider'] = url
                if candidate != state or not self.path.exists():
                    try:
                        self.save(candidate)
                    except OSError as error:
                        raise ProviderError(
                            'Cannot save Anisette identity; check appdata permissions'
                        ) from error
                raw = encoded_bytes(candidate['identifier'])
                return {
                    **{key: response[key] for key in keys},
                    'X-Apple-I-MD-LU': hashlib.sha256(raw).hexdigest(),
                    'X-Mme-Device-Id': str(uuid.UUID(bytes=raw)),
                    'X-MMe-Client-Info': client['client_info'],
                    'X-Apple-I-SRL-NO': '0',
                    'X-Apple-Locale': 'en_US',
                    'X-Apple-I-TimeZone': 'UTC',
                    'X-Apple-I-Client-Time': dt.datetime.now(dt.timezone.utc).strftime(
                        '%Y-%m-%dT%H:%M:%SZ'
                    ),
                }
            raise ProviderError(
                'Configured Anisette providers are unavailable or incompatible; identity preserved'
            )


def serve(identity, port=6969):
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path not in ('/', '/health'):
                self.send_error(404)
                return
            try:
                data = {'status': 'running'} if self.path == '/health' else identity.headers()
                body = json.dumps(data).encode()
                self.send_response(200)
            except ProviderError as error:
                body = json.dumps({'error': str(error)}).encode()
                self.send_response(503)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Cache-Control', 'no-store')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format, *args):
            pass

    return http.server.ThreadingHTTPServer(('127.0.0.1', port), Handler)


if __name__ == '__main__':
    location = Path(os.environ.get('DATA_DIR', '/data')) / 'anisette-v3' / 'identity.json'
    providers = os.environ['ANISETTE_V3_SERVERS'].split(',')
    server = serve(Identity(location, providers))
    print(
        'Persistent Anisette v3 service listening on loopback; identity values are not logged',
        flush=True,
    )
    server.serve_forever()
