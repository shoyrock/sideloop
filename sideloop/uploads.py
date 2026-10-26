"""Each preview owns a separate IPA and is bound to the signed-in session."""
import hashlib
import re
import secrets
import time
from . import config
from .renewal import atomic_json, read_json

TTL = 24 * 3600


def folder():
    path = config.DATA / '.uploads'
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    return path


def create(session):
    root = folder()
    for path in root.glob('*'):
        try:
            if path.is_file() and path.stat().st_mtime < time.time() - TTL:
                path.unlink(missing_ok=True)
        except FileNotFoundError:
            pass  # Another preview request may have claimed or cleaned it up.
    token = secrets.token_hex(24)
    return token, root / (token + '.ipa')


def complete(token, session):
    atomic_json(folder() / (token + '.json'), {'owner': hashlib.sha256(session.encode()).hexdigest(),
                                            'created': time.time()})


def claim(token, session):
    if not isinstance(token, str) or not re.fullmatch(r'[a-f0-9]{48}', token):
        raise ValueError('upload the IPA again; this preview has no valid upload identifier')
    root = folder()
    metadata = root / (token + '.json')
    data = read_json(metadata)
    if (data.get('owner') != hashlib.sha256(session.encode()).hexdigest()
            or data.get('created', 0) < time.time() - TTL):
        raise ValueError('this upload preview expired or belongs to another session')
    path, claimed = root / (token + '.ipa'), root / (token + '.claimed')
    try:
        path.rename(claimed)
    except FileNotFoundError:
        raise ValueError('this upload has already been used; upload it again') from None
    metadata.unlink(missing_ok=True)
    return claimed
