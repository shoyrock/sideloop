"""Verify Apple credentials before committing account changes."""
import os
import tempfile
from pathlib import Path

from . import accounts, config
from .jobs import run_pty

SUCCESS = 'Account authentication succeeded.'
AUTH_TIMEOUT = 300


def _authenticate(job, candidate, work):
    home = work / '.altserver'
    home.mkdir(parents=True, exist_ok=True)
    # Unsaved passwords are not yet returned by accounts.passwords().
    job.secrets.append(candidate['APPLE_PASSWORD'])
    env = {**os.environ, 'TZ': 'UTC', 'HOME': str(home),
           'ALTSERVER_ANISETTE_SERVER': config.ANISETTE,
           'ALTSERVER_APPLE_ID': candidate['APPLE_ID'],
           'ALTSERVER_APPLE_PASSWORD': candidate['APPLE_PASSWORD']}
    job.say('Signing in to Apple to verify this account…')
    run_pty(job, ['timeout', '--foreground', str(AUTH_TIMEOUT), os.environ.get('ALTSERVER_BIN', 'AltServer'),
                  '--verify-account'], env=env, cwd=str(work))
    confirmed = job.rc == 0 and not job.cancelled and SUCCESS in job.lines
    if not confirmed:
        job.rc = job.rc or 1
        if job.cancelled:
            job.say('Account verification cancelled.')
        elif job.rc == 124:
            job.say('Account verification timed out. Try again when you can complete Apple verification.')
        else:
            job.say('Apple sign-in was not verified. See Details for the authentication error.')
    return confirmed


def verify(job, account_id):
    candidate = accounts.credentials(account_id)
    work = config.DATA if account_id == 'default' else accounts._folder(account_id) / 'runtime'
    accounts.set_verification(account_id, 'checking')
    try:
        confirmed = _authenticate(job, candidate, work)
        accounts.set_verification(account_id, 'verified' if confirmed else
                                  'unverified' if job.cancelled else 'failed')
    except Exception:
        accounts.set_verification(account_id, 'failed')
        raise


def verify_and_save(job, account_id, candidate):
    # Pending credentials stay in memory and out of existing signing caches.
    with tempfile.TemporaryDirectory(prefix='sideloop-auth-') as work:
        if not _authenticate(job, candidate, Path(work)):
            job.say('Apple sign-in was not verified; account changes were not saved.')
            return
    with job.lock:
        if job.cancelled:
            job.rc = 1
            return
        saved = accounts.save(account_id, candidate['APPLE_ID'], candidate['APPLE_PASSWORD'])
        accounts.set_verification(saved, 'verified')
        job.saved_account = saved
