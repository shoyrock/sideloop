"""Verify saved Apple credentials through the same engine used for signing."""
import os
from pathlib import Path

from . import accounts, config
from .jobs import run_pty

SUCCESS = 'Account authentication succeeded.'
AUTH_TIMEOUT = 300


def verify(job, account_id):
    c = accounts.credentials(account_id)
    work = config.DATA if account_id == 'default' else accounts._folder(account_id) / 'runtime'
    home = work / '.altserver'
    home.mkdir(parents=True, exist_ok=True)
    env = {**os.environ, 'TZ': 'UTC', 'HOME': str(home),
           'ALTSERVER_ANISETTE_SERVER': config.ANISETTE,
           'ALTSERVER_APPLE_ID': c['APPLE_ID'], 'ALTSERVER_APPLE_PASSWORD': c['APPLE_PASSWORD']}
    accounts.set_verification(account_id, 'checking')
    job.say('Signing in to Apple to verify this account…')
    try:
        run_pty(job, ['timeout', '--foreground', str(AUTH_TIMEOUT), os.environ.get('ALTSERVER_BIN', 'AltServer'),
                      '--verify-account'], env=env, cwd=str(work))
        confirmed = job.rc == 0 and not job.cancelled and SUCCESS in job.lines
        if confirmed:
            accounts.set_verification(account_id, 'verified')
        else:
            job.rc = job.rc or 1
            accounts.set_verification(account_id, 'unverified' if job.cancelled else 'failed')
            if job.cancelled:
                job.say('Account verification cancelled.')
            elif job.rc == 124:
                job.say('Account verification timed out. Try again when you can complete Apple verification.')
            else:
                job.say('Apple sign-in was not verified. See Details for the authentication error.')
    except Exception:
        accounts.set_verification(account_id, 'failed')
        raise
