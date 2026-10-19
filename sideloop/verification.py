"""Verify Apple credentials before committing account changes."""
import os
import tempfile
from pathlib import Path

from . import accounts, config
from .jobs import run_pty

SUCCESS = 'Account authentication succeeded.'
AUTH_TIMEOUT = 300
REJECTED_HINT = ('Apple refused this Apple ID sign-in (-22411). Complete any verification Apple requests '
                 'and try again. This error can also indicate a signing-service compatibility problem; '
                 'it does not by itself mean the account has never been used on an Apple device.')
# Apple returns -80045 when the client identity doesn't match the platform that made the
# Anisette data. Nothing about the Apple ID causes it; the signing service has to change.
SIGNER_HINT = ('Apple refused the sign-in from this signing service (-80045), not the Apple ID. '
               'Update Sideloop to the latest image, then try again.')

SERVICE_HINT = ('Apple authentication service unavailable (HTTP 503). Apple may be refusing the signing '
                'service identity, or its service may be temporarily unavailable. The password and MFA '
                'have not been verified; changing the account is not a confirmed fix.')


def _authenticate(job, candidate, work, unsaved=False):
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
        # The last line is the sheet's summary, so it carries the save outcome too.
        note = ' Account changes were not saved.' if unsaved else ''
        if job.cancelled:
            job.say('Account verification cancelled.' + note)
        elif job.rc == 124:
            job.say('Account verification timed out. Try again when you can complete Apple verification.' + note)
        elif 'Apple authentication HTTP status: 503' in job.lines:
            job.say(SERVICE_HINT + note)
        elif any('-22411' in line for line in job.lines):
            job.say(REJECTED_HINT + note)
        elif any('-80045' in line for line in job.lines):
            job.say(SIGNER_HINT + note)
        else:
            job.say('Apple sign-in was not verified; account changes were not saved.' if unsaved else
                    'Apple sign-in was not verified. See Details for the authentication error.')
    if confirmed:
        (work / '.auth-retry-after').unlink(missing_ok=True)
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
        if not _authenticate(job, candidate, Path(work), unsaved=True):
            return
    with job.lock:
        if job.cancelled:
            job.rc = 1
            return
        saved = accounts.save(account_id, candidate['APPLE_ID'], candidate['APPLE_PASSWORD'])
        work = config.DATA if saved == 'default' else accounts._folder(saved) / 'runtime'
        (work / '.auth-retry-after').unlink(missing_ok=True)
        accounts.set_verification(saved, 'verified')
        job.saved_account = saved
