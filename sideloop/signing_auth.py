"""Account-wide authentication failures and persistent automatic retry limits.

Only fixed classifications are stored. Raw signer output can contain Apple
session material and must never become part of this state or the API response.
"""
import json
import os
import re
import shlex
import sys
import time
from pathlib import Path

RETRY_INTERVAL = 30 * 60
MAX_RETRY_INTERVAL = 4 * 60 * 60


def classify(output):
    status = re.search(r'^Apple authentication HTTP status: (429|503)\s*$', output, re.M)
    if status:
        code = status[1]
        return 'service', ('Apple authentication is unavailable or rate limited (HTTP ' + code + '). '
                           'The account has not been verified. Changing the password or reinstalling apps '
                           'does not resolve a signing-service outage.')
    for code in ('-80045', '-80046'):
        if re.search(r'(?<!\d)' + code + r'(?!\d)', output):
            return 'service', (f'Apple refused authentication ({code}). This can affect the signing service '
                               'or account; the code alone does not prove the password is wrong. '
                               'No app reinstall can repair this authentication failure.')
    if '-22411' in output:
        return 'account', ('Apple refused this Apple ID sign-in (-22411). Complete any verification Apple requests '
                           'and try again. This error can also indicate a signing-service compatibility problem; '
                           'it does not by itself mean the account has never been used on an Apple device.')
    if '-20101' in output:
        return 'account', 'Apple rejected the Apple ID or password (-20101). Check the saved account in Settings.'
    if (re.search(r'two.?factor code|verification code', output, re.I)
            and not re.search(r'Got token for|Fetching team|Account authentication succeeded\.', output)):
        return 'verification', 'Apple is asking for a 2FA code. Verify the account in Settings.'
    return '', ''


def read(work):
    try:
        state = json.loads((Path(work) / 'authentication-state.json').read_text())
        if (not isinstance(state, dict) or state.get('kind') not in ('service', 'account', 'verification')
                or not isinstance(state.get('message'), str)
                or any(type(state.get(k)) is not int or state[k] < 0
                       for k in ('failures', 'failed_at', 'retry_at'))):
            return {}
        return state
    except (FileNotFoundError, ValueError, UnicodeError):
        return {}


def retry_at(work):
    state = read(work)
    if state:
        return state['retry_at']
    # Preserve pauses written by earlier images on upgrade.
    try:
        value = (Path(work) / '.auth-retry-after').read_text().strip()
        return int(value) if value.isdecimal() and len(value) <= 10 else 0
    except FileNotFoundError:
        return 0


def failed(work, output):
    kind, message = classify(output)
    if not kind:
        return {}
    work = Path(work)
    previous = read(work)
    failures = min(previous.get('failures', 0) + 1, 4)
    now = int(time.time())
    state = {'kind': kind, 'message': message, 'failures': failures, 'failed_at': now,
             'retry_at': now + min(RETRY_INTERVAL * 2 ** (failures - 1), MAX_RETRY_INTERVAL)}
    work.mkdir(parents=True, exist_ok=True)
    path = work / 'authentication-state.json'
    tmp = path.with_suffix('.tmp')
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(state, stream)
    os.replace(tmp, path)
    # Kept for safe rollback to images that only understand the old pause file.
    (work / '.auth-retry-after').write_text(str(state['retry_at']))
    return state


def clear(work):
    for name in ('authentication-state.json', '.auth-retry-after'):
        (Path(work) / name).unlink(missing_ok=True)


def main():
    from . import accounts
    action, account_id, *args = sys.argv[1:]
    work = accounts.runtime_folder(account_id)
    if action == 'retry-at':
        print(retry_at(work))
    elif action == 'clear':
        clear(work)
        accounts.set_verification(account_id, 'verified')
    elif action == 'failure':
        output = Path(args[0]).read_text(errors='replace')
        state = failed(work, output)
        if state:
            accounts.set_verification(account_id, 'failed')
        elif any(line in ('Account authentication succeeded.', 'Fetching team...',
                          'Fetching renewal profiles...') for line in output.splitlines()):
            # A token alone is insufficient: Authenticate still has to fetch the account.
            clear(work)
            accounts.set_verification(account_id, 'verified')
        for name, value in {'AUTH_HINT': state.get('message', ''),
                            'AUTH_RETRY_AT': state.get('retry_at', 0)}.items():
            print(f'{name}={shlex.quote(str(value))}')
    else:
        raise ValueError('invalid authentication operation')


if __name__ == '__main__':
    main()
