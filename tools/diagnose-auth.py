"""Print a shareable authentication report; never print raw signer output.

Run inside Sideloop. --verify makes one Apple sign-in attempt using the saved
default account, without installing an app or saving account changes.
"""
import argparse
import datetime as dt
import email.utils
import json
import os
import re
import subprocess
import tempfile
import urllib.request


def summarize(output):
    # Extract only fixed messages, HTTP status integers, and numeric error codes.
    # Native output also contains passwords/session material; do not return it.
    auth = [int(x) for x in re.findall(r'Received auth response status code: (\d{3})\b', output)]
    mfa = 'Requires two factor...' in output or 'Enter two factor code' in output
    report = {
        'gsa_http_statuses': auth,
        'mfa_requested': mfa,
        'mfa_http_statuses': [int(x) for x in re.findall(r'Received 2FA response status code: (\d{3})\b', output)],
        'sign_in_verified': 'Account authentication succeeded.' in output.splitlines(),
        'developer_token_obtained': 'Got token for com.apple.gs.xcode.auth!' in output,
    }
    errors = re.findall(r'^Authentication failed:.*?\((-?\d+)\)', output, re.M)
    report['apple_error_codes'] = sorted(set(map(int, errors)))
    if not mfa and 1 <= len(auth) <= 3:
        report['last_gsa_operation'] = ['init', 'complete', 'apptokens'][len(auth) - 1]
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--verify', action='store_true')
    args = parser.parse_args()
    from sideloop import accounts, config

    report = {'container_utc': dt.datetime.now(dt.timezone.utc).isoformat()}
    try:
        with urllib.request.urlopen(config.ANISETTE, timeout=15) as response:
            headers = json.load(response)
        required = ('X-Apple-I-MD', 'X-Apple-I-MD-M', 'X-Apple-I-MD-LU',
                    'X-Apple-I-MD-RINFO', 'X-Mme-Device-Id', 'X-MMe-Client-Info')
        report['anisette_fields_present'] = {k: bool(headers.get(k)) for k in required}
        timestamp = dt.datetime.fromisoformat(headers['X-Apple-I-Client-Time'].replace('Z', '+00:00'))
        report['anisette_age_seconds'] = round((dt.datetime.now(dt.timezone.utc) - timestamp).total_seconds())
        report['anisette_timezone_is_utc'] = headers.get('X-Apple-I-TimeZone') == 'UTC'
    except Exception as error:
        report['anisette_error_type'] = type(error).__name__
    try:
        with urllib.request.urlopen('https://gsa.apple.com/', timeout=15) as response:
            apple_date = response.headers.get('Date')
        if apple_date:
            report['apple_clock_difference_seconds'] = round((dt.datetime.now(dt.timezone.utc) - email.utils.parsedate_to_datetime(apple_date)).total_seconds())
    except urllib.error.HTTPError as error:
        # The root may return an HTTP error but its Date header still checks time.
        if error.headers.get('Date'):
            report['apple_clock_difference_seconds'] = round((dt.datetime.now(dt.timezone.utc) - email.utils.parsedate_to_datetime(error.headers['Date'])).total_seconds())
        report['apple_root_http_status'] = error.code
    except Exception as error:
        report['apple_connection_error_type'] = type(error).__name__

    if args.verify:
        credentials = accounts.credentials('default')
        if not all(credentials.values()):
            report['verification'] = 'No saved default credentials'
        else:
            with tempfile.TemporaryDirectory(prefix='sideloop-diagnostic-') as work:
                env = {**os.environ, 'TZ': 'UTC', 'HOME': work,
                       'ALTSERVER_ANISETTE_SERVER': config.ANISETTE,
                       'ALTSERVER_APPLE_ID': credentials['APPLE_ID'],
                       'ALTSERVER_APPLE_PASSWORD': credentials['APPLE_PASSWORD']}
                result = subprocess.run(['timeout', '--foreground', '60', 'AltServer', '--verify-account'],
                                        env=env, cwd=work, stdin=subprocess.DEVNULL,
                                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                report['authentication'] = summarize(result.stdout.decode('utf-8', 'replace'))
                report['authentication']['exit_code'] = result.returncode
                report['authentication']['note'] = 'MFA input is intentionally not submitted by this diagnostic.'
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
