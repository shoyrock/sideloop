"""Device boundary for legacy shell integration tests.

The actual renewal implementation has signed-profile tests in test_renewal.py.
This double keeps the older account/scheduler tests independent of a real phone.
"""
import datetime
import hashlib
import os
import plistlib
import subprocess
import sys
from pathlib import Path
from sideloop import accounts, config

operation, app, device, *args = sys.argv[1:]
if operation == 'can-reinstall': sys.exit(42)
if operation in ('guard', 'record', 'check'):
    sys.exit(0)
result = subprocess.run([os.environ['ALTSERVER_BIN'], '-u', device, str(config.APPS/app/'app.ipa')])
if result.returncode:
    sys.exit(result.returncode)
payload = plistlib.loads((config.DATA/'payload.plist').read_bytes())
state = accounts.state_folder(app,device)
state.mkdir(parents=True,exist_ok=True)
(state/'expiry').write_text(str(int(payload['ExpirationDate'].replace(tzinfo=datetime.timezone.utc).timestamp())))
(state/'certificate').write_text(hashlib.sha1(payload['DeveloperCertificates'][0]).hexdigest())
(state/'consecutive_failures').write_text('0')
print('Profile renewal succeeded. No app was copied.')
