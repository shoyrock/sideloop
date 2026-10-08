#!/usr/bin/env python3
"""Synthetic browser fixture only; never contacts Apple."""
import os
import sys

assert sys.argv[1:] == ['--verify-account']
email = os.environ['ALTSERVER_APPLE_ID']
if email.startswith('mfa@'):
    print('Enter two factor code', flush=True)
    if input() != '123456':
        print('Authentication failed: incorrect verification code (-21669).')
        sys.exit(1)
elif email.startswith('reject@'):
    print('Authentication failed: This action cannot be completed at this time (-22411).')
    sys.exit(1)
print('Account authentication succeeded.')
