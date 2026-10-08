# Apple account verification and conditional MFA

`Save and Verify Account` saves credentials and immediately performs Apple sign-in.
`Verify Saved Account` retries a saved account without re-entering its password.
The six-digit verification field appears only when Apple asks for verification;
accounts without MFA do not see it. An account is marked verified only after the
signing engine confirms authentication, including fetching the Apple account.

This uses AltServer's existing authentication implementation through a small
`--verify-account` entrypoint patch. It doesn't sign an IPA, register an App ID,
create or revoke a certificate, or require a connected iPhone. Subsequent signing
still authenticates normally; the displayed status describes the last verification
attempt and is not a permanent Apple session or a guarantee of installation.

The existing engine requests codes from trusted Apple devices. This change does
not add SMS delivery or bypass Apple's authentication requirements. If Apple
rejects sign-in before issuing an MFA challenge, the code field does not appear;
the failed status and Details show the error. The live server's existing `-22411`
rejection is not proven resolved by this UI/entrypoint change.

One-time codes are validated as six digits, sent to the waiting process, and
redacted from job output. They are not stored in account files or verification
status. The verification job exposes only selected status/error lines rather
than raw Apple authentication responses. Credentials changing invalidates the
account's prior verified status. Cancellation, errors, timeout, and interrupted
checks after restart cannot produce a verified status.

The account state and UI changes are in separate modules and the native change
is an `altserver/*.patch` applied to the pinned upstream tag. Existing upstream
signing and installation behavior remains available. Reapply/check the patch
when upgrading the signing engine; don't copy an old binary into an image with
the new verification UI.

## Build and tests

Build locally for the user's amd64 Unraid server (no GitHub runners):

```bash
docker build --platform linux/amd64 -f tools/Dockerfile.candidate \
  -t sideloop:account-verification-amd64 .
docker run --rm --network none --entrypoint python3 \
  -v "$PWD/tests:/tests:ro" sideloop:account-verification-amd64 \
  -m unittest discover -s /tests -p 'test_*.py' -v
docker run --rm --network none --add-host gsa.apple.com:127.0.0.1 \
  --entrypoint python3 -v "$PWD/tests:/tests:ro" \
  sideloop:account-verification-amd64 /tests/check_native_verification.py
python tests/smoke_container.py sideloop:account-verification-amd64
```

Twenty regression tests cover account isolation and PTY authentication with and
without MFA, wrong codes, rejection, silent exit zero, cancellation, timeout,
credential changes, and restart. The compiled binary test reaches a loopback-only
fake Apple endpoint, returns nonzero on rejection, and creates no signing data.
Browser tests use only synthetic accounts with `tests/fake_auth_preview.py`.
These checks validate the implementation; they don't claim live Apple sign-in.

## Test the exported image on Unraid

Copy `sideloop-account-verification-amd64.tar.gz` to the server, then load it:

```bash
docker load -i sideloop-account-verification-amd64.tar.gz
```

Edit the existing container's Repository to `sideloop:account-verification-amd64`.
Keep the existing appdata and pairing mounts, host network, USB access, `MUX`,
Anisette URL, and `UI_PORT=8743`. This is a local image tag, which must be loaded
first. No new port or credential/MFA environment variable is needed. Verification
codes are entered in the browser only when Apple requests them.

The new image includes the previous clock/error-handling corrections: signing and
the Anisette helper run in UTC; Sideloop can retain its configured log timezone.
Failed installation jobs acknowledge AltServer's error pause and report Apple
authentication errors instead of a locked-device/Wi-Fi hint.
