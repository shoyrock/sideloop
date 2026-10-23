# Apple account verification and conditional MFA

`Sign In and Save Account` performs Apple sign-in before saving credentials.
New credentials remain pending in memory until authentication succeeds. A failed,
cancelled or timed-out attempt does not add a new account or overwrite an existing
account's credentials, signing cache or verification status. Existing accounts
remain available for compatibility; this does not require re-adding them.
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
the failed status and Details show the error.

## Apple error -22411

Apple returns `-22411` when it cannot complete authentication. It is not a
unique diagnosis of an account that has never been used on an Apple device:
an unsupported MFA response can also cause a later token request to fail with
this code. Complete any verification Apple requests and inspect the signing
service's compatibility before changing account or device settings.

## Apple error -80045

Since October 12, 2026, Apple returns `-80045` ("This action cannot be completed
at this time") when the client identity a sign-in reports doesn't match the
platform that produced its Anisette data. The bundled Anisette server produces
that data with Apple's Android library but reports a Mac. Sideloop's signing
engine therefore reports an Android device. With the Mac identity, Apple answered
`-80045` for every Apple ID; with the Android identity, a nonexistent Apple ID
receives the normal `-20101`. The error is not caused by the Apple ID. If it
appears, the image predates the fix. Apple can also now answer the password step
with a code already sent to the trusted devices; the code field then appears
without a second code being requested.

During a re-sign run, an account that Apple refuses (`-80045`, `-22411`, `-20101`
or a required code) is tried once. The run skips its other apps. Automatic
checks then wait 30 minutes, 1, 2, then 4 hours between runs while apps stay due.
A device coming back online or a change of signing account still checks at once.

`docker exec Sideloop python3 /usr/local/bin/diagnose-auth.py` reports Anisette
fields, timestamp age and the clock offset from Apple. Add `--verify` to make one
sign-in attempt with the saved default account. The report contains only status
codes and fixed messages, not credentials or tokens.

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

Twenty-six regression tests cover account isolation and PTY authentication with and
without MFA, wrong codes, rejection, silent exit zero, cancellation, timeout,
credential changes, and restart. The compiled binary test reaches a loopback-only
fake Apple endpoint, returns nonzero on rejection, and creates no signing data.
Browser tests use only synthetic accounts with `tests/fake_auth_preview.py`.
These checks validate the implementation; they don't claim live Apple sign-in.
Additional save-flow tests prove credentials are committed only after successful
authentication, including MFA, and that unsuccessful edits preserve the old account.

See [the authentication comparison](account-authentication-comparison.md) for the
iloader, SideStore, AltStore and Impactor source used to review the save flow.

## Pull the published image on Unraid

Set the existing container's Repository to `ghcr.io/shoyrock/sideloop:latest`
and click Apply. Keep the existing appdata, pairing and USB mounts, host network,
Anisette URL and `UI_PORT=8743`. Future published images can be installed through
Unraid's Check for Updates and container update action. No registry login is
needed to pull this public image. The `account-verification-amd64` tag also
identifies the initial verification build.

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
