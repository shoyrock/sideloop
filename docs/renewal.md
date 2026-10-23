# Renewing and updating apps

**Renew** extends an installed app's provisioning profiles without copying its IPA.
The Apple sign-in and profile download use AltSign, the same Apple API implementation
used for installation. Profiles are installed through the phone's misagent service,
following AltStore's profile-only renewal approach. No companion app is required.

Before changing profiles, Sideloop checks the installed bundle ID, recorded signing
certificate, Apple team, device authorization, entitlements, and all reported app
extensions. Every replacement is validated before any is installed. Success is
reported only after every new profile is read back from the phone. The expiry shown
is the earliest expiry across the app and its renewed extensions. Old profiles stay
in place during transfer and are cleaned up only after successful verification.

Uploading a new IPA does not update installed apps. **Install / Update** is the
separate action that signs and transfers the saved IPA. Its confirmation explains
that this can replace a newer installed version with an older saved version. The
Apps page shows the last observed installed version alongside the saved IPA version.
A library IPA requiring a newer iOS does not block renewal of an older installed app.

If profile renewal requires a full re-sign, automatic repair is allowed only when
a successful installation receipt exists, the phone still reports that bundle,
version and build, and the saved IPA's SHA-256 and extension setting match the
receipt. A changed upload, changed installed version, missing receipt, or uncertain
device state requires an explicit Install / Update. Network/authentication errors
never authorize reinstalling an app. Existing installations with a recorded matching
certificate can use profile-only renewal immediately; older installs without enough
signing information need one explicit installation to establish it.

Settings, app assignments, account-specific signing caches and existing data paths
remain compatible. The existing `/api/refresh` endpoint now renews by default.
Installation requires one app and device plus `operation: "install"` and
`confirm_replace: true`. The command-line equivalent is
`refresh.sh --app APP --device UDID --force --install --confirm-replace`.
Automatic and `--force` renewals never mean "install the uploaded update".

Source reference: [AltStore's refresh/fallback decision](https://github.com/altstoreio/AltStore/blob/develop/AltStore/Managing%20Apps/AppManager.swift#L961-L990)
and [profile installation request](https://github.com/altstoreio/AltStore/blob/develop/AltStore/Operations/RefreshAppOperation.swift).

The Linux CLI has no complete profile-only entrypoint upstream, so this fork adds
a small `--refresh-profiles` adapter around the existing AltSign API. It does not
duplicate Apple authentication or signing cryptography. The remaining orchestration
and safety checks are in `sideloop/renewal.py`.
