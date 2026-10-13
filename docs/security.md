# Security

Sideloop is meant for a private network. It stores Apple account passwords so it can re-sign
unattended, and it runs with the device access that USB and Wi-Fi installs need. This page lists
what protects it and what remains your responsibility.

## Protections

**Imported IPAs are treated as untrusted.** IPAs from third-party sites can be crafted.

- Uploads are rejected if any archive member would land outside the app (absolute paths, `..`),
  if the archive has more than 300,000 files or unpacks to more than 16 GB, or if the bundle
  identifier isn't valid. The app's storage folder can't escape `apps/`.
- The signing engine's extractor (AltSign `UnzipArchive`) is patched to enforce the same
  containment (`altserver/hardening.patch`).
- Values read from the IPA (such as its minimum iOS version) are validated before use. A crafted
  `MinimumOSVersion` could previously run a command through a `sed` replacement in `refresh.sh`.

**Apple sign-in verifies TLS.** Upstream AltSign disabled certificate validation for
`gsa.apple.com`, whose certificate chains to Apple Root CA. The image now trusts that root,
checked against its published SHA-256 fingerprint
(`B0:B1:73:0E:…:01:F0:24`), and the patched signer validates the connection.

**Apple passwords stay out of the process list.** The signer receives the Apple ID and password
in its environment instead of as command-line arguments.

**Web UI:**

- Password checks run one at a time, with a one-second delay per failure. An address is locked
  out for 15 minutes after 10 wrong passwords.
- Sessions can be revoked: signing out invalidates the session on the server, not only in the
  browser. Sessions created before this update are no longer accepted; sign in again once.
- Changing requests need the app's own header and are refused when the browser marks them as
  coming from another site (`Sec-Fetch-Site`).
- The page's script is allowed by a hash-based Content Security Policy, so injected markup can't
  run scripts. The UI can't be framed, and responses carry `nosniff`/`no-referrer` headers.
- Request bodies are size-checked, including invalid `Content-Length` values, and stalled
  connections time out.
- Behind an HTTPS reverse proxy that sets `X-Forwarded-Proto: https`, the session cookie is
  marked `Secure`.

**Container:**

- Anisette's machine ID and one-time passwords are filtered out of the container log, which is
  often shared when asking for help.
- The supervisor control socket is restricted to root.
- Base images are pinned by digest, and the netmuxd download is checked against a recorded
  SHA-256.

## Remaining risks

- **Privileged container with host networking.** USB pairing and Wi-Fi discovery rely on it.
  Treat the host as trusting Sideloop with broad access, and prefer a dedicated machine or VM.
- **Plain HTTP.** Passwords, 2FA codes and the session cookie cross the network unencrypted.
  For access beyond a trusted LAN, put Sideloop behind an HTTPS reverse proxy (or VPN), and only
  allow the proxy to reach the UI port.
- **First setup.** Whoever first opens the UI chooses its password. Set it right after starting
  the container.
- **Stored Apple passwords.** They're saved in `/data` (mode `0600`) so renewals can run
  unattended. Protect the appdata folder and its backups, and use separate Apple IDs for
  sideloading.
- **Upstream binaries.** AltServer, Anisette and Apple's libraries are third-party native code.
  Sideloop can't verify that an installed app itself is trustworthy.

## Tests

`tests/test_security.py` covers the archive checks, bundle-identifier validation, session
revocation, login throttling, request checks, headers and the CSP hash. `tests/test_accounts.py`
checks that IPA metadata can't inject commands into `refresh.sh` and that the signer gets
credentials from its environment. `tests/smoke_container.py` checks that Anisette data stays out
of the container log.
