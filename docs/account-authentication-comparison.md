# Account authentication comparison

Source reviewed on 2026-10-08. These findings concern each project's login flow;
they do not prove successful authentication against Apple with a particular account.

| Project | What happens before account persistence |
| --- | --- |
| [iloader](https://github.com/nab138/iloader/blob/80142ff82fc3dfa7312d77ea6151b4d20090151b/src-tauri/src/account.rs) | `login_new` awaits `login`, which authenticates with Apple and creates a developer session. Only then does it optionally write the password to the keyring and add the account to the saved list. MFA is handled through a callback during login. |
| [SideStore](https://github.com/SideStore/SideStore/blob/0dd743f75afc358b0ba4a002feb5f19474492371/SideStore/Core/Operations/StandaloneOperations/SignInOperation.swift) | The interactive sign-in loop awaits authentication, with callbacks for verification and account repair. Credentials and session tokens are stored after successful sign-in; team selection and account activation follow. |
| [AltStore Classic](https://github.com/altstoreio/AltStore/blob/56854e66fef2eac32dad88dcbad1dc131d430e60/AltStore/Operations/AuthenticationOperation.swift) | Authentication supplies a verification-code callback. The operation then fetches a team and certificate, registers the device, and saves account/team state. It is a fuller setup flow than a credentials-only check. |
| [Modern Impactor](https://github.com/claration/Impactor/blob/c7f8387121b37a896abb0fef34fd8a97b0c2b8a0/apps/plumeimpactor/src/screen/windows/login_window.rs) | The login window adds an account to the store on `LoginSuccess`, after Apple authentication and developer-session/team lookup. The [authentication state machine](https://github.com/claration/Impactor/blob/c7f8387121b37a896abb0fef34fd8a97b0c2b8a0/crates/plume_core/src/auth/account/login.rs) handles trusted-device codes, SMS codes and SMS fallback. |

The modern open-source Impactor above is distinct from the older Cydia Impactor.
The old product's historical app-specific-password instructions should not be
applied to Sideloop's current AltServer authentication engine.

## Sideloop change

The earlier Save and Verify Account action persisted credentials and then launched
a separate verification request. It exposed failures but could leave a rejected
new account in the list or overwrite a previously usable password.

The save API now launches one authentication job using candidate credentials held
in memory and a temporary working directory. Only a successful exit with the
signer's explicit authentication-success marker commits credentials and marks the
account verified. A cancelled, timed-out or rejected attempt does not commit them.
The browser waits for the job result before selecting the newly saved account.
This applies to both `/api/account/save` and the legacy `/api/appleid` route.

Authentication is independent of installing an IPA. MFA remains conditional on
Apple requesting a challenge. Existing saved accounts, assignments and signing
data are retained. Background signing is excluded while the login job is active.

## Limits and the observed failure

Sideloop reuses its existing AltServer implementation. It does not yet add the SMS
fallback, account-repair flow or session-token persistence present in newer engines.
A successful login check also cannot guarantee every later signing/install step,
which can separately fail for provisioning limits or device problems.

The live server returned Apple's `-22411` rejection during account-only verification
before any MFA prompt. Correcting persistence order does not resolve that rejection
or force Apple to issue an MFA challenge. Investigate the actual authentication
exchange and Anisette identity separately; don't reset pairing or signing data as
an assumed fix for a generic authentication error.
