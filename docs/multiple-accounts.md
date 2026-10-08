# Multiple signing accounts

This fork can save several Apple accounts, select a default for new apps on each
device, and select a signing account for each app/device target. Automatic renewal
uses that target's saved account. Re-sign Early and account dropdowns also use
readable foreground and background colours in light and dark modes.

Multiple accounts do not bypass iOS's limit of three active apps installed with
free provisioning on one device. Each account has its own App ID allowance;
extensions also consume App IDs.

## Using the feature

1. In Settings, open Apple Accounts. Your existing credentials are the default
   account. Choose Add another account to save an additional Apple ID and its
   regular password. Leaving a saved account's password blank retains it.
2. On a device, choose Account for new apps. Existing apps retain their previous
   account; newly uploaded or newly assigned apps use the device's new default.
3. On an app's device row, choose its Signing account. Each device can use a
   different account for the same IPA. Refresh and automatic renewal use this
   selection. Account changes are blocked while a signing job is running.

Changing a target's signing account does not move its app data. AltServer derives
the installed bundle identifier from the signing team, so signing with another
team can install a separate copy. Use the original account to renew an existing
installation and retain its data. Apple may request a 2FA code for each account,
and the device may require trusting each developer.

The email of an existing saved account is retained with its signing cache. To
use another Apple ID, add another account instead of replacing that email.

## Compatibility with the existing installation

The default account retains `config.env`, `/data/.altserver`,
`/data/AltServerData`, and the original app/device signature state paths. Existing
app and device metadata formats are unchanged. There is no migration on startup.

Additional data lives in:

| Data | Location under `/data` |
| --- | --- |
| Account credentials | `accounts/<account-id>/credentials.env` |
| Account working directory and certificate cache | `accounts/<account-id>/runtime/` |
| Account HOME | `accounts/<account-id>/runtime/.altserver/` |
| Device defaults and app/device selections | `signing-accounts.json` |
| Additional account's signature state | `apps/<app>/state/<device>/accounts/<account-id>/` |

Credentials stay server-side; API state contains account emails and password
presence, and job output masks all saved account passwords. Removing an app or
device clears its assignments without deleting saved accounts.

Back up the full appdata directory before testing an update. The old image does
not understand multiple-account assignments and would use its default account
for all apps. Restore the pre-update backup when rolling back; retained legacy
paths alone do not make that rollback safe for apps signed with other accounts.

## Published image and local builds

Use `ghcr.io/shoyrock/sideloop:latest` for the current published image. The older
`all-in-one-amd64` release predates this feature. Build locally from this checkout:

```bash
docker build --platform linux/amd64 -f tools/Dockerfile.candidate \
  -t sideloop:multi-account-candidate .
```

This layers the application changes onto the pinned, previously tested combined
image and rebuilds AltServer with the small authentication-only patch described
in [account verification](account-verification.md). The root Dockerfile also
incorporates the changes in a complete source build. No GitHub runner is used.

The exported `artifacts/sideloop-multi-account-candidate-amd64.tar.gz` can be copied
to Unraid and loaded there:

```bash
docker load -i sideloop-multi-account-candidate-amd64.tar.gz
```

After backing up appdata and stopping Sideloop, set its Unraid Repository field
to `sideloop:multi-account-candidate`. Retain the existing appdata, pairing, USB,
host network, privileged mode, and `UI_PORT=8743` settings. The local candidate
tag must already be loaded; it is not a published registry tag. Test the existing
account's renewal first, then test the additional account on a separate app.

## Keeping upstream updates usable

The extension is concentrated in `sideloop/accounts.py`. Small hooks connect it
to the existing server, store, job masking, watcher, refresh script, and UI.
Upstream signing binaries and original metadata formats are retained.

Keep `origin` pointing to `filippofinke/sideloop` and `fork` pointing to
`shoyrock/sideloop`. Commit the extension on a separate feature branch. To bring
upstream changes into that branch:

```bash
git fetch origin
git merge origin/main
```

Review conflicts in the hook locations; updates to the signing flow or state
format still need compatibility review. The extension reduces divergence but
cannot guarantee conflict-free merges. Rebuild and run the checks below before
publishing an updated image. If upstream changes signing binaries or container
dependencies, rebuild with the root Dockerfile instead of the pinned candidate
Dockerfile.

## Validation

```bash
docker run --rm --entrypoint python3 -e PYTHONPATH=/opt \
  -v "$PWD/tests:/tests:ro" sideloop:multi-account-candidate \
  -m unittest discover -s /tests -p test_accounts.py -v
python tests/smoke_container.py sideloop:multi-account-candidate
```

The eleven regression tests cover legacy state/cache preservation, independent
account state, assignment changes, renewal scheduling, shell quoting, credential
masking, busy-job guards, removal, and the actual refresh script using fake signing
and device tools. Container checks cover both services, process recovery,
graceful shutdown, and persistent accounts and selections after recreation.

Browser checks use disposable accounts and a simulated app/device, with automatic
signing disabled. They cover account selectors, persistence, and dropdown colours
in both themes. These checks do not establish successful Apple sign-in or signing
on a physical iPhone; that requires a live-device test with real accounts.
