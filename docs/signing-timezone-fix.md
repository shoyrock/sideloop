# Apple sign-in timestamp and error reporting fix

The original combined image's Activity log showed repeated `-22411` Apple
authentication failures for YouTube and YouTube Music. The device and internal
Anisette/mux services were available. The last manual attempt was terminated
while still in the sign-in stage; no signing or transfer progress was recorded.

## Reproduced defects

The bundled AltServer parses Anisette's UTC timestamp using `mktime`, which treats
it as local time. With `TZ=America/New_York`, a synthetic timestamp of
`2026-10-08T12:00:00Z` becomes `2026-10-08T17:00:00Z` in its Apple authentication
request. In UTC it remains `2026-10-08T12:00:00Z`. This was reproduced using the
actual binary from the published image, fake loopback-only Anisette and Apple
servers, synthetic credentials, and a container with external networking disabled.

AltServer also catches authentication exceptions and exits 0. Sideloop then
reports that the app is missing, with a locked-device/Wi-Fi hint. This obscures the
earlier Apple rejection. Interactive signing output previously was not persisted
in the Activity history, making manual attempts harder to diagnose.

The error code alone does not prove a unique account-side cause. The timestamp
defect is a reproducible local cause worth correcting first. If `-22411` continues
with a correct timestamp, account/Anisette authentication needs further diagnosis.

## Patch

Only `scripts/refresh.sh` changes at runtime:

- Run AltServer with `TZ=UTC` in both interactive and automatic modes. The parent
  process retains its configured timezone, so log dates remain local.
- Capture interactive output while retaining its terminal input, including 2FA.
- Treat an explicit AltServer Error/Exception as failure even when its exit code
  is 0. Report `-22411` as an Apple sign-in rejection instead of a Wi-Fi problem.

No account feature, binary upgrade, app metadata migration, credential change,
pairing reset, or Anisette identity reset is included.

## Trying the correction on the existing Unraid image

Confirm the current timezone in the Unraid terminal:

```bash
docker exec Sideloop printenv TZ
docker exec Sideloop date -u
```

For a test without replacing the image, edit Sideloop in Unraid, set its Timezone
variable (`TZ`) to `UTC`, and click Apply. Retry a single install from the UI with
the phone unlocked. Enter a fresh 2FA code when requested. This changes the log
timezone as well; the patched image below scopes UTC just to signing.

Alternatively, retry only YouTube Music in the Unraid terminal with the existing
account and data:

```bash
docker exec -it -e TZ=UTC Sideloop /usr/local/bin/refresh.sh \
  --app com.google.ios.youtubemusic \
  --device <your-device-udid> --force
```

The same process lock prevents simultaneous signing. Terminal input allows the
2FA prompt to be answered. Do not share raw verbose AltServer logs containing
authentication data. This command still uses the old script's misleading final
hint if authentication fails; inspect the preceding Apple error.

## Build and validation

Build locally from the single-account release checkout:

```bash
docker build --platform linux/amd64 -f tools/Dockerfile.signing-fix \
  -t sideloop:signing-fix-amd64 .
docker run --rm --network none --entrypoint python3 \
  -v "$PWD/tests:/tests:ro" sideloop:signing-fix-amd64 \
  -m unittest discover -s /tests -p test_signing_fix.py -v
python tests/smoke_container.py sideloop:signing-fix-amd64
```

To reproduce the actual binary's timestamp behaviour without contacting Apple:

```bash
docker run --rm --network none --add-host gsa.apple.com:127.0.0.1 \
  --entrypoint python3 -v "$PWD/tests:/tests:ro" \
  sideloop:signing-fix-amd64 /tests/reproduce_signing_clock.py
```

Two regression tests verify UTC signing, preserved local log timestamps, accurate
failure state/history, and interactive 2FA input. Container checks verify helper
services, process recovery, shutdown, and persistent data. Physical-device Apple
sign-in and installation require a live retry; they are not proven by fake services.

The local exported image is `sideloop-signing-fix-amd64.tar.gz`. To test on Unraid,
copy it to the server and run `docker load -i sideloop-signing-fix-amd64.tar.gz`.
Then set the existing container's Repository to `sideloop:signing-fix-amd64`, keeping
its appdata, pairing mounts, host network, privileged setting, and UI port. This
local tag must be loaded first; it is not a registry-published tag.
