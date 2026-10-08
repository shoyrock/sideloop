<div align="center">
  <a href="https://github.com/filippofinke/sideloop">
    <img width="140px" src=".github/logo.png" alt="Sideloop" />
  </a>
  <h3 align="center">Sideloop</h3>
</div>

> Keep sideloaded IPAs signed with a free Apple ID, re-installed over Wi-Fi before the 7-day signature expires.

A small self-hosted service with a web UI for any Linux machine (amd64 or arm64) or a Mac. It re-signs your apps with [AltServer-Linux](https://github.com/jaakkopalvaila/AltServer-Linux) and installs them in place, so app data is kept. You don't need AltStore or SideStore on the device.

## Features

- [x] Multiple apps on multiple iPhones and iPads
- [x] Multiple saved Apple accounts, with a signer selected per app/device (fork feature)
- [x] Verify saved Apple credentials, with a code prompt only when Apple requests MFA
- [x] Automatic re-signing when a device comes online, before the signature expires
- [x] Web UI for pairing, uploading IPAs, 2FA codes and live progress
- [x] Checks each IPA for FairPlay encryption, tweaks and app extensions
- [x] Self-hosted Apple sign-in via [anisette-v3-server](https://github.com/Dadoum/anisette-v3-server)
- [x] Python standard library only, one Docker image for amd64 and arm64

This checkout packages Sideloop and Anisette in **one container**. It adds
account selection, account verification and readable dropdowns in dark mode.
A small AltServer patch adds authentication-only verification using the existing
Apple sign-in implementation. Signing and Anisette run in UTC, and failed jobs
report authentication errors without waiting at AltServer's error pause.
Supervisor manages both services, and Anisette keeps its original service
account. All persistent data, including Anisette, lives under `./data`.

See [multiple accounts and upstream updates](docs/multiple-accounts.md) for
usage, storage compatibility and local testing. See [account verification](docs/account-verification.md)
for the conditional MFA flow and its testing limits. These features are included
in the published `latest` image.

## Demo

https://github.com/user-attachments/assets/8c6b799d-b9e7-4a15-898d-d96a2af8e876

A two-minute narrated walkthrough: setup, adding devices and apps, the first install with a 2FA code, and automatic re-signing.

## Screenshots

| Login | Apps | Signing | Settings | Activity |
| :---: | :---: | :---: | :---: | :---: |
| <img src=".github/screenshots/login.png" width="160" /> | <img src=".github/screenshots/apps.png" width="160" /> | <img src=".github/screenshots/signing.png" width="160" /> | <img src=".github/screenshots/settings.png" width="160" /> | <img src=".github/screenshots/activity.png" width="160" /> |

## Quick Start

### Pull the published amd64 image

For an Intel/AMD 64-bit Linux server, use
`ghcr.io/shoyrock/sideloop:latest`. This includes the Anisette helper
in the same container. See [the Unraid template and installation instructions](templates/README.md)
for Unraid, or clone this fork and run:

```bash
git clone https://github.com/shoyrock/sideloop.git
cd sideloop
TZ=America/New_York docker compose -f docker-compose.registry.yml up -d
```

Open `http://<server-ip>:8743`. The Unraid template and registry Compose file
set `UI_PORT=8743` to avoid the commonly used 8080 port. Keep host networking
for device discovery. You can choose another available port with `UI_PORT`;
on Unraid, update the advanced WebUI URL to match it.

The published image is built and tested locally. `latest` moves when a new image
is published; existing containers must pull the update and be recreated. On
Unraid, use **Check for Updates** and update Sideloop. With Compose, run:

```bash
docker compose -f docker-compose.registry.yml pull
docker compose -f docker-compose.registry.yml up -d
```

Only **linux/amd64** is published here. The `account-verification-amd64` tag retains
the current verification build for testing. Live Apple sign-in and installation
still require testing; adding the verification flow is not proof that Apple's
existing `-22411` rejection is resolved.
Source builds for other architectures are described below.

Prerequisites

- Docker with Compose
- A throwaway Apple ID

Run on Linux

From this consolidated checkout (for the exported image, use the server
instructions below):

```bash
cp .env.example .env
docker compose up -d --build
```

The first build compiles AltServer, which takes a few minutes. On a small board like a Raspberry Pi 3 it is much faster to build on another arm64 machine and copy the image over:

```bash
docker build --platform linux/arm64 -t sideloop:all-in-one .
docker save sideloop:all-in-one | gzip | ssh pi@<host> 'gunzip | docker load'
ssh pi@<host> 'cd sideloop && docker compose up -d --no-build'
```

Open `http://<host>:8080` and set a password. Then pair a device over USB, add an IPA and enter your Apple ID.

### Run the exported image on a Linux server

Copy `sideloop-all-in-one-amd64.tar.gz` and `docker-compose.server.yml` from
the `artifacts` directory to a folder on your Intel/AMD 64-bit server. Then run:

```bash
docker load -i sideloop-all-in-one-amd64.tar.gz
TZ=America/New_York docker compose -f docker-compose.server.yml up -d
docker compose -f docker-compose.server.yml ps
```

The Compose file creates one container named `sideloop`. Open
`http://<server-ip>:8080`. Pair over USB once, then use the same LAN for Wi-Fi
refreshes. The first start downloads Apple's Anisette libraries and initializes
its identity; the health check allows five minutes for this initialization.
Internet access is still needed for Apple sign-in and signing.

To run without Compose:

```bash
mkdir -p data/lockdown
docker run -d --name sideloop --restart unless-stopped \
  --stop-timeout 45 --network host --privileged \
  -e TZ=America/New_York \
  -v "$PWD/data:/data" \
  -v "$PWD/data/lockdown:/var/lib/lockdown" \
  -v /run/udev:/run/udev:ro \
  -v /dev/bus/usb:/dev/bus/usb \
  sideloop:all-in-one
```

Back up `data` to preserve apps, configuration, pairing records, signing
certificates, and Anisette identity. Anisette listens inside this container on
`127.0.0.1:6969`; no separate helper container is needed. The health check checks
the UI, Anisette, and (in Linux builtin mode) the device connection service.
View logs with `docker logs sideloop`.

### Migrate an existing two-container installation

Stop the old deployment first. Keep the existing `data` directory. Before
starting the new image, copy the old Anisette volume's contents into
`data/anisette` so its identity and downloaded libraries are preserved. The
default old volume name was `sideloop_anisette_data`; confirm yours with
`docker volume ls`. For that default name, run from the installation directory:

```bash
mkdir -p data/anisette
docker run --rm --entrypoint /bin/sh \
  -v sideloop_anisette_data:/old:ro \
  -v "$PWD/data/anisette:/new" \
  sideloop:all-in-one -c 'cp -a /old/. /new/'
docker compose -f docker-compose.server.yml up -d
```

Keep the old volume until the new deployment is verified. Without migration,
Anisette initializes a fresh identity on first start.

Run on macOS

Docker on macOS can't see USB or Wi-Fi devices, so bridge the system usbmuxd first:

```bash
socat TCP-LISTEN:27015,bind=127.0.0.1,reuseaddr,fork UNIX-CONNECT:/var/run/usbmuxd &
docker compose -f docker-compose.yml -f docker-compose.mac.yml up -d
```

Pair the device in Finder and enable **Show this iPhone when on Wi-Fi**.

## Notes

- Use the Apple ID's **regular password**. App-specific passwords don't work.
- A **2FA code** is requested only when Apple requires verification. **Sign In and Save Account** verifies sign-in before saving new credentials. Failed attempts preserve existing accounts. The existing trusted-device code flow is supported; SMS delivery/fallback is not added.
- The device must be **unlocked and on the same Wi-Fi** while a re-sign runs.
- A free account allows 3 apps per device and 10 App IDs per week. Each app extension needs its own App ID.
- Trust the developer once in **Settings > General > VPN & Device Management**. Refreshes keep it trusted.
- If Apple sign-in stops working, update `ALTSERVER_TAG` in the `Dockerfile`. AltServer is built from that tag with the patches in `altserver/`.

Data is stored in `./data`.

## Author

👤 **Filippo Finke**

- Website: [https://filippofinke.ch](https://filippofinke.ch)
- Twitter: [@filippofinke](https://twitter.com/filippofinke)
- GitHub: [@filippofinke](https://github.com/filippofinke)
- LinkedIn: [@filippofinke](https://linkedin.com/in/filippofinke)

## Show your support

Give a ⭐️ if this project helped you!

<a href="https://www.buymeacoffee.com/filippofinke">
  <img src="https://github.com/filippofinke/filippofinke/raw/main/images/buymeacoffe.png" alt="Buy Me A McFlurry">
</a>

## 📝 License

Copyright © 2026 [Filippo Finke](https://github.com/filippofinke).<br />
This project is [MIT](./LICENSE) licensed. Icons from [Ionicons](https://ionic.io/ionicons) (MIT).

***

_Not affiliated with Apple. Use a throwaway Apple ID._
