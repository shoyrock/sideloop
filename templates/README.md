# Unraid

This template runs the tested **amd64** all-in-one image from
`ghcr.io/shoyrock/sideloop:all-in-one-amd64`.

To install it manually, run this from the Unraid terminal:

```bash
mkdir -p /boot/config/plugins/dockerMan/templates-user
curl -fL https://raw.githubusercontent.com/shoyrock/sideloop/main/templates/sideloop.xml \
  -o /boot/config/plugins/dockerMan/templates-user/my-sideloop.xml
```

In **Docker > Add Container**, select **Sideloop** from your user templates and
click **Apply**. Open `http://<unraid-ip>:8080`, set the UI password and pair
your unlocked device over USB. Add your IPA and throwaway Apple ID in the UI.

Keep **Host** networking and **Privileged** enabled for the existing USB/Wi-Fi
device workflow. The template does not need a second Anisette container.
Internet access is needed for Apple's services and initial Anisette library
downloads. Allow up to five minutes for the first startup.

The default persistent directory is `/mnt/user/appdata/sideloop`. If you change
it, change the pairing-record path to the corresponding `lockdown` subdirectory.
Back up the whole appdata directory. Stop an existing Sideloop or Anisette
deployment before starting this one to avoid host port conflicts. The UI uses
8080; the local helper services use 6969 and 27015.

The image passed startup, service recovery and data persistence checks. Physical
iPhone pairing and Apple signing still need testing on your server.
