# Persistent signing identity

AltStore stores account credentials and certificate material, and authenticates
again during its signing workflow. It does not get a permanent Apple session that
bypasses future authentication changes. SideStore's remote Anisette v3 mode keeps
a provisioned virtual-device identifier and ADI blob locally, then asks compatible
providers to generate fresh one-time data for that identity.

Sideloop now supports that v3 lifecycle without changing AltSign's account or
profile APIs. A loopback service translates v3 into AltServer's existing JSON
interface. All processes still run in one container.

## Enable on Unraid

Update to an image containing this feature, then add a container variable:

```text
ANISETTE_V3_SERVERS=https://mac-ani.jkcoxson.com,https://new.ani.sidestore.io
```

These Mac-backed providers are also used by iloader. When this variable is set,
the container routes signing through its local v3 client on 127.0.0.1:6969;
the old ANISETTE_SERVER value is ignored. Verify each saved Apple account once
in Settings and complete MFA if requested. This is a new private identity,
separate from the provider's old shared v1 endpoint, so Apple can ask for a code.

With the variable absent or empty, the old local Anisette backend and any
explicit ANISETTE_SERVER override retain their existing behavior. Existing
installations are not silently migrated merely by pulling a new image.

## What persists

Back up the complete appdata directory. The identity is saved at
`/data/anisette-v3/identity.json` with owner-only permissions. It contains the
identifier, provisioned ADI blob, advertised client metadata, and last successful
provider. It contains no Apple password, MFA code, or developer authentication
token. Treat the identity file as private authentication material nonetheless.

Restarting or recreating the container reuses this file. Provider requests obtain
fresh one-time values rather than caching and replaying them. A provider outage
does not erase or rotate the identity. A backup receives the saved blob only
when its client metadata matches; it must also successfully use that blob before
it becomes preferred. An incompatible provider is skipped. Identity rejection
does not silently provision another device and trigger repeated MFA challenges.
Damaged state requires restoring a backup, rather than an automatic identity reset.

Health probes check the local process without contacting providers or generating
one-time passwords. Provider failures affect signing, but do not make Docker
restart an otherwise healthy local service. Provider response bodies and identity
values are not written to the container log. Apple credentials remain in the
existing account handling and are sent only through AltSign to Apple.

## Validation and limits

`tests/test_anisette.py` checks restart persistence, compatible failover, outage
recovery, incompatible providers, rejected identities, damaged files, provisioning
URL validation, and health checks. `tests/smoke_anisette_v3.py` exercises the actual
container's v3 startup and recreation offline. The Forgejo build runs both the old
container checks and this new mode before exporting the image.

A real protocol test provisioned an identity with the primary provider, reused it
after reconstructing the client from disk, and successfully fetched headers from
the backup with the primary deliberately unavailable. This test used no Apple
account credentials. Live account/MFA and phone-renewal validation is separate.

This closes a persistence and provider-availability gap. It cannot prevent Apple
from changing its private protocols, restore revoked certificates, or make
incompatible providers accept an identity. Provider lists are explicit, not
downloaded and trusted automatically. Native upstream updates still need review,
compilation and regression checks.

## Upstream references inspected

- [AltStore authentication, commit 56854e6](https://github.com/altstoreio/AltStore/blob/56854e66fef2eac32dad88dcbad1dc131d430e60/AltStore/Operations/AuthenticationOperation.swift)
- [SideStore v3 persistence and failover, commit d97ec13](https://github.com/SideStore/SideStore/blob/d97ec133719d79916675bdaf722b82a8d091d545/SideStore/Core/Anisette/AnisetteProvider.swift)
- [iloader v2.4.0 Mac provider change](https://github.com/nab138/iloader/releases/tag/v2.4.0)
- [Omnisette v3 protocol](https://github.com/SideStore/omnisette-server)
