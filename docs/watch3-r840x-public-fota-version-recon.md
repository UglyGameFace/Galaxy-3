# SM-R840X public Samsung FOTA version metadata: a bounded, no-watch check

**Issue:** [#47](https://github.com/UglyGameFace/Galaxy-3/issues/47).
**Owner watch:** SM-R840X, R08, installed `R840XXXU1AUA2`,
working normally on Tizen after its previously verified
**four-byte only** Wireless Download `ODIN` / `LOKE` exchange.

## Question

Does Samsung's *public firmware version listing* expose any
`SM-R840X` release token? Do **not** confuse this with the
bootloader's unsigned image acceptance or a downloadable **full
signed R840X stock recovery package**.

A public Samsung FOTA `version.xml` endpoint is documented by
open-source firmware downloader research, in particular the Bifrost
`VersionFetch` source:

`https://fota-cloud-dn.ospserver.net/firmware/{REGION}/{MODEL}/version.xml`

This is an HTTPS web request from GitHub Actions **to Samsung public
metadata**, not Samsung's Odin/NetOdin port, not Tizen SDB and
not the owner's watch.

## One-time lookups chosen (region is deliberately a hypothesis)

The actual LDU **CSC/region is NOT independently established** by the
public ATFA catalog's `(OXA)` multi-CSC suffix. OXA is not proof of
a specific 3-letter sales CSC for the running watch. To keep the test
small and avoid random-region enumeration, the workflow requests just:

1. `SM-R840X / XAR` (retail US region used only as a hypothesis);
2. `SM-R840X / KOO` (retail Korea region used only as a hypothesis);
3. `SM-R840 / XAR` (public **retail** control; never an R840X firmware
   replacement).

The code hardcodes all three URL paths and uses at most three HTTPS
GETs, a 7-second timeout, at most 128 KiB of response per request,
TLS certificate verification and **no redirect following**. It sends
**no** IMEI, serial, auth token, cookie, device model probe, SDB
connection, Odin handshake, PIT command, firmware installer or personal
phone IP. No arbitrary URL or input is accepted.

Only a schema marker, region/model hypothesis, HTTP/error status and
*allowlisted firmware-version tokens* are recorded in the sanitized
JSON. Raw XML is **never** archived, and an invalid HTML/login page
is not treated as a version response.

If GitHub Actions cannot reach the public FOTA server, or if a specific
lookup returns 403/404/empty/no matching token, this is **not**
proof that R840X firmware never existed or that the owner has a
particular CSC. A returned `R840XXX...` build token is useful
**catalog evidence** but still not a complete downloadable
signed restoration archive, partition map or flash authorization.

## Local use

GitHub Actions runs the test automatically on PR, after two
synthetic-only parser jobs succeed. The optional Android command
is **networked but contacts only the three public URLs**, and does
**not** interact with the Watch3:

```sh
cd ~/Galaxy-3 && git pull --ff-only
python tools/watch3_r840x_public_fota_version_recon.py \
  --probe-public-metadata \
  --output ~/watch3-r840x-fota-public-metadata.json
cat ~/watch3-r840x-fota-public-metadata.json
```

No reason to repeat on the phone if GitHub Actions has produced
usable results. With no flags the script refuses network action.

To parse an already-existing local XML sample without a network
request:

```sh
python tools/watch3_r840x_public_fota_version_recon.py \
  --offline-sample /path/to/local-version.xml
```

**Neither command is an Odin/FOTA *update***. This is a bounded
source metadata lookup and remains `NO_GO` for firmware changes.

## Recovery gate remains unchanged

- Samsung's US public retail `SM-R840` update history
  (`R840XXU...`) is not evidence of LDU `SM-R840X`
  installed `R840XXXU1AUA2`.
- The older `R840XXXU1ATFA` candidate was independently
  listed by multiple sellers, but the owner found HalabTech's
  actual download flow required an **account-credit deposit**
  and public pars-hamrah download link no longer resolved (404).
  No authenticated file bytes or matching signed restore plan.
- The FCC Samsung hardware equivalence report is **useful for
  off-device comparison** of retail image structures only;
  it does not prove identical bootloader identity, signed
  image acceptance, PIT layout or a safe retail cross-flash.
- The owner has one working watch; firmware, 1024-byte Odin
  session/PIT commands, memory manipulation, unlock/exploit
  attempts, update packages and repartitioning remain prohibited
  until genuine full stock rescue and independently validated
  device-specific recovery are available.

This metadata test must never claim the watch has been unlocked,
rescued, booted into UgLy|OS, or proven flashable.
