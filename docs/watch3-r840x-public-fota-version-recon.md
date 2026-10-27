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

## October 27: physical SM-R840X active CSC has now been observed

The owner ran the merged, **single fixed-path read-only SDB**
\`tools/watch3_r840x_csc_readonly.py\` on the *actual* SM-R840X
without any firmware write, Odin session, PIT request or CSC change.
Their supplied privacy-filtered JSON reported:

- \`remote_path=/opt/system/csc-default/output/csc-active-customer.log\`
- \`state=ACTIVE_CSC_CANDIDATE_READ_FROM_EXACT_TIZEN_PATH\`
- \`observed_active_csc_candidate=PAP\`
- \`model=SM-R840X\`, installed \`R840XXXU1AUA2\`
- \`watch_write_performed=false\`, \`odin_session_started=false\`,
  \`pit_requested=false\`, \`firmware_written=false\`
- \`full_stock_recovery_proven=false\`, \`flash_allowed=false\`.

**This is direct, model-specific evidence of the watch's *currently
active* CSC PAP**, not merely the \`(OXA)\` tag on an old seller
listing. Whether PAP describes the original factory/sales CSC, LDU
distribution region, ROM package CSC or a bootloader acceptance policy
is **not established**. The file is mutable system configuration, not
Samsung's signed hardware identity or authentic PIT.

Public CSC lists label PAP as a European code:
https://technastic.com/samsung-csc-codes-list/ .
Also, *other* X-suffixed Galaxy Watch variants SM-R860X and
SM-R890X have PAP listed in public firmware catalog *metadata*:
https://samfrew.com/devices/galaxy-watch4/sm-r860x
https://samfrew.com/devices/galaxy-watch4-classic/sm-r890x .
These are corroborating catalog references, **not signed LDU
firmware bytes or a universal PAP flash compatibility rule**.

### New one-request manufacturer metadata check

Rather than repeat the unrelated, historically guessed XAR/KOO
regions, \`--probe-owner-active-csc\` contacts only this **one
public model/region endpoint** from GitHub Actions, no watch:

\`https://fota-cloud-dn.ospserver.net/firmware/PAP/SM-R840X/version.xml\`

As before, this is capped, verified HTTPS **version metadata only**:
one GET, no redirect following, no IMEI, serial, token, owner IP,
firmware image, Odin command or any access to the physical watch.
Even a valid XML version list **cannot** provide boot/recovery image
bytes, trusted vendor signatures or a return-to-stock guarantee.
403/404/no answer may reflect publication policy and are
**inconclusive about firmware existence**.

The old, unrelated public lookups and their real HTTP 403/retail
control results are retained *below as historical evidence*, but
the current CI job now requests only \`SM-R840X/PAP\`.

## Historical October 27 lookups before PAP was known (hypotheses only)

When the original lookup ran, the actual LDU **CSC/region was not yet known**;
it has subsequently been observed as active **PAP** from the watch's exact
Tizen CSC file. The earlier guess was not validated by
the public ATFA catalog's `(OXA)` multi-CSC suffix. OXA is not proof of
a specific 3-letter sales CSC for the running watch. To keep the test
small and avoid random-region enumeration, the workflow requests just:

1. `SM-R840X / XAR` (retail US region used only as a hypothesis);
2. `SM-R840X / KOO` (retail Korea region used only as a hypothesis);
3. `SM-R840 / XAR` (public **retail** control; never an R840X firmware
   replacement).

The **historical** `--probe-public-metadata` mode still hardcodes those
three URL paths and uses at most three HTTPS GETs; the new 
`--probe-owner-active-csc` sends only one fixed PAP request, a 7-second timeout, at most 128 KiB of response per request,
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
synthetic-only parser jobs succeed. The optional Android command is **networked but contacts only the
public Samsung PAP metadata URL**, and does **not** interact with the Watch3:

```sh
cd ~/Galaxy-3 && git pull --ff-only
python tools/watch3_r840x_public_fota_version_recon.py \
  --probe-owner-active-csc \
  --output ~/watch3-r840x-pap-public-metadata.json
cat ~/watch3-r840x-pap-public-metadata.json
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
