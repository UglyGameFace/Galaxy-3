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
`tools/watch3_r840x_csc_readonly.py` on the *actual* SM-R840X
without any firmware write, Odin session, PIT request or CSC change.
Their supplied privacy-filtered JSON reported:

- `remote_path=/opt/system/csc-default/output/csc-active-customer.log`
- `state=ACTIVE_CSC_CANDIDATE_READ_FROM_EXACT_TIZEN_PATH`
- `observed_active_csc_candidate=PAP`
- `model=SM-R840X`, installed `R840XXXU1AUA2`
- `watch_write_performed=false`, `odin_session_started=false`,
  `pit_requested=false`, `firmware_written=false`
- `full_stock_recovery_proven=false`, `flash_allowed=false`.

**This is direct, model-specific evidence of the watch's *currently
active* CSC PAP**, not merely the `(OXA)` tag on an old seller
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

### Completed October 27: actual Samsung server response for owner CSC PAP

This is **not a proposed check anymore**. The owner-sourced active CSC
`PAP` was used for an independently executed *public Samsung server*
query in [GitHub Actions run #40567883134](
https://github.com/UglyGameFace/Galaxy-3/actions/runs/40567883134).

The three actual jobs **completed successfully**: `offline-parser-regressions`
(Ubuntu 22.04 and 24.04) and `one-shot-owner-pap-version-xml`
(Ubuntu 24.04). The latter issued **exactly one bounded HTTPS GET** to
the public `SM-R840X/PAP/version.xml` endpoint, without accessing the
owner's watch, uploading device identity, or downloading firmware.

The real job log, NOT a synthetic test fixture, contains:

- `model=SM-R840X`, `region=PAP`
- `state=R840X_BUILD_TOKEN_FOUND_IN_PUBLIC_FOTA_XML`
- `r840x_build_tokens=[R840XXXU1AUA2]`
- `retail_build_tokens=[]`
- `physical_active_csc_observed=PAP` (proven by separate owner SDB read)
- `exact_stock_recovery_archive_obtained=false`,
  `signed_stock_recovery_verified=false`,
  `restoration_of_failed_boot_verified=false`,
  `device_contacted=false`, `firmware_downloaded=false`,
  `firmware_written=false`, `flash_allowed=false`,
  `result=NO_GO`.

The [sanitized metadata artifact, ID 12763761551](
https://github.com/UglyGameFace/Galaxy-3/actions/runs/40567883134/artifacts/12763761551)
was archived with requested 14-day retention; it is **not** an update
image and may expire. The original workflow log also contains the
sanitized token result.

**Conclusion:** Samsung's public firmware-version metadata really
recognizes the *specific model + active CSC + installed build* triple:
`SM-R840X / PAP / R840XXXU1AUA2`. This is a reproducible and
independent match to the physical watch. A `version.xml` entry,
however, does not establish that Samsung FUS serves a full watch
repair archive. The Bifrost author's full-watch firmware limitation,
missing verified R840X signed recovery ZIP/PIT, and refusal to use
retail `SM-R840` packages still apply.

### Interpreting PAP carefully: demo association versus geography

Public aggregators label `PAP` as Europe, and some label it Hungary.
That should **not** be treated as verified manufacture/original
sales country for this physical LDU:

- [SamFrew SM-R860X](https://samfrew.com/devices/galaxy-watch4/sm-r860x),
  [SM-R870X](https://samfrew.com/devices/galaxy-watch4/sm-r870x)
  and [SM-R880X](https://samfrew.com/devices/galaxy-watch4-classic/sm-r880x)
  list `PAP` as their sole catalog CSC, alongside `...XXX...`
  builds on these **other X-suffix watch variants**.
- An older [third-party Galaxy A9 2018 demo-unit discussion](
  https://4pda.to/forum/index.php?showtopic=921470&st=2300)
  likewise labels `PAP` as the original CSC for an `SM-A920X`
  demo unit; it is a user-community claim on **another** device,
  not an OEM Samsung policy statement.
- Generic [CSC catalogs](https://technastic.com/samsung-csc-codes-list/)
  label `PAP` as Europe but do not establish that this watch's
  `PAP` identifies a particular retail region/market.

The repeated independent **demo-model PAP association is suggestive,
not proof of a universally reserved LDU-only code**, and the same
CSC string might be reused for different purposes. No alternate
CSC should be written to the watch, no retail CSC firmware should be
selected by geographic assumption, and the current active `PAP`
does not establish original factory provenance, signed-image
compatibility or stock repair acceptance.

### Follow-up: determine whether the PAP XML exposes a download reference

The October 27 confirmed `SM-R840X / PAP / R840XXXU1AUA2`
public `version.xml` contains a firmware *version token*. The crucial
next distinction is **what the XML actually includes**, versus what
people assume a version endpoint includes.

Other open-source readers including
[jesec/samfirm.js](https://github.com/jesec/samfirm.js/blob/master/index.ts)
and [SamFetch's public resource notes](
https://github.com/ysfchn/SamFetch/blob/main/RESOURCES.md)
read the `versioninfo/firmware/version/latest` and `upgrade` fields.
The FOTA *version index* is not by itself an authenticated full
Samsung recovery ZIP, nor does the presence of a generic `<url>`
text node provide full boot/recovery images.

A new **one-request, public-only**
`--inspect-owner-pap-xml-structure` mode examines the existing,
fixed PAP endpoint from GitHub Actions and emits **only**:
bounded XML element paths, number of HTTP-looking text elements,
number whose text *resembles* an archive URL suffix, and explicit
`NO_GO` verification flags. It retains and publishes **no raw
XML, URL value, private identifiers or file downloads**.
Do **not** promote a suffix-looking URL to a genuine signed image;
a missing link in this one file likewise does not mean no full
firmware exists through another authorized repair channel.

The original PAP confirmation
[run #40567883134](https://github.com/UglyGameFace/Galaxy-3/actions/runs/40567883134)
remains the source of the exact-build match. This follow-up
is an additional metadata-shape observation, not a rerun of
CSC detection and never interacts with the owner's only watch.

### New one-request manufacturer metadata check

Rather than repeat the unrelated, historically guessed XAR/KOO
regions, `--probe-owner-active-csc` contacts only this **one
public model/region endpoint** from GitHub Actions, no watch:

`https://fota-cloud-dn.ospserver.net/firmware/PAP/SM-R840X/version.xml`

As before, this is capped, verified HTTPS **version metadata only**:
one GET, no redirect following, no IMEI, serial, token, owner IP,
firmware image, Odin command or any access to the physical watch.
Even a valid XML version list **cannot** provide boot/recovery image
bytes, trusted vendor signatures or a return-to-stock guarantee.
403/404/no answer may reflect publication policy and are
**inconclusive about firmware existence**.

The old, unrelated public lookups and their real HTTP 403/retail
control results are retained *below as historical evidence*, but
the current CI job now requests only `SM-R840X/PAP`.

## Historical October 27 lookups before PAP was known (hypotheses only)

When the original lookup ran, the actual LDU **CSC/region was not yet known**;
it has subsequently been observed as active **PAP** from the watch's exact
Tizen CSC file. The earlier guess was not validated by
the public ATFA catalog's `(OXA)` multi-CSC suffix. OXA is not proof of
a specific 3-letter sales CSC for the running watch. To keep that initial test small and avoid random-region enumeration, the
original workflow requested just:

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
