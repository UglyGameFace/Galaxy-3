# SM-R840X Recovery Firmware: Candidate Triage and Evidence Register

**Status: NO-GO FOR FLASHING.** Active blocker [Issue #47](https://github.com/UglyGameFace/Galaxy-3/issues/47).
The experimental port is for the actual `SM-R840X` (`NOBLESSE-LARGE-BT R08`)
running `R840XXXU1AUA2`, not an ordinary `SM-R840`. Its ordinary Tizen
SDB shell cannot back up privileged boot/recovery partitions.

## Candidate inventory, October 27, 2026

| Candidate | What the public listing establishes | Blocker |
| --- | --- | --- |
| `R840XXXU1ATFA-(OXA) (Firmware 3 Files).zip` | Third-party R840X repair-firmware catalog listing, ~837MB | Older `ATFA` vs installed `AUA2`; no independently verified official hash, contents, signing or recovery success |
| `R840XXU1ATF9`, `R840XXU1DWK2` | Retail **R840** firmware references | **Different model**; hardware similarity does not establish acceptance by the LDU bootloader |
| `COMBINATION-FT55_R840XTXXU1ATF1` and other engineering/combination packages | Third-party Watch3 service-firmware listings | Service/engineering images do **not** equal complete stock rescue, nor establish R840X compatibility |
| Exact `R840XXXU1AUA2` | Current firmware read on physical watch | **No authenticated complete restoration archive located** |

Catalog/reference links (metadata leads only):
- R840X: https://support.halabtech.com/index.php?a=downloads&b=folder&id=112593
- R840 retail: https://support.halabtech.com/index.php?a=downloads&b=folder&id=92976
- Watch3 combination listing: https://support.halabtech.com/index.php?a=downloads&b=folder&id=90509
- Public stock retail firmware list: https://samfrew.com/devices/galaxy-watch3/sm-r840
- Research-oriented Ragnarök implementation: https://github.com/AsteroidOS/ragnaroek

**No downloaded bytes were supplied or independently authenticated by this research.**
Third-party catalog labels and file extensions can be spoofed. Samsung signing
cannot be verified merely from an archive name, ZIP CRC or SHA256 without a
trusted independent reference. Odin/PIT parsing is research, not recovery.

## October 27 expanded public-source audit: exact-model source confidence

Investigated fresh public metadata and code references **without requesting
firmware bytes, logging into paywalls, downloading installers, touching the
watch or running network Odin commands**. The evidence levels below are
deliberately separate: **model registered** does not mean **archive exists**;
**archive named** does not mean **archive authentic**; **authentic ZIP hash**
does not mean **bootloader accepts it**; **loader accepts stock** would not
mean **custom UgLy|OS boots**.

| Source and observed evidence | Confidence in *that narrow fact* | Missing before restoration |
| --- | --- | --- |
| [Samsung Electronics Service Korea wearable download catalog](https://www.samsungsvc.co.kr/download?code=%EC%9B%A8%EC%96%B4%EB%9F%AC%EB%B8%94) explicitly lists **SM-R840X** separately from **SM-R840**, also alongside other `X` demonstration variants. | **High** that Samsung recognizes a distinct R840X support model; **zero** new actual firmware bytes | The catalog index does not itself expose a tested R840X full firmware archive, bootloader signature, rollback flag or restore guide. Clicking/selecting the exact X model did not yield independently verified package bytes here. |
| [Samsung's official R840 firmware release notes](https://doc.samsungmobile.com/SM-R840/XAR/doc.html) carry **`R840XXU1...`** versions (without the `XXX` segment); the owner's live R840X build is **`R840XXXU1AUA2`**. | **High** that retail update history is for a **different firmware model**; no inference about exact hardware acceptance | Neither `R840XXU1DWK2` nor other retail builds validate R840X custom boot, downgrade or rescue. |
| [Contemporaneous July 28, 2020 public firmware-list post](https://www.reddit.com/r/u_gsm2file/comments/hzfoeq) explicitly names **`R840X R840XXXU1ATFA 3File`**. Previously indexed [HalabTech R840X folder](https://support.halabtech.com/index.php?a=downloads&b=folder&id=112593) also named that same older package (~837 MB). | **Medium** confidence the **ATFA package label** circulated in 2020. This is a vendor/listing claim, **not independent binary authentication**; both listings could originate from the same untrusted supplier. | **No original package bytes, trusted publisher manifest or SHA256, Samsung signing evidence, exact `AUA2` support, PIT, anti-rollback evaluation or confirmed restore outcome**. |
| [SamFrew Galaxy Watch3 firmware model index](https://samfrew.com/devices/galaxy-watch3) lists nine retail/market models but does not list **SM-R840X** among those models at inspection. | **High** for what that consumer-oriented public index shows; absence is **not** proof Samsung or an authorized repair shop never had R840X files. | Searching retail repositories or installing a generic phone firmware downloader cannot replace independent same-model recovery evidence. |
| [Samsung SM-R840X public UK support page](https://www.samsung.com/uk/support/model.SM-R840XTKAEUA/) supplies manuals/safety documents; [Bifrost downloader FAQ](https://github.com/Ff428/SamloaderKotlin) states Samsung's FUS route does not serve **full watch firmware**. | **High** for the public support-page content and the **tool author's own documented limitation**; not evidence no offline service image exists. | A genuinely complete full-stock signed R840X package remains missing. |

### Target evidence that would actually unblock offline engineering

A **lawfully obtained complete** factory/repair ZIP is a candidate only after
it arrives with an independently attributable original publisher/channel,
exact **SM-R840X / R840XXXU1AUA2** model/build information, full BL/AP/CSC
and any required model-specific components, device variant/PIT partition
information, a trusted cryptographic fingerprint/signature reference, and
a reproducible original-device rescue procedure. A different signed build
could eventually be considered **only if** Samsung-specific bootloader,
rollback and partition compatibility is independently proven, not inferred
from shared `U1` text.

After obtaining a candidate, the existing
`audit_watch3_r840x_recovery_zip.py` and
`audit_watch3_r840x_odin_components.py` can inspect a **locally
supplied file entirely offline**. They only validate ZIP/TAR
structure and naming and MUST continue to report **`NO_GO`**.
Even authentic, correctly named file bytes would not establish that
the owner's unique LDU watch can be restored after a failed custom boot.

**Public-source research result (not vendor negative proof):** no
independently authenticated complete **`R840XXXU1AUA2`** recovery
archive or approved alternate-build rollback route was obtained.
No one should buy speculative firmware access, cross-flash
retail `R840`, use combination images or run further 1024-byte
NetOdin commands on the only working watch to fill this gap.

## Updated October 27: real Odin magic proven; full watch firmware still unavailable

The owner physically showed `SM-R840X` Wireless Download WPS/AP screens,
used a phone-local TCP/13579 listener to exchange four-byte `ODIN` →
`LOKE`, and **confirmed stock Tizen rebooted normally afterward**.
This proves **basic live bootloader transport**, not a complete Odin
session, PIT transfer, partition writes, signing acceptance or rescue
after a bad boot. The [offline command risk audit](
watch3-r840x-odin-offline-risk-classification.md) explicitly refuses
every 1024-byte Odin command on the owner's only functioning watch.

A separate current-source check adds a key blocker that makes phone
downloader experimentation a poor use of time:

- Samsung's actual [SM-R840X official support page](
  https://www.samsung.com/uk/support/model.SM-R840XTKAEUA/)
  exposes manuals and safety guides, with no published full-firmware
  rescue archive in its `softwares` listing.
- The open-source [Bifrost Samsung FUS downloader FAQ](
  https://github.com/Ff428/SamloaderKotlin)
  explicitly says Samsung does not serve **full watch firmware**
  through its download route. Thus neither Bifrost on Android nor
  Samloader/FUS should be advertised as a verified way to obtain
  this exact R840X rescue ZIP. This is a vendor/tool-author
  *availability statement*, not proof no repair center could possess
  offline factory firmware.
- Independent public repair-package catalogs still identify an
  **older** `R840XXXU1ATFA` R840X 3-file package, while the owner's
  actual installed build is `R840XXXU1AUA2`. There are no
  independently authenticated complete package bytes/hashes,
  trusted Samsung signatures, compatible PIT/rollback metadata or
  documented verified R840X restore success here.

**Practical direction:** obtain *legitimately and securely* sourced
same-variant complete firmware from an authorized service/repair channel,
or a demonstrably authentic candidate for **offline analysis only**.
Do **not** pay for or install unverified flash utilities, assume a
retail R840 ROM is compatible, or test an old ATFA package just to
see whether it might work. A full rescue failure could brick the only
working watch.

The ZIP audit's past string
`R840X_DOWNLOAD_MODE_AND_STOCK_RECOVERY_UNVERIFIED` wrongly joined
two independent statements. It has been replaced by the narrower
`EXACT_R840X_STOCK_RESTORATION_AND_LOADER_ACCEPTANCE_UNVERIFIED`.
The tool now carries an explicitly **owner-specific, static, dated**
record of the physical magic-only test separately from the trust of
an arbitrary ZIP. Neither a correctly named ZIP nor the known
magic exchange changes its final `NO_GO` decision.

## Android-only offline triage, without extracting anything

If a legitimate R840X recovery ZIP is obtained, inspect its central directory
locally on Android/Termux. This does **not** install software, contact the
watch, extract scripts, inspect private personal data, or trust the payload:

```sh
cd ~/Galaxy-3 && git pull --ff-only
python tools/audit_watch3_r840x_recovery_zip.py \
  "/sdcard/Download/R840XXXU1ATFA-(OXA).zip" \
  --expected-build R840XXXU1AUA2 \
  --sha256 \
  --output ~/watch3-r08-recovery-zip-triage.json
cat ~/watch3-r08-recovery-zip-triage.json
```

**The path is a hypothetical example**. Do not download unknown executable
flash utilities or purchase a file just because it appears in a catalog.
The optional `--sha256` streams bytes (slower for 837MB); it does not
authenticate them.

The report lists only recognized `BL/AP/CSC/CP` component prefixes,
firmware build tokens, model mismatches, archive size/hash, source-separated
physical magic-only evidence, and warnings.
ZIP member data are not extracted or executed. Unsupported nesting and
malformed archive layouts remain unverified. The result is **always NO_GO**
even when all expected names match.

## Optional nested Odin component inventory

The original ZIP-only audit cannot establish whether a BL/AP/CSC component
contains real firmware images. The companion offline analyzer enumerates
**nested TAR headers** without extracting any member onto storage or running
any executable:

```sh
cd ~/Galaxy-3 && git pull --ff-only
python tools/audit_watch3_r840x_odin_components.py \
  "/sdcard/Download/R840XXXU1ATFA-(OXA).zip" \
  --expected-build R840XXXU1AUA2 \
  --output ~/watch3-r08-odin-contents.json
cat ~/watch3-r08-odin-contents.json
```

The path is an example only, **not a file presently on the user's phone**.
It scans only BL/AP/CSC/CP archives with `.tar` or `.tar.md5`
suffixes, reports the embedded filenames and declared sizes, identifies
names containing boot/recovery and potential PIT files, and checks for
path traversal, links, excessive file counts and oversized archives.
A counterfeit ZIP with fake `boot.img` and `recovery.img` names can
pass an inventory. ZIP CRC, TAR metadata and a file hash are **not**
Samsung firmware-signature checks. A reported PIT *name* is not a parsed,
authenticated partition map. No actual vendor package was supplied to
CI; all tests use tiny obviously fake fixtures.

**Bootloader research finding:** Samsung's July 2021 wearable security
bulletin documents `CVE-2021-25434` (parameter partition) and
`CVE-2021-25435` (recovery partition), both affecting Watch3 firmware
before its July 2021 release. The physical watch reports a pre-July
`R840XXXU1AUA2` build, but the applicability of those specific flaws
to this LDU bootloader, whether a reproducible research proof exists,
and any safe reversible loading method have **not** been established.
No malformed partition submissions or live wireless-download exploit
experiments are authorized by the archive tool.

Official advisory: https://security.samsungmobile.com/serviceWeb.smsb?year=2021&month=7

## Gates before a recovery can be called real

1. Obtain authorized genuine stock **R840X** firmware, show content listing
   and hashes, compare exact build/rollback version, model and region.
2. Obtain an authentic PIT/partition map and compare to real R08 metadata;
   map all needed rescue images. Do not guess `mmcblk0pN` roles.
3. Establish documented, reproducible exact-model Samsung wireless-download
   recovery on a **sacrificial** R840X/repair fixture, not the only working
   watch. Distinguish entering download mode from restoring a failed boot.
4. Separately prove boot-chain acceptance of an alternate kernel or a
   temporary boot route. Working NetOdin with stock signatures does not
   imply an unlocked bootloader.
5. Only after a validated rescue route and custom boot acceptance, attempt
   a minimal kernel/initramfs smoke test. No flashing, root shell writes,
   PIT repartition, factory reset or device protocol testing is authorized
   by this metadata check.

Useful publication outcome is a reproducible method and artifact fingerprints;
`first ever` remains a goal, not a verified claim.
