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
firmware build tokens, model mismatches, archive size/hash and warnings.
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
