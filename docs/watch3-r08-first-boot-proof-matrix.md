# Galaxy Watch3 SM-R840X R08 first boot: evidence and recovery gate

Updated 2026-10-27 (physical Watch3 AP/ODIN-LOKE transport proof). Target board **NOBLESSE-LARGE-BT R08**; installed
firmware **R840XXXU1AUA2**, Tizen 5.5, Linux 4.9.59.
This is an **engineering decision record**, not installation instructions.
No device writes, unlock attempts, or unverified images are authorized.

## Owner's physical transport evidence: October 27, 2026

The original pre-test language in this file has been superseded by direct
observations from the **owner's actual SM-R840X R08**, not a simulated
peer: Watch3 reboot selector with `Download (Wireless)` (approximately
five-second timeout); WPS mode; AP Mode labeled `SM-R840X`; Android
host bound to the watch AP at `192.168.49.20:13579`; exact four-byte
`ODIN`/`LOKE` exchange; after the intentionally incomplete handshake,
the watch rebooted into normal Tizen. An expected-looking
`Failed to recv cmd (0 != 1024)` message corresponds with no subsequent
1,024-byte packet having been sent. The source-level classification is
recorded in [offline Odin command risk matrix](
watch3-r840x-odin-offline-risk-classification.md).

This proves **basic wireless download transport** and a normal return
after *that* non-flashing experiment, not recovery after corrupting
storage. The actual loader's supported session/PIT commands, Samsung
signing/anti-rollback checks, authentic OEM restoration archive,
device-specific full rescue from boot failure and UgLy|OS kernel
acceptance remain **unproven**. No new 1,024-byte protocol traffic
is allowed on the only working watch.

## October 27 physical kernel PARTNAME map: 21/21 text records reconciled

Owner physically performed four bounded, read-only Tizen SDB
`/sys/class/block/mmcblk0pN/uevent` text batches, then successfully
ran **the offline report reconciler** from Android/Termux on the four
original privacy-filtered JSON files. The resulting
`watch3-r840x-all21-sysfs-evidence.json` records
`ALL_21_KERNEL_TEXT_PARTNAME_FIELDS_RECONCILED` and
`21/21` readable `uevent` files with `21/21` `PARTNAME` fields
in the owner's supplied summaries.

**Recognized labels:** `p5=module`, `p7=steady`,
`p10=param`, `p11=up_param`, `p13=boot`,
`p14=recovery`, `p18=csc`, `p20=rootfs`,
`p21=user`. The **12 remaining observed labels** were redacted to
`unclassified` by our privacy filter, not literally assigned that
name by Samsung. Source and scope:
[on-phone 21/21 evidence reconciliation](watch3-r840x-sysfs-partition-labels.md#completed-owner-run-offline-2121-merge-october-27-2026).

**Newly established:** kernel-reported **number-to-name mappings for
nine common partitions** on the installed stock R840X, including
named `param` and `recovery` paths relevant to Samsung's
2021 bootloader vulnerability disclosures. Do **not** infer that the
exact LDU bootloader is exploitable or supports a different image.

**Still absent:** an authenticated Samsung PIT containing the
complete partition geometry; actual partition contents,
bootloader identification, raw boot/recovery images,
signature/rollback compatibility, complete OEM stock
rescue data, tested recovery after damage, and an accepted
UgLy|OS kernel. The offline merge made **no new watch contact**
and the actual reports weren't independently cryptographically
attested by Samsung. A named `rootfs` partition does not establish
the kernel's root mount/device-mapper dependency by itself.

No reason to repeat physical sysfs batches or issue 1024-byte Odin
commands. **All write/install actions remain NO-GO.**

## Automated first-boot safety gate (2026-10-26)

The **R08 first-boot readiness and recovery gate** is available at
[readiness instructions](watch3-r08-firstboot-readiness.md). It combines
the existing redacted Android/SDB boot and storage reports, optional
pinned historical reference audit, and optional LOCAL artifact checksums
into one NO-GO report. This is a documentation/CI safeguard, **not**
proof that custom Samsung boot images are accepted.

The GitHub Actions validation uses synthetic evidence only, runs quickly
without Yocto compilation, and requires --enforce-install to block
with code 4. Verified smoke Psplash/early-boot packages are software
progress, not stock rescue, successful physical boot or flash permission.

## Already established for this specific device

Read-only SDB inspection established the board and Exynos 9110 revision,
touch, bezel and display device nodes, and a dm-verity-protected Tizen
rootfs. The ordinary SDB shell lacks permission to back up the boot and
recovery partitions. See [machine evidence](../meta-noblesse/README.md).

A **real ARM64 AsteroidOS offline ext4** was built in
[Actions #40095182440](https://github.com/UglyGameFace/Galaxy-3/actions/runs/40095182440).
A second [read-only artifact audit](watch3-r08-offline-image-audit.md)
confirmed original SHA256, clean filesystem, ARM64 launcher and required
graphics packages. This is not a Samsung boot package or proof of device boot.

PR #9 configured a **separate R08-only** legacy ext4 output candidate, not a
proven boot image. Keep the original successful image unchanged.

## Paths investigated, with rigorous proof boundaries

| Candidate route | What is established | What remains unproven on R840X | Decision |
|---|---|---|---|
| **Tizen SDB over Wi-Fi** | Official Samsung documentation supports wireless SDB on Tizen Galaxy Watches; it has already been used read-only on this R840X. | Root or raw boot/recovery partition access, loading a custom kernel. | **Use now, read-only** for boot and hardware evidence. |
| **Samsung recovery/reboot menu** | Samsung officially documents the Galaxy Watch3 reboot-mode and stock recovery navigation. | Restoring a damaged bootloader, accepting unsigned images. Factory reset is not recovery of firmware partitions. | **Inspect only**; do not select factory reset. |
| **NetOdin / Wireless Download** | The owner's actual SM-R840X showed Wireless Download WPS and AP screens and successfully exchanged four-byte `ODIN`/`LOKE` with Android TCP/13579; stock Tizen booted afterward. | No 1,024-byte Odin session command has been tested; PIT, authentic matching stock-restoration image, recovery after damaged firmware and custom boot acceptance remain unknown. | **Transport proved; device writes NO-GO**. |
| **AsteroidOS Ragnarök** | Direct inspection of the pinned source confirms the four-byte magic stage and a subsequent stateful 1,024-byte command protocol. Galaxy-3's physical four-byte stage succeeded. | `detect` invokes session start/end, `print-pit` also starts a session, and firmware/rollback acceptance are unproven on R840X. The source includes destructive factory reset and PIT/flash operations. | **Offline source audits only**; no new live Odin commands. |
| **Internal USB/UART test pads** | Internal access is documented for *other* Samsung Galaxy Watch models, including Watch FE. | Exact R840X pad location, voltage, pinout, UART console and service recovery. | **Do not copy another model's pinout**; professional board research only if noninvasive routes fail. |
| **AsteroidOS web installer / Fastboot / ADB unlock** | Works for particular Android/WearOS devices listed by AsteroidOS. | A fastboot or OEM-unlock interface on Tizen R840X. | **Not an applicable proven R840X method.** |
| **Tizen .tpk apps via SDB** | Samsung's developer documentation supports installing signed Tizen apps. | Replacing the Linux kernel or running a complete independent OS. | Can test an app or limited UI, **not an AsteroidOS install**. |
| **Tizen OTA, modified recovery, dual boot, kexec, chroot** | General techniques exist on other Linux/Android devices. | Appropriate signatures, root privileges, loader support and reversible storage on R840X. | **Unproven on this device**; do not infer viability. |
| **Host QEMU / off-device tests** | Image and userspace integrity can be validated on other machines. | Exynos/Samsung board initialization, display, touch, secure boot. | Good software evidence but **not a substitute for real boot**. |

### Public evidence and scope

- Samsung official Tizen watch wireless SDB:
  https://developer.samsung.com/galaxy-watch-tizen/testing-your-app-on-galaxy-watch.html
- Samsung official Galaxy Watch3 reboot-menu guidance:
  https://www.samsung.com/us/support/troubleshoot/TSG10007068/
- SM-R840X-specific XDA thread (suggestions about stock and combination
  firmware; not an independently verified custom boot):
  https://xdaforums.com/t/flashing-sm-r840x.4248229/
- Galaxy Watch3 R840 NetOdin/region-change community report:
  https://xdaforums.com/t/gw3-region-change.4148221/page-6
- AsteroidOS Ragnarök project, with explicit device-support limitations:
  https://github.com/AsteroidOS/ragnaroek
- AsteroidOS supported watches (does not list Galaxy Watch3):
  https://www.asteroidos.org/watches/
- AsteroidOS Watch FE bootloader and internal USB analysis
  (different model/firmware; **not transferable pinout or procedure**):
  https://wiki.asteroidos.org/index.php/Fresh/wise
- General Samsung secure boot notes:
  https://docs.samsungknox.com/admin/fundamentals/whitepaper/samsung-knox-mobile-security/system-security/trusted-boot/

## New R08 boot contract evidence from pinned public source

The [historical source audit workflow](../.github/workflows/watch3-r08-reference-boot-audit.yml)
fetches five files from pinned vendor reference commit
`ec258e12887d37362b59e3291c1d3e5363c24bff` and produces a tiny,
read-only JSON report without recompiling or contacting the watch.

- The reference `tizen_noblesse_defconfig` contains
  `# CONFIG_KEXEC is not set`; neither recipe fragment overrides it.
  There is **no evidence of a ready-made kexec jump** from running Tizen.
- The historical R08 device-tree source's `/chosen/bootargs` includes
  `root=/dev/ram0`, and an initrd memory range. A raw AsteroidOS ext4 is
  therefore **not equivalent to a complete watch boot image**.
- `CONFIG_BLK_DEV_INITRD=y`, `CONFIG_EXT4_FS=y`, and
  `CONFIG_DM_VERITY=y` are present in the reference base.
- These are historical source **inputs**, not a verified copy of the
  running firmware's final `/proc/config.gz`, `/proc/cmdline` or boot
  partition contents. Actual bootloader signature acceptance remains unknown.

**Most informative next live comparison (read-only SDB only):**
`/proc/cmdline` and visible device-tree `chosen/bootargs`, followed by
`/proc/partitions`. They can confirm whether the installed firmware uses
the same initramfs boot assumptions. Never collect serial numbers or
private identifiers in public GitHub logs.

## Ready-to-use read-only runtime comparison

The [R08 live Tizen boot evidence tool](watch3-r08-live-boot-evidence.md)
can use an already authorized SDB client, or parse saved output entirely
offline with Python on an Android phone. It reports actual kernel/root
arguments, selected partition labels and direct differences from the
pinned reference without exposing raw command lines or private identifiers.
The new CI uses **synthetic samples only**, never contacts a device.
A report is an observation, not evidence that the bootloader accepts a
custom kernel or that stock firmware can be restored.

## Fastest evidence-first route to first boot

**Gate A: stock baseline and observation, no writes.** Reuse the existing
read-only SDB connection where available. Record only *non-secret hardware*
facts: /proc/version, /proc/cmdline, /proc/partitions, /proc/mounts,
device-tree model and read-accessible by-name partition symlinks. Review
commands below; some paths or permissions may be absent. Do not attempt
SDB root, raw block reads, changing mount state or device reboot merely
to complete the inventory.

Example if a legitimate SDB client is already connected and authorized
(the existing watch is Tizen: **SDB, not ADB**):

```sh
sdb shell "cat /proc/version"
sdb shell "cat /proc/cmdline"
sdb shell "cat /proc/partitions"
sdb shell "cat /proc/mounts"
sdb shell "ls -l /dev/disk/by-name"
sdb shell "ls -l /dev/block/by-name"
```

Absent directory/access-denied is expected and must be recorded, not
bypassed or treated as permission for destructive testing. Keep any
serial numbers, Wi-Fi credentials and unique identifiers out of public CI.

**Gate B: exact safe-return route.** Identify independently verified,
same-variant R840X stock firmware **matching the actual bootloader and
partition layout**, including a feasible restoration method and device
acceptance criteria. Recovery menu and a factory reset do **not**
constitute a full firmware restoration. Do not flash R840 stock firmware
to an R840X simply because the identifiers are similar.

**Gate C: boot-chain acceptance.** Establish a supported method for this
specific Tizen bootloader to load a custom or temporary kernel. Merely
entering Wireless Download mode or reading a PIT does not demonstrate
acceptance of unsigned images. Any signing/unlock claim must be backed
by exact model, firmware and reproducible results.

**Gate D: non-destructive trial boot if proven.** Only if A-C pass, prepare
a watch-specific kernel, DTB and rootfs with precisely verified boot
packaging; prefer a temporary in-memory boot route if *actually supported
on R840X*, preserving every stock partition. Otherwise stay off-device.

**Gate E: functional smoke test.** First kernel serial/debug output and
storage, then framebuffer, touch, bezel, radios, power, and eventually
audio. An ext4 integrity pass alone is not boot success.

## Explicit STOP conditions

- No verified restorable stock firmware + actual recovery transport.
- No demonstrated unsigned custom kernel support/unlock or signed boot route.
- No authenticated R840X Samsung PIT/partition *geometry* or boot image format or recovery boundaries. Nine kernel-reported partition labels are now known; that does **not** satisfy this gate.
- Mismatch between R840X and any firmware/tutorial aimed at R840,
  R845, Galaxy Watch FE/4, or other models.
- No reliable way to connect to the watch after a failed boot.

**Current go/no-go: NO-GO for writing to device; GO for read-only boot
research.** This is not extra polish. These are the minimum checks that
protect a working watch from a permanently failed boot.
