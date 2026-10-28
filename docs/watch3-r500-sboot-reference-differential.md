# Issue #47: genuine public SM-R500 S-BOOT differential reference

**Date:** October 28, 2026. **Target device remains SM-R840X (R08), NOT SM-R500.**
This is an **off-device, non-executing reverse-engineering note**. No ROM, keys,
private owner uploads, signed firmware, or executables are committed here.
No Odin/PIT/FOTA calls, commands, flashing, device connections or custom boot.

## Artifact provenance: real archived bytes, not a firmware listing

The public third-party repository
[`lapinclown/SM-R500-TizenFOTA-pkgs`](https://github.com/lapinclown/SM-R500-TizenFOTA-pkgs)
contains historical OTA packages for the **Galaxy Watch Active SM-R500**,
another Exynos9110 device. Public Git tree metadata was checked against
downloaded Git blob SHA1, then actual ZIP/7z and nested TAR archive content
was inspected in isolated GitHub Actions runners. This proves consistency
with the *public repository blobs*, **not Samsung cryptographic
authentication or R840X restore compatibility**.

- **2019 source:** `R500XXU1BSD3/R500XXU1BSD3-FOTA.7z`,
  35,010,721 bytes; SHA-256
  `6d104d87d934af6908fd182a589662b72d06e4ad79445896b15355fd77f97586`.
  Contained `R500XXU1BSD3-FOTA.tar`, 39,589,387 bytes; TAR SHA-256
  `637ca4c0cd79283ecf9e0e0dd33b23c887cc9cdacf5792f272a46d3c85706a6f`.
- **2021 source:** `R500XXU1GUJ2/R500XXU1GUJ2-FOTA.7z`,
  later historical SM-R500 update, Git blob SHA1
  `3f7fb436056ad43a58a735ae026b5ac603ea1ae8`.
  The exact nested TAR and its sboot were read and checked off-device.
- The 2019 TAR has **849 actual member entries**. It contains
  `sboot.bin`, `cm.bin`, `delta.boot`, `delta.ramdisk1`,
  `delta.ramdisk2`, `delta.upparam`, `delta.recovery`,
  `delta.ua`, `unpack.sh`, `update.cfg`, and file-level rootfs diffs.
  `delta.recovery` is only **two bytes** (`31 0a`, ASCII `1\n`).
  This cannot be treated as a complete signed stock recovery image.
- `delta.ua` is a real **ARM32 ELF** (141,748 bytes, SHA-256
  `cdc0ae93d5e807602086f291b46adf51c5dc27fd33ee10adbbf2ad2e3f613911`).
  String evidence includes `SS_verify_DELTA_image`,
  `SS_IMGVerifyFullImage`, `EVP_PKEY_verify` and
  `FOTA_ROOT.cer`, plus `/opt/usr/data/fota`. These are static
  binary references, **not a proven invoked signature-check call path**.
  The matching folder name on the owner's R840X FOTA client does not
  establish identical agent code, credentials or privileges.

## Two actually extracted S-BOOT executables

| Public sibling firmware | sboot length | SHA-256 |
| --- | ---: | --- |
| `R500XXU1BSD3` (2019) | 1,921,296 B | `4715861156eeceb949899d355ccc37eefb57062888aadc76aa9f93f9eaf5966e` |
| `R500XXU1GUJ2` (2021 Oct) | 1,921,296 B | `c96813f283e2f98d3f33a30c6215fa25b06b756b93adf55ecf8d59fc4d9211a9` |

They differ at **815,192 same-offset bytes**, with **201 of 470**
same-offset 4-KiB blocks identical. Across the *two-year*
release gap, these changes cannot be attributed to Samsung's July
2021 CVEs without identifying particular functions and versions.

Both images retain strings `ODIN` (5), `LOKE` (1),
`PIT` (9), `recovery` (10), with device string `SM-R500`.
In the 2019 image the `LOKE` string is at **file offset `0xB7398`**;
in October 2021 it moved to **`0xB8090`**. These are **file
offsets, not proved live addresses or callable functions**.
The real R840X watch previously exchanged four-byte `ODIN`/`LOKE`
over its own wireless-download transport. Protocol similarity does
not establish identical loaders or acceptance rules.

## Verified AArch64 instruction-level PIT header check

A bounded raw AArch64 disassembly was executed in an isolated runner
against the **actual extracted S-BOOT bytes**, without ever running
the bootloader. The executable code and its marker strings yield
multiple direct candidate PC-relative `ADRP`+`ADD` references
under a raw-file-offset memory mapping hypothesis.

Particularly compelling are the matching PIT-related sequences:

| Evidence | 2019 offset | Oct 2021 offset |
| --- | --- | --- |
| `ADRP` + `ADD` to PIT string | `0x58BB0` / `0x58BB4` | `0x58E60` / `0x58E64` |
| Compare incoming length to `0x2000` | `0x58BD4` | `0x58E84` |
| Compose `0x12349876` using `MOV` / `MOVK` | `0x58BE0` / `0x58BE8` | `0x58E90` / `0x58E98` |
| Compare reconstructed 4-byte input header with constant | `0x58C00` | `0x58EB0` |
| Conditional branch on equal header | `0x58C04` | `0x58EB4` |

The bytes around those locations decode to real AArch64 load,
bitwise OR, compare and branch instructions. The header validation
sequence and the 8-KiB length comparison are seen in both
versions and **not asserted to be the patched CVE**. The
`0x2000` check is a condition on a *caller-provided length
register in this candidate routine*, not a verified maximum
Samsung wireless command size or authenticated PIT capacity.

Other raw-offset candidate references to `ODIN`
(`0x5CE70` in 2019 / `0x5D1B4` in 2021) appear near
boot-mode label selections and **must not be called a proven network
packet decoder**. The `recovery` reference
(`0x6E274` / `0x6E758`) is near an indirect call/logging
pattern and **must not be called a proven recovery partition writer**.

All source, size, hash and byte-address outputs are reproducible
through [Issue #47 sibling archive audit workflow](
../.github/workflows/watch3-r500-public-fota-inventory.yml) and its
[verified run #40634785980](
https://github.com/UglyGameFace/Galaxy-3/actions/runs/40634785980).

## What the evidence actually changes

**Established:** one authentic-to-public-repository pre/post
SM-R500 S-BOOT **byte-level comparison**, AArch64 instruction
locations, PIT candidate validation sequence, and one real public
Samsung FOTA update agent with security-related symbols.

**Not established:** the original **SM-R840X / `R840XXXU1AUA2`**
S-BOOT bytes or its memory layout, the exploitable code path in
CVE-2021-25434/25435, input control on the owner's loader,
unsigned boot-image acceptance, full signed stock R840X recovery
package, or independent rescue on sacrificial compatible hardware.

**Next useful reverse-engineering step:** off-device control-flow
and provenance analysis of the **actual SM-R840X bootloader** when
obtained. Closely spaced older/newer **same-model** releases would
help attribute a 2021 security patch; the currently compared
2019/October-2021 SM-R500 versions alone cannot. Do not send
any Odin payload, repartition, install sibling firmware, change
`param`/`recovery`, or test exploits on the sole working watch.

**Current physical-watch decision: NO-GO for firmware writes or
UgLy|OS boot.**