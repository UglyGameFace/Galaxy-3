# UgLy|OS R08 genuine smoke Psplash: native early-boot integration

Scope: Galaxy Watch3 SM-R840X NOBLESSE-LARGE-BT R08 experimental AsteroidOS.
NOT boot-validated on real hardware. No firmware changes, device writes or flashing.

## Why the native integration matters

Pinned meta-asteroid Android initramfs starts /usr/bin/psplash BEFORE
switch_root. Pinned meta-smartphone
meta-android/recipes-core/images/initramfs-android-image.bb gets extra
packages from ANDROID_EXTRA_INITRAMFS_IMAGE_INSTALL, which previously did
not include Psplash on our R08 machine. Merely verifying the GIF or
Psplash packaging would not prove smoke displays during early boot.

The new machine-conf override appends psplash only for noblesse-r08.
The existing R08-only bbappend saves the original upstream GIF as
/usr/share/psplash-upstream.gif and writes the exact approved smoke
SHA256 2878bb3917eceec530f321acd61a21967fdb0f158370252866a21452b9f5060f
as /usr/share/psplash.gif.

## New GitHub Actions evidence

The R08 native-smoke-initramfs workflow fetches pinned Yocto/OE-Core,
BitBake and AsteroidOS layers. It checks actual BitBake -e variables
for Psplash and initramfs-android-image including animated-gif,
SRC_URI, MACHINE, package architecture, IMAGE_INSTALL and
ANDROID_EXTRA_INITRAMFS_IMAGE_INSTALL.

Before compilation, dependency-aware native psplash package_write_ipk
and initramfs-android-image image_complete task graphs are required
to be bounded at 3000 tasks, with no kernel/Qt/full-OS expansion.
If unsafe or unsupported, CI fails rather than skipping dependencies.

A successful run independently validates native Psplash .ipk and
package staging D/packages-split; it compares exact bytes for the
smoke GIF, checks a distinct stock fallback GIF, and requires a real
Psplash ELF. It then builds a native R08 initramfs cpio.gz and reads
the actual cpio to confirm the smoke/fallback, compiled ELF, and
boot script referencing Psplash. The artifact is clearly marked
OFFDEVICE-NOT-FLASHABLE.

## What remains unverified

No host-rendered test proves physical Watch3 bootloader acceptance,
correct graphics/framebuffer, actual Psplash playback, stock recovery,
or flash safety. The exact R840X recovery/boot-chain acceptance is
still unverified. Do NOT install or flash the resulting archives.

## CI runtime correction (2026-10-26)

The prior head run #40319035583 failed with exit code 124 solely because
`timeout 3300s` stopped the native package build after reaching task 935/974.
Its source tests, actual BitBake variables and 974-task graph had passed.
No compiler failure or unsafe dependency was reported.

The same exact pinned layer source, QML-independent build graph, R08
package validation, smoke SHA256 gate and stock fallback checks are retained.
The native build has a 6600-second bounded timeout; the early-boot cpio
build has 6000 seconds within a 240-minute workflow ceiling. This changes
CI execution time, not acceptable output, dependencies, or device safety.

GitHub Actions now restores signature-verified Yocto download/sstate caches,
and after native Psplash succeeds optionally checkpoints at most 6 GiB
before the image stage. Cache save failures cannot waive the real IPK or
initramfs verification. Build graph limits remain 3000 tasks per stage.
