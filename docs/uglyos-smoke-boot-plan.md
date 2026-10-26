# UgLy|OS | smoke-only startup animation (R08)

Requested exact source: https://youtu.be/WqeCrfgum38

**Intended look:** ONLY the source smoke, keyed cleanly off its green
background and composited onto pure black for the 360x360 round AMOLED
display. No extra logo, no green screen, no sound.

## Reality of our boot sequence

The pinned meta-asteroid source at
1af66a6188f7909303cfcec779c8475be1bc4679 uses
recipes-core/psplash/psplash_%.bbappend and an animated GIF Psplash
extension. Pinned upstream installs its loop into /usr/share/psplash.gif
and the initramfs boot script launches /usr/bin/psplash before systemd.
The included GIF decoder allocates 24-bit RGB for every frame, so
**do not** feed Psplash a huge video or a 360px/30fps/20-second GIF.

Because the loader plots GIF pixels directly onto the black framebuffer,
pure black compositing is deliberately preferable to relying on
transparent GIF alpha. The green background must be removed in the
conversion pass, not merely hidden by trimming off the corners.

## Exact source clip still required

The YouTube page cannot be downloaded or inspected from this build
environment, and the clip's reuse license has not been verified.
The linked media is **not** included here. We must use an original
source copy the user has rights to use or a verified licensed copy;
do not pretend a synthetic smoke test matches the requested video.
The conversion CLI has no network calls or downloader.

## Current OFF-DEVICE conversion constraints

- 280x280 pixels, black canvas within 360px round screen.
- 3 seconds / 10fps / 30 frames. No forced minimum display time.
- Up to 1.5MB compressed output, less than 8MB cached decoded RGB.
- Center-fit source, green-screen chromakey with despill, and 64-color
  optimized palette to conserve storage/memory.
- Validation rejects green residue, bright rectangle corners, static
  frames, invisible smoke, wrong durations or too-large GIFs.

After obtaining an authorized source copy named input.mp4, run:

    python3 tools/build_uglyos_smoke_splash.py \
      --input input.mp4 \
      --output uglyos-smoke.gif

The generated file is *not yet installed on the watch*. The optional
--start argument can select a smoke-heavy portion of a longer clip;
--similarity and --blend may need adjustment against actual green lighting.

## Gate before any native startup integration

The next PR slice will be a machine-scoped
meta-noblesse/recipes-core/psplash/psplash_%.bbappend that installs
this validated GIF at /usr/share/psplash.gif **only for noblesse-r08**,
without overwriting the upstream fallback on other watches. The asset
must be committed or otherwise reproducibly furnished to the build
with its checksum and documented reuse permission.

CI must build the actual R08 psplash package and initramfs/rootfs,
verify that THIS GIF is the one selected instead of the upstream
280x154 default, and keep the stock original available for rollback.
Only after target framebuffer and device recovery tests may we claim
the splash actually plays on the physical Galaxy Watch3.

No MP4 decoder, extra boot service, boot delay or firmware write is
introduced in the current preparation PR. The Watch3 port itself is
not yet proven bootable and no flash commands are authorized.
