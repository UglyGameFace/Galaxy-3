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

## Source received and actual smoke converted

The user supplied `Smoke-Explosion-Shockwave-SnapYT.App.mp4` in ChatGPT.
SHA-256: `0f64c684f52c7f5eb61e273cc3a5c924bc4699386234d674fd3edba451c40de0`.

The first three seconds were chroma-keyed, despilled, desaturated to white
smoke and composited on true black. The final approved output is
`uglyos-smoke-boot-r08.gif`, SHA-256
`2878bb3917eceec530f321acd61a21967fdb0f158370252866a21452b9f5060f`,
222,599 bytes. All 30 frames passed timing, nonblank-motion, dark-corner and
green-spill checks. This is the user's uploaded footage, not synthetic smoke.

The ChatGPT-produced binary still must be added to the GitHub PR. Until then
the Psplash overlay is **source-only** and is not installable or merge-ready.
The smoke source isn't rehosted, shared or downloaded automatically by CI.

## Current OFF-DEVICE conversion constraints

- 280x280 pixels, black canvas within 360px round screen.
- 3 seconds / 10fps / 30 frames. No forced minimum display time.
- Up to 1.5MB compressed output, less than 8MB cached decoded RGB.
- Center-fit source, green-screen chromakey with despill, and 24-color monochrome
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

PR #29 implements a machine-scoped
`meta-noblesse/recipes-core/psplash/psplash_%.bbappend` to install the
approved GIF at `/usr/share/psplash.gif` for `noblesse-r08` only.
It copies the upstream GIF to `/usr/share/psplash-upstream.gif` before
replacement and leaves all other machines unchanged. The binary must
be uploaded at `meta-noblesse/recipes-core/psplash/files/uglyos-smoke.gif`
in the PR branch. A new CI gate rejects absent, modified, oversized
or differently timed assets by SHA-256 and GIF format checks.

CI must build the actual R08 psplash package and initramfs/rootfs,
verify that THIS GIF is the one selected instead of the upstream
280x154 default, and keep the stock original available for rollback.
Only after target framebuffer and device recovery tests may we claim
the splash actually plays on the physical Galaxy Watch3.

No MP4 decoder, extra boot service, boot delay or firmware write is
introduced in this offline Psplash integration. The Watch3 port itself is
not yet proven bootable and no flash commands are authorized.
