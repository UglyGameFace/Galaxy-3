# Watch3 R08: experimental DECON framebuffer display backend

## Actual source change

An upstream `asteroid-launcher-configs_%.bbappend` now overrides the installed
`10-platform.conf` **only** for the `noblesse-r08` machine. It selects:

```text
QT_QPA_PLATFORM=linuxfb
QT_QUICK_BACKEND=software
QT_QPA_FB_DRM=0
```

This targets the Samsung DECON fbdev driver instead of an unproven TGM DRM KMS backend.

## Evidence

- Pinned kernel `tizen_noblesse_defconfig` enables `CONFIG_EXYNOS_DECON_FB=y` and `CONFIG_FB=y`.
- The Samsung `drivers/video/fbdev/exynos/dpu_9110/decon_core.c` implements `fb_ops`, `fb_mmap`, and calls `register_framebuffer()`.
- The TGM DRM driver only advertises `DRIVER_GEM | DRIVER_PRIME`; `DRIVER_MODESET` is absent.
- AsteroidOS upstream installs `10-platform.conf` via its own `asteroid-launcher-configs` BitBake recipe.
- Qt documents `linuxfb` plus `QT_QUICK_BACKEND=software` as its software-only Qt Quick route: https://doc.qt.io/qt-6/embedded-linux.html

## Real blockers, not solved by this recipe

- `/dev/fb0` was **not verified on the user's watch**. Framebuffer registration in public reference source isn't runtime evidence.
- Qt6 LinuxFB QPA plugin cross-compilation and package splitting **passed**; inclusion in the eventual target image and runtime plugin loading remain unverified.
- The AsteroidOS Lipstick/QtWayland compositor must be checked for shader and Wayland buffer compatibility with software rendering.
- CPU rendering might be slow and increase power usage.
- The stock boot chain and recoverable boot method are still unverified. Never flash this image.

## Next verification

The off-device AsteroidOS preflight has unpacked `asteroid-launcher-configs`
and matched the effective `10-platform.conf` to the Watch3 file. The subsequent Qt package metadata test checks the R08 recipe's LinuxFB feature and plugin dependencies.
The [full QtBase package CI run](https://github.com/UglyGameFace/Galaxy-3/actions/runs/39593317503)
**successfully compiled `libqlinuxfb.so` for AArch64**, but did not run a
compositor/client rendering test or verify the physical watch framebuffer.

Sources:

- https://github.com/UsrBinLuna/kernel_samsung_galileo/blob/ec258e12887d37362b59e3291c1d3e5363c24bff/arch/arm64/configs/tizen_noblesse_defconfig#L2331-L2386
- https://github.com/UsrBinLuna/kernel_samsung_galileo/blob/ec258e12887d37362b59e3291c1d3e5363c24bff/drivers/video/fbdev/exynos/dpu_9110/decon_core.c#L3273-L3287
- https://github.com/AsteroidOS/meta-asteroid/blob/1af66a6188f7909303cfcec779c8475be1bc4679/recipes-asteroid/asteroid-launcher/asteroid-launcher-configs_git.bb

### Pinned AsteroidOS launcher software-rendering fallback

The official Qt documentation confirms that `ShaderEffect` items do not draw
on the Qt Quick software scenegraph. The pinned AsteroidOS launcher includes a
full-screen `ShaderEffectSource` and `CircleMaskShader` for artificially
rounding its compositor output. The physical Galaxy Watch3 panel is already
round, so the `noblesse-r08` machine now includes an upstream-source QML
patch removing **only** that compositor-wide GPU-only corner mask.

The [launcher patch CI](https://github.com/UglyGameFace/Galaxy-3/actions/workflows/watch3-r08-launcher-patch.yml)
checks the patch against AsteroidOS launcher commit
`0ba0eb50a68fc6f1019312d511ec3e2fd1b48f31` without
building Qt. This is a **source-level adaptation**, not proof the remaining
Wayland compositor, watch faces or app animations work with CPU rendering.

The pinned launcher also uses `WindowWrapperBase.qml` to apply a
`CircleMaskShader` **per application window** during gestures. R08 now
has a second machine-scoped patch,
`0002-noblesse-r08-disable-app-window-mask-layer.patch`, that removes
this GPU-only window layer without changing other watches. The
[fast pinned-source workflow](https://github.com/UglyGameFace/Galaxy-3/actions/workflows/watch3-r08-launcher-patch.yml)
applies both patches to the exact upstream `0ba0eb50` source and checks the
resulting QML. The real BitBake `do_patch` preflight now inspects both
QML files as well. These workflow results have not yet been confirmed for
the new changes.

Other effects exist, including launcher speed-dial effects and watch-face
shaders. Their software compatibility is still unresolved; do not mark the
full GUI operational from these two patches alone.

Official reference: https://doc.qt.io/qt-6/qml-qtquick-shadereffect.html

### Runtime plugin and Wayland client integration (in progress)

The official AsteroidOS launcher declares `qtwayland-plugins` as a runtime
dependency. In Qt6 meta-qt6, the QPA plugins live in a separate
`qtbase-plugins` package. R08 now explicitly adds `qtbase-plugins` to the
launcher's runtime dependencies, with CI inspecting effective `bitbake -e`
metadata for `qtbase` LinuxFB/GUI `PACKAGECONFIG`, the plugin packaging
mapping and launcher package dependencies. The [QtBase package build](https://github.com/UglyGameFace/Galaxy-3/actions/runs/39593317503)
now proves the plugin compiled and was placed in `qtbase-plugins`, but not
that it was installed in the final image or loaded by a running compositor.

QtWaylandCompositor documents shared-memory (`wl_shm`) client buffers when
hardware integrations are unavailable. Its `QWaylandQuickItem` can create
Qt Quick textures from shared-memory buffer images. This makes a CPU-rendering
path plausible; a real off-device compositor/client smoke test is still needed
and watch performance remains unknown.

AsteroidOS's upstream `asteroid-launcher.service` reads its `EnvironmentFile`
from `/var/lib/environment/compositor/*.conf` **for that launcher service**.
The Watch3 LinuxFB environment override is therefore *not* evidence that
independently launched Wayland client apps inherit `QT_QUICK_BACKEND=software`.
Do not apply `QT_QPA_PLATFORM=linuxfb` globally: Wayland clients need their
own Wayland platform selection, not direct framebuffer access. Establish the
actual application launch environment before changing that path.

Remaining validation gates: confirm the complete AsteroidOS preflight CI
(including the launcher `do_patch` stage), install the verified QtBase plugin
in an actual R08 rootfs, test QtWayland compositor/client `wl_shm` rendering,
and eventually verify physical display behavior only after recovery/boot
safety has been independently established.

References:
- https://github.com/AsteroidOS/meta-asteroid/blob/master/recipes-asteroid/asteroid-launcher/asteroid-launcher_git.bb
- https://github.com/AsteroidOS/meta-asteroid/blob/master/recipes-asteroid/asteroid-launcher/asteroid-launcher/asteroid-launcher.service
- https://github.com/YoeDistro/meta-qt6/blob/6.11/recipes-qt/qt6/qt6.inc
- https://doc.qt.io/qt-6/qtwaylandcompositor-index.html

### Off-device QtBase LinuxFB binary packaging gate

A separate [Watch3 QtBase LinuxFB package build workflow](https://github.com/UglyGameFace/Galaxy-3/actions/workflows/watch3-r08-qt-linuxfb-package.yml) is now available.
It follows the already-used pinned AsteroidOS/OE-Core metadata revisions, verifies
QtBase/launcher effective settings, and builds only `qtbase -c package`.
It then checks the real `PKGDEST/qtbase-plugins` output for exactly one
`plugins/platforms/libqlinuxfb.so` with an AArch64 ELF64 shared-object
header. The plugin itself is not uploaded or distributed.

The validator has regression tests for missing/misplaced plugin binaries,
wrong architecture or ELF type, invalid headers, and duplicate copies.
This is an **off-device package check**, not a runtime plugin-load,
Wayland `wl_shm` compositor/client test, or physical framebuffer test.
**Verified passed:** [run #39593317503](https://github.com/UglyGameFace/Galaxy-3/actions/runs/39593317503)
completed all 2,171 BitBake tasks and produced `libqlinuxfb.so` under
`qtbase-plugins/usr/lib/plugins/platforms/`. The file is an ELF64 AArch64
shared object, with SHA-256
`eeb85c3d13ba428067f514798da27ac3957d90518a536513f89d760ddb24afb6`.
The run executed from 11:37 to 17:26 UTC on 2026-10-21. BitBake reported
719 sstate-cache misses out of 719 wanted entries, explaining why the cold
build required almost six hours. The runner had 86 GB free when inspected
before the build; disk exhaustion was not observed.

The expensive package workflow is now **manual-only**, has a pre-build disk
capacity check, and can run on an explicitly provisioned `watch3-yocto`
self-hosted runner with persistent Yocto download and shared-state caches.
A standard hosted runner remains an opt-in choice. The full compiled plugin
was not uploaded as a binary, only diagnostic metadata. No rootfs image or
flashable firmware was produced by this package test.

### CPU-rendered Wayland shared-memory scenegraph gate

Pinned QtWayland 6.11.3 `src/compositor/compositor_api/qwaylandquickitem.cpp`
has an explicit `ref.isSharedMemory()` path. It reads CPU pixel data via
`buffer.image()`, calls `createTextureFromImage()`, and paints the view
using `QSGSimpleTextureNode`. This is source-level evidence that
`wl_shm` client frames have a non-EGL texture route. The Qt Quick software
renderer cannot render `ShaderEffect`, which motivated the two
machine-scoped launcher-mask patches.

The new [fast host Qt software texture smoke](https://github.com/UglyGameFace/Galaxy-3/actions/workflows/watch3-r08-qt-software-texture-smoke.yml)
checks those pinned source contracts and then compiles a small host Qt Quick
harness. It uses a deterministic CPU-memory image, `QT_QUICK_BACKEND=software`,
a virtual X11 display and `QSGSimpleTextureNode`, and asserts actual pixels
via `QQuickWindow::grabWindow()`. The user reports that the corrected GitHub Actions host smoke **passed** on 2026-10-21. Its successful run ID was not independently retrieved in this session. This is not evidence of a Wayland protocol exchange.

The host runner's system Qt differs from the target Qt 6.11.3 and the
test does **not** run a Wayland compositor/client protocol exchange, mount
`/dev/fb0`, or install the actual ARM64 plugin. A future true
`wl_shm` compositor/client smoke must prove buffer handoff, startup,
and that the right QPA plugins are installed in the target rootfs before
any hardware test. Do not interpret a host pixel-test pass as proof of a
working watch UI.

References:
- https://github.com/qt/qtwayland/blob/6.11.3/src/compositor/compositor_api/qwaylandquickitem.cpp
- https://doc.qt.io/qt-6/qtwaylandcompositor-index.html
- https://doc.qt.io/qt-6/qtquick-visualcanvas-adaptations-software.html

The [off-device QtWayland `wl_shm` round-trip test](watch3-r08-wayland-roundtrip-gate.md) **passed in GitHub Actions run #39695926149** on 2026-10-21. The real compositor observed a client's shared-memory frame and captured its expected pixels using Qt Quick's software renderer. This is host Qt 6.2.4 under Xvfb; target ARM64 Qt 6.11.3, rootfs integration, `/dev/fb0` and watch boot remain untested.
