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
- The exact Qt6 LinuxFB QPA plugin must be built and installed in the target image.
- The AsteroidOS Lipstick/QtWayland compositor must be checked for shader and Wayland buffer compatibility with software rendering.
- CPU rendering might be slow and increase power usage.
- The stock boot chain and recoverable boot method are still unverified. Never flash this image.

## Next verification

The off-device AsteroidOS preflight has unpacked `asteroid-launcher-configs`
and matched the effective `10-platform.conf` to the Watch3 file. The subsequent
Qt package metadata test checks the R08 recipe's LinuxFB feature and plugin
installation dependencies; it still does **not** build `libqlinuxfb.so`,
run a compositor/client rendering test, or verify the physical watch framebuffer.

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

Other effects exist, including launcher speed-dial effects and watch-face
shaders. Their software compatibility is still unresolved; do not mark the
full GUI operational from this patch alone.

Official reference: https://doc.qt.io/qt-6/qml-qtquick-shadereffect.html

### Runtime plugin and Wayland client integration (in progress)

The official AsteroidOS launcher declares `qtwayland-plugins` as a runtime
dependency. In Qt6 meta-qt6, the QPA plugins live in a separate
`qtbase-plugins` package. R08 now explicitly adds `qtbase-plugins` to the
launcher's runtime dependencies, with CI inspecting effective `bitbake -e`
metadata for `qtbase` LinuxFB/GUI `PACKAGECONFIG`, the plugin packaging
mapping and launcher package dependencies. This is **not** proof the plugin
has actually been compiled or included in the final root filesystem.

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

Remaining validation gates: real BitBake metadata CI success, compiled QtBase
`libqlinuxfb.so` installed in an R08 package/rootfs, a software QtWayland
compositor+client `wl_shm` runtime test, and ultimately non-destructive
physical display testing after recovery/boot is independently verified.

References:
- https://github.com/AsteroidOS/meta-asteroid/blob/master/recipes-asteroid/asteroid-launcher/asteroid-launcher_git.bb
- https://github.com/AsteroidOS/meta-asteroid/blob/master/recipes-asteroid/asteroid-launcher/asteroid-launcher/asteroid-launcher.service
- https://github.com/YoeDistro/meta-qt6/blob/6.11/recipes-qt/qt6/qt6.inc
- https://doc.qt.io/qt-6/qtwaylandcompositor-index.html
