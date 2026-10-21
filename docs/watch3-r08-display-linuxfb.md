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

Run off-device BitBake `bitbake -c unpack asteroid-launcher-configs` and compare
its effective unpacked `10-platform.conf` to the Watch3 layer's replacement,
then inspect the Qt6 package configuration. These steps verify actual recipe
file selection; they do **not** demonstrate a watch framebuffer or a bootable GUI.

Sources:

- https://github.com/UsrBinLuna/kernel_samsung_galileo/blob/ec258e12887d37362b59e3291c1d3e5363c24bff/arch/arm64/configs/tizen_noblesse_defconfig#L2331-L2386
- https://github.com/UsrBinLuna/kernel_samsung_galileo/blob/ec258e12887d37362b59e3291c1d3e5363c24bff/drivers/video/fbdev/exynos/dpu_9110/decon_core.c#L3273-L3287
- https://github.com/AsteroidOS/meta-asteroid/blob/1af66a6188f7909303cfcec779c8475be1bc4679/recipes-asteroid/asteroid-launcher/asteroid-launcher-configs_git.bb
