# Galaxy Watch3 SM-R840X R08: graphics integration gate

**Research evidence, not proof of device boot or GUI compatibility.**

## Confirmed reference facts

- Read-only Tizen SDB showed `/dev/dri/card0` with Samsung `tgm-drm` and `/dev/mali0`, rather than a proven standard DRM/KMS display pipeline.
- The pinned public Linux 4.9.59 kernel reference is `UsrBinLuna/kernel_samsung_galileo@ec258e12887d37362b59e3291c1d3e5363c24bff`. Its `drivers/gpu/drm/tgm/tgm_drv.c`, near line 284, has `static struct drm_driver tgm_drm_driver`, whose `driver_features` are **`DRIVER_GEM | DRIVER_PRIME`**. It does **not** advertise `DRIVER_MODESET` there.
- This vendor driver also declares Samsung-specific TDM and TBM interfaces (`drivers/gpu/drm/tgm/`), which are not automatically equivalent to standard DRM/KMS scanout.
- AsteroidOS upstream's `recipes-asteroid/asteroid-launcher/asteroid-launcher-configs/10-platform.conf` selects `QT_QPA_PLATFORM=eglfs` with `QT_QPA_EGLFS_INTEGRATION=eglfs_kms`.
- The unmodified AsteroidOS launcher therefore has **no demonstrated rendering path** on the R08 watch. Successfully resolving or building Qt6 recipes says nothing about physical scanout.

## What cannot be assumed

- `DRIVER_GEM | DRIVER_PRIME` is not evidence that DRM modesetting, connectors, atomic KMS, or Qt's EGLFS/KMS device integration work.
- Do not reuse another watch's KMS connector name, panel mode, or modesetting JSON until this hardware is verified.
- Do not equate Samsung's 32-bit Tizen/TDM/TBM/Mali userspace stack with 64-bit AsteroidOS userspace libraries.
- Do not infer that rendering is solved because `bitbake asteroid-image`, `bitbake asteroid-launcher` or an offscreen Qt test passes.

## Next engineering gates (all off-device until a safe boot/recovery route exists)

1. **Display ABI audit:** inspect the R08 device tree, `tgm_drv.c`, TDM/TBM interfaces, Exynos9110 display-controller code, and actual panel wiring. Identify the supported kernel-to-userspace scanout API.
2. **Backend feasibility:** investigate a legitimate KMS/GBM path or another verifiable compatible Qt6 display backend. Do not choose a renderer based only on another Galaxy Watch model.
3. **UI build independently:** build AsteroidOS packages and exercise Qt6 UI headlessly on a supported host, clearly separating package compilation from on-watch rendering.
4. **Input integration separately:** confirm exact touch and rotating-bezel event codes with read-only evidence before creating keymaps. Known event-device paths alone do not establish key codes.
5. **Hardware test only with recovery:** require a verified full stock backup, signed boot expectations, and a recoverable test route before changing boot/recovery partitions.

Upstream reference sources:

- https://github.com/UsrBinLuna/kernel_samsung_galileo/blob/ec258e12887d37362b59e3291c1d3e5363c24bff/drivers/gpu/drm/tgm/tgm_drv.c
- https://github.com/AsteroidOS/meta-asteroid/blob/master/recipes-asteroid/asteroid-launcher/asteroid-launcher-configs/10-platform.conf

**Status: device-specific graphical display support remains unimplemented and unverified.**
