# R08-only adjustment of the pinned official AsteroidOS launcher.
# Qt software rendering skips ShaderEffect; avoid a compositor-wide
# round-mask shader or per-window GPU masking on the physical round display.
FILESEXTRAPATHS:prepend:noblesse-r08 := "${THISDIR}/asteroid-launcher:"
SRC_URI:append:noblesse-r08 = " file://0001-noblesse-r08-remove-gpu-only-round-mask.patch file://0002-noblesse-r08-disable-app-window-mask-layer.patch"

# LinuxFB is a QtBase QPA plugin. Unlike library dependencies, dlopened
# platform plugins are not pulled in automatically by the linker.
# Keep this scoped to R08; upstream already supplies qtwayland-plugins.
RDEPENDS:${PN}:append:noblesse-r08 = " qtbase-plugins "

# R08-only notification privacy, adjustable preview time and correct Dismiss.
SRC_URI:append:noblesse-r08 = " file://0003-uglyos-notification-previews.patch"

# Resident event-driven adaptive saver; reuses Mce gauge, no timer or radio changes.
SRC_URI:append:noblesse-r08 = " file://0004-uglyos-adaptive-battery.patch"
