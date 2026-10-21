# R08-only adjustment of the pinned official AsteroidOS launcher.
# Qt software rendering skips ShaderEffect; avoid a compositor-wide
# round-mask shader on physical round display without affecting other watches.
FILESEXTRAPATHS:prepend:noblesse-r08 := "${THISDIR}/asteroid-launcher:"
SRC_URI:append:noblesse-r08 = " file://0001-noblesse-r08-remove-gpu-only-round-mask.patch"

# LinuxFB is a QtBase QPA plugin. Unlike library dependencies, dlopened
# platform plugins are not pulled in automatically by the linker.
# Keep this scoped to R08; upstream already supplies qtwayland-plugins.
RDEPENDS:${PN}:append:noblesse-r08 = " qtbase-plugins "
