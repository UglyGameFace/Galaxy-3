# R08-only adjustment of the pinned official AsteroidOS launcher.
# Qt software rendering skips ShaderEffect; avoid a compositor-wide
# round-mask shader on physical round display without affecting other watches.
FILESEXTRAPATHS:prepend:noblesse-r08 := "${THISDIR}/asteroid-launcher:"
SRC_URI:append:noblesse-r08 = " file://0001-noblesse-r08-remove-gpu-only-round-mask.patch"
