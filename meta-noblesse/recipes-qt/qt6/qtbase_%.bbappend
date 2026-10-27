# Watch3 SM-R840X R08 only: distinguish Samsung bezel's REL_X hall
# diagnostics from actual REL_WHEEL rotation in BOTH Qt6 input backends.
# Preserve other watches, real mice, touchscreen and hardware keys.
# Never change a global QT_QPA_FB_NO_LIBINPUT setting just to force evdev.
FILESEXTRAPATHS:prepend:noblesse-r08 := "${THISDIR}/qtbase:"
SRC_URI:append:noblesse-r08 = " file://0001-noblesse-r08-tizen-detent-wheel-only.patch"
