# Samsung Galaxy Watch3 SM-R840X R08 only.
# Override upstream AsteroidOS compositor's existing 10-platform.conf
# via its documented FILESEXTRAPATHS lookup, not a copied recipe.
FILESEXTRAPATHS:prepend:noblesse-r08 := "${THISDIR}/asteroid-launcher-configs:"

# Refuse silently packaging the upstream eglfs_kms environment file for R08.
# This runs only if the upstream config recipe is built, not at parse time.
do_install:append:noblesse-r08() {
    platform="${D}/var/lib/environment/compositor/10-platform.conf"
    test -s "${platform}" || bbfatal "R08 compositor platform.conf was not installed"
    grep -Fxq "QT_QPA_PLATFORM=linuxfb" "${platform}" || bbfatal "R08 LinuxFB platform override not installed"
    grep -Fxq "QT_QUICK_BACKEND=software" "${platform}" || bbfatal "R08 Qt Quick software backend override missing"
    grep -Fxq "QT_QPA_FB_DRM=0" "${platform}" || bbfatal "R08 DRM fallback must remain disabled"
}

# This upstream recipe installs text environment files and converts a keymap
# using the native kmap2qmap tool. It compiles NO target ARM64 code.
# Avoid unrelated virtual/cross-cc, compilerlibs and libc cold builds on R08.
# KEEP the upstream qttools-native DEPENDS and keys.kmap -> keys.qmap step.
INHIBIT_DEFAULT_DEPS:noblesse-r08 = "1"

# QtTools 6.11 kmap2qmap lacks entries for MenuKB and Sleep in its symbol
# lookup table, although these are valid Qt::Key enum values. This R08-only
# encoder preserves *all six* watch buttons and the exact QDataStream binary
# mapping proven by the host Qt6 compatibility workflow.
# Every other AsteroidOS machine continues using upstream kmap2qmap.
SRC_URI:append:noblesse-r08 = " file://r08-qmap.py"
DEPENDS:remove:noblesse-r08 = "qttools-native"

do_install:noblesse-r08() {
    install -d ${D}/var/lib/environment/compositor/
    install -m 0644 ${UNPACKDIR}/00-default.conf ${D}/var/lib/environment/compositor/
    install -m 0644 ${UNPACKDIR}/10-platform.conf ${D}/var/lib/environment/compositor/
    install -m 0644 ${UNPACKDIR}/20-device.conf ${D}/var/lib/environment/compositor/

    install -d ${D}/usr/share/qt6/keymaps/
    python3 ${UNPACKDIR}/r08-qmap.py ${UNPACKDIR}/keys.kmap ${D}/usr/share/qt6/keymaps/keys.qmap
    test -s ${D}/usr/share/qt6/keymaps/keys.qmap || bbfatal "R08 Qt keymap missing"
}
