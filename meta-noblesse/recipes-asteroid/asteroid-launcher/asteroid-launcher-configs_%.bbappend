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
