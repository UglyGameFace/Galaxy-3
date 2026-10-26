# UgLy|OS R08 only: smoke-only startup GIF prepared from the user-supplied clip.
# The stock AsteroidOS animated GIF remains available as psplash-upstream.gif.
# NO direct bootloader, initramfs script, device flash, or framebuffer modifications.
FILESEXTRAPATHS:prepend := "${THISDIR}/files:"
SRC_URI:append:noblesse-r08 = " file://uglyos-smoke.gif"

do_install:append:noblesse-r08() {
    test -s "${UNPACKDIR}/uglyos-smoke.gif" || { bberror "Missing UgLy|OS smoke GIF"; exit 1; }
    install -d "${D}${datadir}"
    test -s "${D}${datadir}/psplash.gif" || { bberror "Upstream Psplash fallback missing"; exit 1; }
    install -m 0644 "${D}${datadir}/psplash.gif" "${D}${datadir}/psplash-upstream.gif"
    install -m 0644 "${UNPACKDIR}/uglyos-smoke.gif" "${D}${datadir}/psplash.gif"
}

FILES:${PN}:append:noblesse-r08 = " ${datadir}/psplash-upstream.gif"
