SUMMARY = "UgLy|OS R08 lightweight selectable launcher collection"
DESCRIPTION = "Fast List, Compact Grid, Stoner Lounge and Gamer Arcade, R08-only Qt Quick assets"
HOMEPAGE = "https://github.com/UglyGameFace/Galaxy-3"
LICENSE = "MIT"
LIC_FILES_CHKSUM = "file://${COMMON_LICENSE_DIR}/MIT;md5=0835ade698e0bcf8506ecda2f7b4f302"
COMPATIBLE_MACHINE = "(noblesse-r08)"
PACKAGE_ARCH = "${MACHINE_ARCH}"
INHIBIT_DEFAULT_DEPS = "1"
SRC_URI = " file://900-uglyos-fast-list.qml file://901-uglyos-compact-grid.qml file://902-uglyos-stoner-lounge.qml file://903-uglyos-gamer-arcade.qml "
do_configure[noexec] = "1"
do_compile[noexec] = "1"
do_install() {
    install -d "${D}${datadir}/asteroid-launcher/applauncher"
    for layout in 900-uglyos-fast-list.qml 901-uglyos-compact-grid.qml 902-uglyos-stoner-lounge.qml 903-uglyos-gamer-arcade.qml; do
        install -m 0644 "${UNPACKDIR}/$layout" "${D}${datadir}/asteroid-launcher/applauncher/$layout"
    done
}
FILES:${PN} = "${datadir}/asteroid-launcher/applauncher/*.qml"
RDEPENDS:${PN} = "asteroid-launcher"

# For this R08 data-only recipe, a single unversioned runtime dependency
# does not justify compiling launcher/Qt dependency packagedata.
# CI must independently verify native IPK Depends and graph cost.
python __anonymous () {
    if d.getVar("MACHINE") == "noblesse-r08":
        deps = (d.getVar("RDEPENDS:" + d.getVar("PN")) or "").split()
        if deps != ["asteroid-launcher"]:
            bb.fatal("R08 launcher-only package must depend on asteroid-launcher")
        d.setVarFlag("do_package_write_ipk", "rdeptask", "")
}
