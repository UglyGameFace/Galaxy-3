SUMMARY = "Optional Watch3 Edition watch faces for AsteroidOS"
DESCRIPTION = "Three low-power, software-Qt-friendly watch faces: Orbit, Focus and Signal"
HOMEPAGE = "https://github.com/UglyGameFace/Galaxy-3"
LICENSE = "MIT"
LIC_FILES_CHKSUM = "file://${COMMON_LICENSE_DIR}/MIT;md5=0835ade698e0bcf8506ecda2f7b4f302"

# Do not ship these board-specific enhancement assets on other watches.
COMPATIBLE_MACHINE = "(noblesse-r08)"
PACKAGE_ARCH = "${MACHINE_ARCH}"
INHIBIT_DEFAULT_DEPS = "1"

SRC_URI = " \
    file://900-watch3-orbit.qml \
    file://901-watch3-focus.qml \
    file://902-watch3-signal.qml \
    file://uglyos-edition.json \
"

do_configure[noexec] = "1"
do_compile[noexec] = "1"

do_install() {
    install -d "${D}${datadir}/asteroid-launcher/watchfaces"
    for face in 900-watch3-orbit.qml 901-watch3-focus.qml 902-watch3-signal.qml; do
        install -m 0644 "${UNPACKDIR}/$face" "${D}${datadir}/asteroid-launcher/watchfaces/$face"
    done
    install -d "${D}${datadir}/uglyos"
    install -m 0644 "${UNPACKDIR}/uglyos-edition.json" "${D}${datadir}/uglyos/edition.json"
}

FILES:${PN} = "${datadir}/asteroid-launcher/watchfaces/*.qml ${datadir}/uglyos/edition.json"
RDEPENDS:${PN} = "asteroid-launcher"
