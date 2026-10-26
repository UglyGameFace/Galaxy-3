SUMMARY = "UgLy|OS App Hub offline native catalog for R08"
DESCRIPTION = "Native Qt 6 App Hub browsing and compatibility info; no installer"
HOMEPAGE = "https://github.com/UglyGameFace/Galaxy-3"
LICENSE = "MIT"
LIC_FILES_CHKSUM = "file://${COMMON_LICENSE_DIR}/MIT;md5=0835ade698e0bcf8506ecda2f7b4f302"
COMPATIBLE_MACHINE = "^noblesse-r08$"
PACKAGE_ARCH = "${MACHINE_ARCH}"

# Mirrors the pinned meta-asteroid asteroid-app.inc Qt6 build conventions,
# but keeps this repository-owned package entirely R08-only.
inherit qt6-cmake
DEPENDS += "qml-asteroid asteroid-generate-desktop-native qttools-native qtdeclarative-native"

SRC_URI = " \
    file://CMakeLists.txt \
    file://main.cpp \
    file://main.qml \
    file://HubPage.qml \
    file://HubCatalog.js \
    file://uglyos-app-hub.in \
    file://uglyos-app-hub.desktop.template \
    file://i18n/uglyos-app-hub.desktop.h \
"
S = "${UNPACKDIR}"
FILES:${PN} += "${libdir}/uglyos-app-hub.so"
# Native invoker/Qt Asteroid app runtime remains the upstream dependency model.
# No lifecycle scripts, opkg code, services, root access or update feeds.
