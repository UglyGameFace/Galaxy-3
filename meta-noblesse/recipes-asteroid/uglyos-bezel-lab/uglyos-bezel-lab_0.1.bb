SUMMARY = "UgLy|OS read-only native bezel interaction lab for Watch3 R08"
DESCRIPTION = "Qt6 Bezel Engine app: local rotary/gesture/navigation interaction; no privileged hardware access"
HOMEPAGE = "https://github.com/UglyGameFace/Galaxy-3"
LICENSE = "MIT"
LIC_FILES_CHKSUM = "file://${COMMON_LICENSE_DIR}/MIT;md5=0835ade698e0bcf8506ecda2f7b4f302"
COMPATIBLE_MACHINE = "^noblesse-r08$"
PACKAGE_ARCH = "${MACHINE_ARCH}"
inherit qt6-cmake
DEPENDS += "qml-asteroid asteroid-generate-desktop-native qttools-native qtdeclarative-native"
SRC_URI = " \
    file://CMakeLists.txt \
    file://main.cpp \
    file://main.qml \
    file://BezelPage.qml \
    file://BezelEngine.js \
    file://uglyos-bezel-lab.in \
    file://uglyos-bezel-lab.desktop.template \
    file://i18n/uglyos-bezel-lab.desktop.h \
"
S = "${UNPACKDIR}"
FILES:${PN} += "${libdir}/uglyos-bezel-lab.so"
# Deliberately NOT added to IMAGE_INSTALL until native-build and hardware
# input mapping are independently validated. No root, evdev grab or flash.
