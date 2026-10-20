SUMMARY = "Experimental Samsung NOBLESSE R08 reference Linux kernel"
DESCRIPTION = "Off-device kernel research only; no Watch3 flash or recovery validation."
HOMEPAGE = "https://github.com/UsrBinLuna/kernel_samsung_galileo"
SECTION = "kernel"
LICENSE = "GPL-2.0-only"
LIC_FILES_CHKSUM = "file://COPYING;md5=d7810fab7487fb0aad327b76f1be7cd7"
COMPATIBLE_MACHINE = "^noblesse-r08$"

inherit kernel

# Historical public Samsung source mirror, NOT verified identical to R840XXXU1AUA2.
SRC_URI = "git://github.com/UsrBinLuna/kernel_samsung_galileo.git;protocol=https;branch=master"
SRCREV = "ec258e12887d37362b59e3291c1d3e5363c24bff"
LINUX_VERSION = "4.9.59"
PV = "${LINUX_VERSION}+git${SRCPV}"
KERNEL_VERSION_SANITY_SKIP = "1"
# Use modern OE-Core default unpack path; kernel.bbclass stages this into STAGING_KERNEL_DIR.
S = "${UNPACKDIR}/${BP}"
B = "${WORKDIR}/build"

# Match the successful stand-alone R08 reference configuration.
do_configure() {
    install -d "${B}"
    oe_runmake -C "${S}" O="${B}" ARCH=arm64 CROSS_COMPILE="${TARGET_PREFIX}" tizen_noblesse_defconfig
    (
        cd "${S}"
        ARCH=arm64 KCONFIG_CONFIG="${B}/.config" scripts/kconfig/merge_config.sh -m -O "${B}" \
            "${B}/.config" \
            arch/arm64/configs/tizen_noblesse_large_defconfig \
            arch/arm64/configs/tizen_noblesse_brcm_defconfig
    )
    oe_runmake -C "${S}" O="${B}" ARCH=arm64 CROSS_COMPILE="${TARGET_PREFIX}" olddefconfig
    grep -qx "CONFIG_NOBLESSE_LARGE=y" "${B}/.config" || bbfatal "R08 large board configuration missing"
    grep -qx "CONFIG_SOC_EXYNOS9110=y" "${B}/.config" || bbfatal "Exynos9110 config missing"
    grep -qx "CONFIG_DRM_TGM=y" "${B}/.config" || bbfatal "Samsung TGM DRM driver missing"
}

# The historic assembler embeds this upstream-supplied ELF via init/_uh.S.
# O= builds need the ELF reachable relative to the build output directory.
do_compile:prepend() {
    install -d "${B}/init"
    test -s "${S}/init/uh.elf" || bbfatal "Upstream UH ELF missing"
    ln -sf "${S}/init/uh.elf" "${B}/init/uh.elf"
}

# GCC11 warning compatibility for historical 4.9 tree, for exploratory builds.
# Real compiler/linker errors remain fatal. Needs review before production use.
EXTRA_OEMAKE:append = " KCFLAGS=-Wno-error"

# BitBake parsing/build and device boot remain UNTESTED at this milestone.
