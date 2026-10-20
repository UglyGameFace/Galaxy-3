SUMMARY = "Non-flashable Linux rootfs research build for Galaxy Watch3 R08"
DESCRIPTION = "Minimal OpenEmbedded userspace for offline ABI/image-build research. NOT AsteroidOS, not boot tested, and not safe to flash."
LICENSE = "MIT"

# Uses OE-Core minimal userspace, not AsteroidOS/Qt. Establish an
# offline arm64 root filesystem baseline before graphics integration.
require recipes-core/images/core-image-minimal.bb

# Keep a plain ext4 image for offline inspection. No bootloader installer.
IMAGE_FSTYPES = "ext4"
IMAGE_FEATURES = ""
IMAGE_LINGUAS = ""

# Boot readiness, signed image compatibility and recovery are unverified.
