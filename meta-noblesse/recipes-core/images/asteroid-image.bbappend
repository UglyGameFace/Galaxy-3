# Samsung Galaxy Watch3 (SM-R840X) R08 only.
# The R08 reference kernel is Linux 4.9.59. Modern e2fsprogs 1.47+ creates
# ext4 orphan_file (FEATURE_C12), which the R08 4.9 kernel cannot be assumed
# to understand. Our first offline artifact #40095182440 demonstrably
# included it. Generate a NEW offline image, preserving that original.
#
# Pinned OE-Core image_types.bbclass constructs do_image_ext4 with OVERRIDES
# including "ext4" and invokes mkfs.ext4 -F ${EXTRA_IMAGECMD}.
# Keep the upstream '-i 4096' and only disable this one newer feature.
# Do not affect other machines or non-ext4 images.
EXTRA_IMAGECMD:ext4:append:noblesse-r08 = " -O ^orphan_file"
