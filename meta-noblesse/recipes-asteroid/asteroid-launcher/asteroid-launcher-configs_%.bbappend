# Samsung Galaxy Watch3 SM-R840X R08 only.
# Override upstream AsteroidOS compositor's existing 10-platform.conf
# via its documented FILESEXTRAPATHS lookup, not a copied recipe.
FILESEXTRAPATHS:prepend:noblesse-r08 := "${THISDIR}/asteroid-launcher-configs:"
