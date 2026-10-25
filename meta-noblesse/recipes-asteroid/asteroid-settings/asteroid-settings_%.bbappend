# R08-only addition to the *pinned* upstream AsteroidOS Settings watchface page.
# Uses the existing Nemo.Configuration store and OptionCycler; no forked app.
FILESEXTRAPATHS:prepend := "${THISDIR}/files:"
SRC_URI:append:noblesse-r08 = " file://0001-uglyos-watchface-accent.patch"
