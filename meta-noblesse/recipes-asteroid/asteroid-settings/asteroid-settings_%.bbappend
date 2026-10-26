# R08-only addition to the *pinned* upstream AsteroidOS Settings watchface page.
# Uses the existing Nemo.Configuration store and OptionCycler; no forked app.
FILESEXTRAPATHS:prepend := "${THISDIR}/files:"
SRC_URI:append:noblesse-r08 = " file://0001-uglyos-watchface-accent.patch"
SRC_URI:append:noblesse-r08 = " file://0002-uglyos-launcher-effects.patch"
# Pair watch-side previews with a usable Settings page on the R08 machine.
SRC_URI:append:noblesse-r08 = " file://0003-uglyos-notification-preferences.patch"
# Watch-Only Solo Saver controls are sourced from pinned upstream radio/display interfaces.
SRC_URI:append:noblesse-r08 = " file://0004-uglyos-solo-saver.patch"
