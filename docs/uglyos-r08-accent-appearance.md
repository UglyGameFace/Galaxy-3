# UgLy|OS R08 optional accent settings

Keep upstream AsteroidOS Settings. Add an R08-only patch to the existing
Watchface screen using its own OptionCycler. The exact pinned Settings
revision is 60340bd1c27a7b9e4884bd61c0563d091bc8b240.

The selector persists the Nemo.Configuration key
/desktop/uglyos/appearance/accent. The three optional R08 QML faces
read that same key. The original /desktop/asteroid/watchface selector
and the time-format preference are preserved.

Choices: Original, Emerald, Ice, Violet, Ember and Rose. Original
is the default and preserves each face's existing validated colors.
Unrecognized values fall back to Original. The palette applies only
to selected accents, not to the upstream watchfaces.

Host Qt uses fake configuration, time and battery signals to produce
30 PNG previews, including the original 5 display modes plus all 5
custom accent choices on Orbit, Focus and Signal. It does not establish
real device behavior.

The settings-patch CI fetches the exact pinned upstream revision and
runs git apply --check followed by a real source-patch inspection.
Native AsteroidOS Settings binary compilation, Nemo.Configuration
persistence on a watch, full rootfs integration, Watch3 hardware
rendering, boot, recovery, and flashing are NOT VERIFIED.

No device writes are included.
