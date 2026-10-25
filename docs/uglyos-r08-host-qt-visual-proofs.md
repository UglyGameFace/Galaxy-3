# UgLy|OS R08 watch-face visual previews

This is the first OFF-DEVICE rendered-image validation for the optional Orbit,
Focus and Signal QML watch faces.

Run the GitHub Actions workflow named UgLy|OS R08 host Qt visual proofs
(NO DEVICE). Host PySide6 Qt 6.8.3 with the software backend loads the
three REAL and unchanged watch-face source QML files.

The job creates 15 preview PNGs (360px active 12/24-hour, ambient,
nightstand and 240px compact cases), plus a JSON report with checksums,
highlight counts and color buckets. Round alpha masking approximates the
Watch3's circular panel. Screenshots are not hardware screen captures.

All data is MOCKED: the tiny Nemo.Mce fixture provides a fixed 73%
battery percentage, while a fixed time (October 25, 2026 at 15:42),
the time-format preference, ambient/nightstand booleans and the burn-in
offset manager are injected as host QML context properties. This is NOT
a tested sensor or a replacement AsteroidOS module.

CI must fail if QML loading warns or errors, images are blank, offsets
are wrong, or 12/24h and ambient variants do not visually differ.

This does NOT prove target AsteroidOS Qt 6.11 imports or integration, Watch3
framebuffer, performance, brightness, real always-on display, rootfs
installation, hardware boot, recovery, or flashing. No device writes.

No second watch-face selector is created. Upstream AsteroidOS Settings
already reads the watchface QML folder through FolderListModel and uses
the existing selected-face configuration key. Upstream launcher behavior
remains unchanged.
