# UgLy|OS Fast Launchers: first launcher modernization slice

Device target: Galaxy Watch3 SM-R840 R08, 45 mm. Samsung lists the
Exynos 9110 dual-core 1.15 GHz, 1GB RAM, 8GB storage, 360x360 Super AMOLED
screen, and 340mAh battery. This design is limited to that reference machine.

Fast List provides readable app names and one-tap access. Compact Grid
shows a 2-column icon-and-label layout. Both are optional and use the
pinned upstream AsteroidOS launcherModel object and launchApplication
method. They do not replace AsteroidOS Settings or its launcher list.

The existing Settings LauncherPage uses FolderListModel over
file:///usr/share/asteroid-launcher/applauncher, discovers *.qml,
and stores selection in /desktop/asteroid/applauncher. The R08-only
uglyos-launchers recipe installs exactly two optional QML files in that
folder and adds them to the machine's offline image package list.
Stock 000-default-horizontal.qml stays selected by default.

Optimization choices: virtualized ListView/GridView, 0.55-viewport
delegate cache, text ellipsis, OLED dark surfaces, no shader effects,
DropShadow, timers, particle systems, continuous animation or networking.
Themes reuse /desktop/uglyos/appearance/accent.

Host rendering uses a FAKE ten-item application model, mock icons and
Nemo.Configuration, and proves six 360px/240px screenshots and a fake
app-click callback. It does NOT measure RAM, frame rate, battery drain
or the actual Watch3 display. Those require hardware testing.

The machine's current Linux 4.9.59 reference kernel and ARM64 image
are not known to boot on this device. No flashing, stock recovery
changes, partition writes or sideloading are permitted.

Next work can add opt-in favorites, search, configurable shortcuts,
offline utility apps and phone-assisted features. Performance and
feature-superiority claims over newer watches require real benchmarks.
