# UgLy|OS Fast Launchers: first launcher modernization slice

Device target: Galaxy Watch3 SM-R840 R08, 45 mm. Samsung lists the
Exynos 9110 dual-core 1.15 GHz, 1GB RAM, 8GB storage, 360x360 Super AMOLED
screen, and 340mAh battery. This design is limited to that reference machine.

Fast List provides readable app names and one-tap access. Compact Grid
shows a 2-column icon-and-label layout. Stoner Lounge adds a dark pine
420-inspired lounge feel; Gamer Arcade uses cool blue neon panel styling.
All four are optional and use the
pinned upstream AsteroidOS launcherModel object and launchApplication
method. They do not replace AsteroidOS Settings or its launcher list.

The existing Settings LauncherPage uses FolderListModel over
file:///usr/share/asteroid-launcher/applauncher, discovers *.qml,
and stores selection in /desktop/asteroid/applauncher. The R08-only
uglyos-launchers recipe installs four optional QML files in that
folder and adds them to the machine's offline image package list.
Stock 000-default-horizontal.qml stays selected by default.

Optimization choices: virtualized ListView/GridView, 0.55-viewport
delegate cache, text ellipsis, OLED dark surfaces, no shader effects,
DropShadow, timers, particle systems, continuous animation or networking.
Themes reuse /desktop/uglyos/appearance/accent.

Stoner Lounge and Gamer Arcade use a single short ColorAnimation only
during a finger press. The new machine-only Settings Launcher page offers
Off or Subtle effects via /desktop/uglyos/appearance/effects. Effects
are never continuous, and Off disables the touch color tween.

Host rendering uses a FAKE ten-item application model, mock icons and
Nemo.Configuration, and proves 16 360px/240px screenshots and a fake
app-click callback. It does NOT measure RAM, frame rate, battery drain
or the actual Watch3 display. Those require hardware testing.

The machine's current Linux 4.9.59 reference kernel and ARM64 image
are not known to boot on this device. No flashing, stock recovery
changes, partition writes or sideloading are permitted.

## R08 local Favorites Dock (next launcher improvement)

All four selectable UgLy|OS launchers include the SAME optional four-app
dock, backed by /desktop/uglyos/launcher/favorites in the existing
Nemo.Configuration local settings store. **Press and hold** an installed
app tile to pin or unpin it. Long-press never also launches the app.
A single tap still opens the normal application.

The round-screen dock displays one pinned app at a time.
Tap its name to launch, or use the left/right arrows to switch between up
to four pins. If empty, it reads "Hold app to pin" instead of pretending a
favorite exists. This adds no launcher-visible custom app or background service.

The shared JS stores the installed app's upstream LauncherItem.fileID, *not*
a translated title, arbitrary command, or copied app binary. It validates and
deduplicates IDs, never accepts shell/URL input, and resolves pins against
the **currently installed** upstream launcherModel. Uninstalled apps are
silently omitted, while the persisted list stays intact for a later reinstall.
When a fifth app is pinned, the oldest pin drops off.

The existing four layouts and stock launcher picker stay untouched. Qt Quick
uses only bounded list/grid virtualization; no timers, shaders, background
polling or high-power effects. Off-device CI runs JS functional tests,
real 360px Qt Long Press -> Pin -> Dock Click tests using a mock app model,
and checks five exact assets inside the native Yocto IPK.

This is an **off-device software feature**. No saved pins on Tizen or physical
Watch3 performance/persistence has yet been verified. A passing host test
does not establish bootloader acceptance or allow flashing.

Next work can add optional search, configurable shortcuts,
offline utility apps and phone-assisted features. Performance and
feature-superiority claims over newer watches require real benchmarks.
