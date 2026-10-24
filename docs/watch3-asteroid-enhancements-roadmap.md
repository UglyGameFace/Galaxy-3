# UgLy|OS: Enhanced AsteroidOS, not a replacement OS

**2026-10-24 · Owner direction:** preserve the real AsteroidOS/OpenEmbedded
foundation, keep the working experimental `noblesse-r08` integration, and
develop our own highly customizable **UgLy|OS** edition on top.
**UgLy|OS** is the exact user-facing name (including `|`); `uglyos` is the
safe machine identifier for paths, packages, services and automation.
The edition is **based on AsteroidOS**, with upstream licenses, credits and
update boundaries retained. This naming does NOT mean it has booted.

**Current physical status:** a validated *offline* ARM64 AsteroidOS ext4
exists; Android-to-Watch3 Tizen SDB can read runtime evidence. The 4.9.59
reference kernel and partition 20 as dm-0 backing have been verified.
**No supported/verified custom bootloader method or full stock recovery
route has been demonstrated. No installation or device writes.**

## Upstream baseline we keep

The AsteroidOS upstream recommended stable release is **2.1** (April 2026).
The repository's reproducible source build currently pins **meta-asteroid
1af66a6188f7909303cfcec779c8475be1bc4679**, which is Qt 6 migration
code, and **asteroid-launcher 0ba0eb50a68fc6f1019312d511ec3e2fd1b48f31**
from that recipe. Do not silently switch to upstream master or the official
2.1 image. Preserve exact source revisions and test each upstream import.

Already upstream, not features to promise as original innovations:
- Always-on Display, tilt/palm gestures (when hardware supported)
- Several selectable launcher layouts, wallpapers and watchfaces
- Configurable quick-settings toggles, nightstand, timers, alarms
- Android notifications/phone sync, weather and music control
- Device-oriented performance/power management and initial step support

Official upstream references:
- https://asteroidos.org/news/ (2.1 / 2.0 releases)
- https://wiki.asteroidos.org/index.php/Frequently_Asked_Questions_(FAQ)
- https://github.com/AsteroidOS/asteroid-launcher
- https://github.com/AsteroidOS/asteroid-settings
- https://github.com/AsteroidOS/AsteroidOSSync

## Architecture: enhancements without breaking upstream

1. **Keep upstream apps and services.** Add packages, overlays or narrowly
   scoped bbappends under `meta-noblesse`. Never wholesale-copy and abandon
   the real upstream launcher, Settings, notification daemon or Qt components.
2. **Opt-in selection.** The first face pack installs additional .qml assets
   in the exact upstream directory. The existing Settings watchface selector
   discovers them; current default stays unchanged. If features are not
   installed or supported, revert to stock behavior.
3. **Make reusable components later.** Give appearance a shared semantic
   theme interface (accent, surfaces, type scaling, contrast, ambient palette)
   with accessible dark/light variants, controlled per-feature profiles.
   Don't hardcode one person's preferred green theme for every user.
4. **Cap CPU/wakeups.** Favor declarative, data-bound Qt Quick controls;
   never run continuous animation on AOD, and preserve burn-in protection.
   Physical Exynos 9110 and RAM/battery usage must eventually be profiled.
5. **Respect hardware capability flags.** No imaginary NFC wallet,
   certified ECG/BP feature, cellular modem, sensor stream, GPS location
   or audio pipeline. Read actual device capabilities; use graceful fallbacks.
6. **Privacy and offline-first.** Data retention is local by default;
   explicit permission for syncing fitness, maps, assistant and photos;
   no ad IDs, trackers or undisclosed telemetry.
7. **Versioning and updates.** Keep upstream pins, feature-specific CI,
   package version changes, reproducible artifacts and signed/rollback-aware
   upgrades only when a safe Watch3 boot+recovery path has been proven.

## Feature queue (scoped by feasibility, not wishful marketing)

| Order | Area | Target experience | Dependency / truth gate |
|---|---|---|---|
| 1 | Face pack | Orbit, Focus, Signal, selectable from upstream Settings | QML syntax/package and **actual rendering** off-device; this PR includes source/package contracts only |
| 2 | Theme engine | Accent palettes, OLED colors, size/contrast, high legibility, icon/shape styles | Shared QML controls, no multiple conflicting Settings stores |
| 3 | Home/launcher | Layout choices, pinned favorites, folders, quick access, swipe navigation | Use existing launcher model/gesture framework |
| 4 | Complications | Battery, date, weather, notifications, events, phone link | Bind to real existing services; no fabricated metrics |
| 5 | Widgets & quick panel | Configurable tiles, routines, profiles and contextual actions | Validate current settings schema and permissions |
| 6 | Phone companion | Notification actions, media, camera shutter, find phone, navigation prompts | Extend AsteroidOSSync with compatible Android permissions; test BLE stability |
| 7 | Apps | Lightweight offline notes, reminders, calculator, task list, navigation viewer, richer music | Storage and input usability; no dependence on vendor Play Services |
| 8 | Health and fitness | Goals, workout timers, history, steps and heart rate | Verify actual sensorfw inputs, permissions, calibration and accuracy |
| 9 | Advanced interactions | Rotating bezel, haptics, hardware keys, accessibility modes | Physical input and backlight drivers functioning on Watch3 |
| 10 | Optional smart features | Phone-assisted voice assistant, AI summaries, automation, watch-to-phone handoff | User consent, secure networking, microphone/phone limitations |
| 11 | Developer experience | Extension SDK, approved community themes and optional app catalog | Reproducible package/signature design, sandbox/permissions, storage |
| 12 | System upgrades | Tested app updates, safe OTA and reliable rollback | **BLOCKED by verified install, bootloader, signed update & stock rescue** |

### Explicit limitations compared with flagship watches

The Watch3 is not magically a modern certified medical or payment device.
Third-party Samsung Pay / Google Wallet security, ECG/blood pressure regulatory
equivalence, missing cellular hardware, and newer radios cannot be supplied
just by writing QML. Hardware-dependent features remain disabled until
the needed chips and kernel drivers are verified. Remote AI/voice features
can use the Android phone rather than pretend cloud inference is free on a
small 2020-era watch.

## First software slice: optional UgLy|OS watchface assets

Under `meta-noblesse/recipes-asteroid/watch3-faces`:
- `900-watch3-orbit.qml` uses an OLED-friendly dark green accent and
  displays **UgLy|OS** as its nameplate;
- `901-watch3-focus.qml` uses a calm monochrome presentation;
- `902-watch3-signal.qml` uses high-contrast amber sport styling.

All bind to **real** `wallClock.time`, 12/24h `use12H.value`,
`MceBatteryLevel.percent`, `displayAmbient`, `nightstand`, and the
existing `burnInProtectionManager`. No GPU shader masks, heavy animations,
network access or fabricated health information.

The R08-only `watch3-faces_1.0.bb` packages these files and installs
`/usr/share/uglyos/edition.json` containing the exact display name, safe
identifier, base OS credit and experimental/non-flashable status, without patching
the actual launcher and the image recipe appends `watch3-faces` only for
`noblesse-r08`. Existing watchface selection and originals remain intact.

**Status is SOURCE COMPLETE / HOST-CONTRACT TESTED ONLY after CI passes.**
The new package has not yet been built inside the real Yocto image, rendered
under our Qt 6 software-only compositor or run on a watch. Do not describe
the watchfaces as deployed or flash-ready. Next slice should perform a cheap
pinned OE/BitBake parse and package-install test before any full image rebuild.

## Single active task rule

The current priority is **optional AsteroidOS personalization foundation**.
The unrelated partition-label inventory branch can remain parked; avoid
mixing bootloader research, NFC/audio/fitness, and face-pack development
within the same PR. The hardware installation gate stays documented and
is not waived by improving the graphical interface.
