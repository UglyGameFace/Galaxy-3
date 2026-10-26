# UgLy|OS R08: live Battery & Power check and conservative adaptive saver

Target: Galaxy Watch3 SM-R840X, experimental AsteroidOS, pinned `noblesse-r08`.

**OFF-DEVICE SOURCE ONLY.** Existing stock Tizen battery observations (71% to
68% over 34.7 minutes with Wi-Fi/debugging active) prove only that the read-only
sysfs collector works. That sample cannot establish UgLy|OS power savings.
The custom OS is not safely booted, the new QML controls are not physically
validated, and stock firmware recovery remains unproven. Do not flash.

## Built on existing controls

- Under **Settings > Battery & Power**, the readout uses actual MceBatteryLevel
  rather than a simulated drain estimate. It shows current AOD and tilt-to-wake
  configuration and whether adaptive mode is enabled or has a saved snapshot.
- **Adaptive saver** is **Off by default**. When enabled, the resident pinned
  launcher watches the system battery percentage and charge-status signals.
  No background Python, network telemetry, cron, JS polling, interval timer,
  continuous shader or repeated SDB connection is introduced.
- On **20% or less while discharging**, if neither Solo Saver nor nightstand
  owns the display, the controller saves prior AOD/tilt states in existing
  Nemo.Configuration storage *before* disabling enabled AOD/tilt controls.
  A missing sensor capability is not treated as a functional switch.
- On reaching **30% or more**, plugging in, or disabling adaptive mode, the
  controller attempts to restore only settings it previously changed. If
  the user has already turned a setting back on, the restore avoids switching
  it off again. Solo Saver and nightstand take precedence until inactive.
  Settings intentionally never claims a switch was successful without its
  upstream driver acting on it.
- **Bluetooth, Wi-Fi, phone notifications, tap-to-wake, vibration, network
  settings and audio are not touched.** There is no untested CPU governor
  adjustment or battery-life forecast.
- The profile is intentionally fixed at 20% engagement / 30% restoration
  for the first safe slice. More sophisticated tuning requires measured
  battery and wake-event evidence on a *working* R08 AsteroidOS watch.

The launcher is authoritative for automated changes. The Settings page writes
only the shared opt-in preference. It does not start a separate service.
The saved snapshot persists across process restarts to avoid losing the
previous AOD/tilt state. If an interrupted or corrupted snapshot is found,
the policy fails closed instead of guessing how to restore. Recovery of that
rare state will require diagnosing the stored configuration first.

## Source and test gates

- Settings extends pinned AsteroidOS `main.qml` *after* the four existing
  R08 overlays, via `0005-uglyos-adaptive-battery.patch`. The upstream
  Settings homepage and previous Solo Saver remain intact.
- Pinned launcher `MainScreen.qml` gets the resident event-driven controller
  via `0004-uglyos-adaptive-battery.patch`; existing AOD, nightstand,
  QuickPanel and notification implementations remain authoritative.
- On-host regression tests execute the **real extracted QML JavaScript policy**
  against mocked battery, charger, Solo and nightstand state, not an unrelated
  reimplementation of the logic.
- CI must apply all overlays in order against the exact upstream commit,
  check the resulting diff, and run compatibility regressions.
- A compiled Qt/Yocto Settings/launcher package, physical Watch3 operation,
  driver response, recovery and **measured battery savings remain unverified**
  after source CI. No `opkg install`, SDB write, device flash or OTA enabled.

## Limitations and what comes next

Optimizing a watch "perfectly" cannot be validated by one 34-minute Tizen test
or by software settings alone. Screen, radio, kernel suspend, display driver,
scheduler, battery aging and usage pattern all matter. This conservative
mode only removes avoidable display wake load if those controls actually work
on the Watch3 once UgLy|OS runs. It does not replace proper A/B benchmarking.

First physical validation requires verified custom boot + full stock recovery,
followed by actual gauge/control readback and a short test, before any claims of
hours saved. Longer measurement remains useful for accuracy but is **not a
blocker to off-device feature development**.
