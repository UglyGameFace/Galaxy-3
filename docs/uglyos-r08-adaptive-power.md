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
- **Battery & Power > When battery is low** offers two opt-in strategies:
  **Keep wrist wake** disables always-on display but preserves tilt-to-wake,
  following Pixel's usability choice; **Quiet display** disables both where
  supported. Both retain Bluetooth, Wi-Fi and tap-to-wake. The existing
  "extended" behavior is the default for legacy PR #40 opt-ins; new
  users still start with adaptive mode turned off. The profile selector is
  locked while a prior reversible snapshot remains active: stop/restore
  first, then choose a new strategy.
- On **20% or less while discharging**, if neither Solo Saver nor nightstand
  owns the display, the controller saves exactly the controls it intends
  to change in existing Nemo.Configuration storage *before* changing them.
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
- Both strategies use 20% engagement / 30% restoration hysteresis.
  The interface scrolls on the 360×360 round screen. Changing strategy
  while a snapshot exists does not silently rewrite its ownership policy;
  changes take effect after that cycle is restored. More dynamic
  tuning requires measured battery and wake-event evidence.

The launcher is authoritative for automated changes. The Settings page writes
only shared opt-in and profile preferences. It does not start a separate service.
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


## Comparison with major smartwatch power-management approaches

This is a design and capability comparison, **not** a measured battery-runtime
competition. Quoted manufacturer techniques vary by watch generation/model;
newer products have different SoCs, batteries and power domains.

| Watch ecosystem | Manufacturer-documented strategy | R08 UgLy|OS status |
| --- | --- | --- |
| Apple Watch Low Power Mode | Disable AOD; reduce background app refresh and some sensors; limit connectivity as needed | AOD only in our opt-in adaptive mode. Watch3 native background scheduling and sensors not verified |
| Google Pixel Watch Battery Saver | Automatic at 15%; disable AOD and limit background work, but **leave tilt-to-wake enabled** | **Keep wrist wake** retains tilt; optional **Quiet display** disables tilt. Both trigger at 20%, not Google's 15% |
| Samsung Galaxy Watch | Power Saving limits performance/display/radios; separate Watch Only extreme mode | Existing opt-in Solo Saver is a separate manual mode; adaptive saver **does not** disconnect Bluetooth or Wi-Fi |
| Garmin Power Manager | User-editable per-feature/per-activity profiles; estimate savings as switches change | Strong future UX reference; this R08 slice provides two bounded display profiles but **no claimed runtime estimate** |
| Fitbit | Battery guidance emphasizes brightness, AOD, short display timeout and simpler faces | Our existing OLED-black faces/ambient animation limits complement the new AOD behavior, but effects are not measured |

Official references:
- Apple: https://support.apple.com/en-ie/108320
- Google: https://support.google.com/googlepixelwatch/answer/12742648
- Samsung: https://www.samsung.com/us/support/troubleshoot/TSG10007314/
- Garmin: https://support.garmin.com/en-US/?faq=UKdcLjyUEZ4xdiX5HWzgp7
- Fitbit: https://support.google.com/googlehealth/answer/14226518

### Evidence-driven priorities for a later, separately scoped task

1. Future fully custom profiles with separately adjustable AOD and tilt
   controls (the two tested presets are deliberately simpler), while
   maintaining Solo Saver, nightstand and manual-override precedence.
2. Actual per-mode energy/drain and wakeup diagnostics via only verified,
   authorized interfaces. Present estimate ranges only after repeatable same
   device A/B measurements, with clear confidence limits.
3. Reduce costly background work, Bluetooth reconnect churn, wallpaper effects
   and sensor scheduling **only after** verifying their active implementation
   and measurable overhead. Never copy CPU governors or disable safety
   sensors from different hardware.
4. Watch-specific display/CPU/suspend optimizations only after custom boot
   recovery and driver compatibility are independently demonstrated.

Do **not** interpret Garmin multi-day runtimes or Apple/Pixel marketing
comparisons as performance targets proven achievable on the old Exynos 9110.
