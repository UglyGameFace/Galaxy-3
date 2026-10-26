# UgLy|OS Solo Saver: standalone battery-focused watch experience

Target: Galaxy Watch3 SM-R840X, experimental AsteroidOS R08.
OFF-DEVICE ONLY: no real device boot, stock recovery, radio test, or battery measurement.

## Watch-only controls

Settings > Watch-only Solo > Go Solo is a 3-second cancelable action.
It uses the pinned upstream interfaces BluetoothStatus, Connman NetworkTechnology,
DisplaySettings, TiltToWake and the existing Always-on Display setting.
The action saves the previous Bluetooth, Wi-Fi, AOD and tilt settings in local
Nemo.Configuration BEFORE switching those functions off. Tap-to-wake remains
unchanged so a missing/unsupported hardware button does not strand the wearer.

Settings > Watch-only Solo > Restore previous re-applies the saved settings.
The Go Solo button cannot overwrite a saved snapshot with already-off values.
Displayed status reflects read-back radios and display settings; it does not
claim success if a driver refuses a change. Wi-Fi is touched only on watches
where DeviceSpecs.hasWlan is true. Turning radios off disconnects phone sync,
notifications and internet: expect that tradeoff.

The mode should reduce certain power loads on supported hardware but the
actual Watch3 battery benefit has not been measured. It is not certified
airplane mode and never runs a background service or polling loop.

## Optional offline watchfaces

Solo Arcade is a 3-step self-reported daily mini-quest: stretch, water break,
move a little. Tap to mark each complete. The date key comes from the existing
wallClock property and expires the progress display naturally next day. This
is NOT a fitness measurement or medically validated reminder.

Solo Lounge is a calmer watchface with local CHILL, FOCUS and GAME selection
on a one-tap mood control. There is no continuous smoke/particle animation.

Both are pure-black OLED-first faces with subdued time/date in ambient or
nightstand, actual clock, 12/24h and battery signals, and the existing burn-in
protection offsets. Interactive areas are absent while dimmed. The existing
face selector and upstream default continue working. These two add to the
three existing optional faces only for machine noblesse-r08.

## CI boundaries

The strict tests verify:
- All four R08 Settings patches apply in order to the exact pinned upstream.
- 50 Qt software-host previews, including ambient and dark states, with
  real local challenge and mood touch tests against mocked watch signals.
- Native source/install/IPK inventories include all five QML assets and
  the upstream-identifying JSON file; no unexpected extra files.
- No kernel rebuild, on-device writes or flash authorization.

Not proved: physical Watch3 AsteroidOS boot, actual Bluetooth/Wi-Fi and
display control behavior, power measurements, wake events, local persistence
on target, Samsung bootloader acceptance, full stock firmware recovery.

UgLy|OS Connect Android companion work is parked separately while this
single watch-only milestone is validated. 
