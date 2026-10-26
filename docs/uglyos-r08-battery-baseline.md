# UgLy|OS R08: honest battery baseline before larger integrations

**Status:** implemented as off-device Python code and synthetic SDB tests only.
**No physical Watch3 battery reading, UgLy|OS boot, Solo Saver drain result or
stock recovery has been validated. No firmware writes or flash authorization.**

## Hardware and power reference
- Samsung officially specifies Galaxy Watch3 45mm SM-R840 as Exynos 9110 dual
  core 1.15 GHz, 1 GB RAM, 8 GB storage, 360×360 AMOLED, **340 mAh nominal
  battery**. The 41mm SM-R850 has **247 mAh**, so its raw runtime comparison
  is not interchangeable with this 45mm device.
- Samsung's Galaxy Watch Active2 **44mm** is the closest published hardware
  comparison: the same Exynos 9110, 360×360 AMOLED and 340 mAh nominal
  battery, but 768 MB RAM and 4 GB storage in the Bluetooth version versus
  the Watch3's 1 GB/8 GB. Similar hardware is not proof that governors,
  drivers, kernel policy or real-life runtime transfer unchanged.
  Samsung reference: https://news.samsung.com/global/galaxy-watch-active2-designed-to-help-balance-wellness-with-upgraded-connectivity
- AsteroidOS already offers AoD, tilt-to-wake and display management. Its
  documentation explicitly warns that tilt-to-wake can cost battery through
  accidental activations. Our R08 Solo Saver's reversibility is documented in
  [Solo Saver](uglyos-solo-watch-only.md).
- Samsung sources: https://www.samsungmobilepress.com/media-assets/galaxy_watch3?tab=specs
  and https://www.samsung.com/hk_en/news/product/galaxy-watch3-smartwatch/
- AsteroidOS Settings: https://wiki.asteroidos.org/index.php/Settings_Pages

## Safe, Android/Termux-friendly collection

**Current Tizen baseline only.** Use the already implemented authenticated
read-only SDB client, on your private local network with debugging deliberately
enabled. Do not change firmware, root, flash or install another OS.

```sh
cd ~/Galaxy-3 && git pull --ff-only
python tools/watch3_r08_android_sdb.py --watch-ip WATCH_LOCAL_IP --power-only --report ~/watch3-power-start.json
# Use the watch normally, without charging; a longer controlled interval
# makes the coarse 1% battery gauge less misleading.
python tools/watch3_r08_android_sdb.py --watch-ip WATCH_LOCAL_IP --power-only --report ~/watch3-power-end.json
python tools/watch3_r08_power_baseline.py --compare ~/watch3-power-start.json ~/watch3-power-end.json
```

The client executes exactly one fixed read-only shell command:
`cat /sys/class/power_supply/*/uevent`. It does not download or save raw
uevent output. Only a device explicitly identifying as `TYPE=Battery` with
a valid integer `CAPACITY=0..100` is accepted; multiple battery devices,
a missing node, permission denial or missing gauge data fail closed.
The redacted JSON contains percentage, charge state, UTC observation time
and explicit accuracy limits, not the full power-supply details, serial,
network identifiers, private keys or voltage/current estimates.

## Comparison protocol

1. Keep conditions repeatable: same watch, similar room temperature, face,
   brightness, AoD, tilt, Bluetooth, Wi-Fi, app notifications, and activity.
   Write those settings in **local notes**, not in a public GitHub issue.
2. For idle baseline, start/end snapshots **30 minutes to 72 hours** apart.
   Do not charge or intentionally change power modes between snapshots.
   Both must report *Discharging*. The tool rejects negative elapsed time,
   charging snapshots, battery increases, unusable percentages and bad JSON.
3. The result is percentage **points per hour**, not percent of remaining
   capacity, real energy consumption, current draw, battery health or
   a credible whole-day runtime forecast. With no rounded percentage drop,
   the tool reports insufficient resolution, **never zero power draw**.
4. SDB collection requires Wi-Fi/debugging and momentarily perturbs the device.
   These samples cannot reliably measure a Wi-Fi-disabled Solo session or
   provide continuous power traces. A Watch3-specific AsteroidOS build must
   boot safely before Solo Saver A/B comparisons can begin.
5. Later, after supported hardware boot/recovery are demonstrated, repeat
   balanced A/B tests on the **same** watch with matched workloads, number
   of runs and power settings, adding radio/display/wake-signal measurements
   only if those interfaces are actually verified.

## Rollout gates

- Host synthetic tests can prove parser correctness, privacy filtering,
  fixed read-only command selection and arithmetic.
- Physical Tizen power gauge availability must be observed; unavailability
  is a supported outcome rather than a guessed sysfs name or fabricated rate.
- Existing Solo Saver Qt/UI tests, real native package gates and on-watch
  boot/recovery remain independent blockers.
- Do not claim any achieved battery-life improvement over Tizen, AsteroidOS,
  Galaxy Watch Active2, or current smartwatches without comparable test data.
