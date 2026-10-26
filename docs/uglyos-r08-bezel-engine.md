# UgLy|OS Bezel Engine: shared input and application contract (R08)

**Status:** native Qt6 Bezel Lab app source and deterministic shared engine implemented
in the repository, **not installed**, **not hardware-tested**. The Galaxy Watch3
remains on Tizen; the experimental UgLy|OS image is not safe to flash until
real stock recovery, signed boot acceptance, display and input integration
are independently verified. No operator can currently control the watch or
a connected Android phone from this source package.

## Hardware proof, not guesswork

The user's SM-R840X Tizen SDB reconnaissance identified a rotating-bezel
device at `/dev/input/event18`, and a button device at `event17`. Those
are **observed current-node numbers**, not guaranteed persistent kernel paths.

The pinned Samsung Exynos 9110 reference:
- [R08 device tree](https://github.com/UsrBinLuna/kernel_samsung_galileo/blob/ec258e12887d37362b59e3291c1d3e5363c24bff/arch/arm64/boot/dts/exynos/exynos9110-tizen_noblesse_large_bt-r08.dtsi)
  contains `compatible="tizen_detent"`, hall GPIOs and `KEY_BACK`.
- [Samsung tizen_bezel.c](https://github.com/UsrBinLuna/kernel_samsung_galileo/blob/ec258e12887d37362b59e3291c1d3e5363c24bff/drivers/input/misc/tizen_bezel.c)
  calls `input_report_rel(..., REL_WHEEL, direction)`, `direction=+1`
  for CW and `-1` for CCW, **and also reports REL_X**. Do not interpret
  REL_X as a second wheel event.
- [Samsung bezel UX guidance](https://developer.samsung.com/one-ui-watch-tizen/interaction/bezel.html)
  describes 24 mechanical detents, 15° each, one incremental control step.

These vendor sources are the input protocol reference, **not proof** that
the as-shipped kernel or experimental Qt6 compositor delivers `QWheelEvent`.
Any orientation or natural-scroll inversion must be checked physically.
Do not seize the Linux event device, map power-key hold as a shortcut, or
spawn a privileged input daemon without separate authorization and evidence.

## Single canonical engine

`meta-noblesse/recipes-asteroid/uglyos-bezel-lab/uglyos-bezel-lab/BezelEngine.js`
is the **one source of truth** for all pure processing. Source tests use the
**exact file** in a Node VM, with `.pragma library` removed for Node loading.
The native QML page imports the same module.

- `normalizeEvdev(type,code,value,time)` accepts only `EV_REL=2/REL_WHEEL=8`,
  bounded integer direction/steps and timestamps. `REL_X=0`, unknown key
  codes and bogus events are ignored.
- `apply(state,event)` is pure. Default/local ring navigation is fixed one
  item per detent. Acceleration is permitted only in the 0–100 precision dial,
  bounded 3x after fast successive event timestamps.
- Local contexts `everyday`, `gaming`, `work`, `accessibility` are
  user-selected, not inferred from unverified foreground app access.
- Circular 24-position game/inventory selector, character-by-character rotary
  keyboard, bounded timeline controls and cumulative virtual dial are local.
  They don't transmit data to Android, games, Discord or arbitrary services.
- Gesture capture is **explicitly armed**; 2–8 steps, 2-second session window,
  up to 6 stored bindings, assigned only to allowlisted local destinations.
  A positive user confirmation is required; ordinary scrolling never fires
  hidden macros. `Nemo.Configuration` stores only these small local patterns,
  with rigorous parsing of restored values.
- In Bezel Lab, **MODE** explicitly selects local everyday/gaming/work/
  accessibility contexts, while **INVERT** calibrates rotation direction
  as a saved preference. The gestures screen has **RECORD**, **RUN** and
  **TARGET** controls for manual recording, replay and local target selection.
  This is not a hardware power-button hold integration. A future verified
  logical button modifier can move between those same local contexts.
- The app's `WheelHandler` listens only while Bezel Lab owns the page.
  App-local Qt Enter/Select/Back bindings and visible touch controls are
  debug/accessibility alternatives, not claims that the R08 buttons work.
  The UI is event-driven: no polling, continuous particle animation, GPU
  ShaderEffect or added wake loops.
- `remoteIntent` is deliberately inert: it recognizes future action names
  but **never** queues or sends remote commands. Phone companion, consent,
  permissions, BLE trust, confirmation and authorization must exist first.

The native `uglyos-bezel-lab_0.1.bb` recipe follows the existing pinned
AsteroidApp6 CMake/desktop/invoker pattern and targets only `noblesse-r08`.
It is deliberately **not added to IMAGE_INSTALL** until native compile and
hardware input dispatch are verified. Source checks do not equal an IPK build.

## All requested features and truth-in-status

The complete machine-readable matrix is `bezel/features.json` (22 entries).
A status of `engine-implemented` means **off-device source and tests**, not
that a bezel interaction has ever been demonstrated on the physical watch.

**Local source implemented:** ring browsing/selection, gesture language and
recording, safe context switching, bounded precision dial, 24-step gaming
selector, rotary keyboard, local timeline, endless logical dial, local
accessibility key fallback and Bezel Lab app UI.

**Pending actual input hardware verification:** physical event-to-Qt adapter,
OS-wide/default scrolling, button combinations (especially any power-key
hold), haptic navigation and accessible eyes-free interactions. No fake
pressure sensing, detent resistance or precise absolute-angle tracking.

**Pending Android companion and permissions:** remote camera controls,
multimedia scrub, Android/PC/game input, Minecraft, navigation prompts,
Discord/home automations and remote notifications. No fake notification
history. A separate bounded, authenticated, opt-in protocol with per-action
permission, current app/session scope and acknowledgments is needed.
No phone-side background surveillance, unapproved Discord automation or
control of other apps is authorized merely by rotating the watch.

**Pending visual optimization:** stoner smoke swirls and gamer holograms
only during interaction, with GPU/software-backend fallback and watch
battery/performance budgets. Don't run a constantly animating background
to show off a power-saving watch.

## Next input proof: instant, read-only Termux capability report

Run **after this PR merges** using the watch's current trusted-network address:

```bash
cd ~/Galaxy-3 && git pull --ff-only
python tools/watch3_r08_android_sdb.py \\
  --watch-ip 10.54.86.131 --bezel-only
cat ~/watch3-r08-bezel-redacted.json
```

The phone-to-watch SDB call executes precisely one allowlisted shell command:
`cat /proc/bus/input/devices`. It **does not open input event nodes**,
read keypress history, set permissions, run apps or flash any partition.
The parser selects one exact `N: Name="tizen_detent"` device and discovers
its current `eventN` handler instead of hardcoding `event18`. It checks
the Linux capability bitsets `B: EV` and `B: REL`, including
`EV_REL=2` and `REL_WHEEL=8`. No other devices, serials, product IDs,
physical paths, raw bitmaps or keys are saved.

`BEZEL_REL_WHEEL_ADVERTISED` is **only kernel capability evidence**:
it does not mean the watch generated real CW/CCW events, that the
Qt input stack received a wheel event, or that custom OS navigation works.
`BEZEL_CAPABILITY_UNAVAILABLE` means unreadable, missing, ambiguous or
invalid metadata; `BEZEL_WHEEL_NOT_ADVERTISED` means an exact detent device
was found but it did not advertise REL_WHEEL. Neither warrants altering
Tizen system permissions, direct evdev reads or guessing a different path.

If the watch's Wi-Fi IP has changed, replace it. The previously documented
address is just the last observed connection, never a hardcoded identity.

## Gate order for user-safe development

1. Merged PR #43: compile-independent source engine and native app scaffolding,
   test synthetic signed detents, exact Samsung driver code audit and strict
   local-only action boundaries. Keep app **not installed by default**.
2. This PR: verify read-only physical Tizen input capability metadata and
   host Qt WheelHandler delivery independently; then verify Qt6 native IPK
   build and Wayland/LinuxFB startup **off-device**.
3. Verify input device name/EV_REL capability via strictly read-only SDB,
   then verify `REL_WHEEL` under a safe custom boot (after stock recovery
   has been proven); preserve normal swipe/touch navigation.
4. Integrate one **single** user-configurable input dispatcher into the
   actual pinned launcher/Settings without losing normal scrolling.
5. Add hardware button semantics, safe haptic feedback, accessible complete
   interaction navigation, and visible user disable/rollback switch.
6. Only then add an Android companion protocol for camera, media, games,
   haptic turns and automations with explicit permissions and confirmation.
7. Run short real hardware battery and latency measurements before
   promising low-power, high-accuracy rotary control or runtime improvements.

No download from random driver sites, no root shell action, kernel writes,
SDB installs, watch flashing, BLE pairing changes or fabricated benchmarks.
