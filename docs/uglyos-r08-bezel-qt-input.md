# UgLy|OS R08: Qt6 wheel / hall-motion input adapter (off device)

## What is proven on the user's real Galaxy Watch3

On 2026-10-27 00:31 UTC, a read-only SDB report from stock Tizen confirmed
`tizen_detent` with current `event18` handler, `EV_REL`, `REL_WHEEL`
and `REL_X` advertised. The SDB report did **not** capture live rotation.
That event number must not be treated as a stable device path.

The pinned Samsung Exynos 9110 bezel driver sends `EV_REL/REL_WHEEL`
(+1 clockwise, -1 counterclockwise), and auxiliary `EV_REL/REL_X`
hall data. The existing native Bezel Lab (PR #43) passed synthetic
host Qt `QWheelEvent` navigation at 360 and 240 pixels (PR #44).

## Why a Qt-side filter is needed

Pinned [QtBase v6.11.3 qevdevmousehandler.cpp](https://github.com/qt/qtbase/blob/v6.11.3/src/platformsupport/input/evdevmouse/qevdevmousehandler.cpp)
handles `REL_WHEEL` as `angleDelta.y=120*value`, but also treats any
`REL_X` as cursor movement. The [libinput handler](https://github.com/qt/qtbase/blob/v6.11.3/src/platformsupport/input/libinput/qlibinputhandler.cpp)
forwards ordinary pointer-motion and wheel-axis events. The R08
[LinuxFB backend](https://github.com/qt/qtbase/blob/v6.11.3/src/plugins/platforms/linuxfb/qlinuxfbintegration.cpp)
prefers libinput if available and otherwise starts Qt's evdev managers.

Without identifying a bezel separately, the same hardware turn can
produce **both** scroll and stray mouse motion in an embedded Qt GUI.
Setting `QT_QPA_FB_NO_LIBINPUT=1` globally to force a different route
would risk breaking touchscreen/keyboard discovery and is **not done**.

## Single scoped adaptation in source

The `qtbase_%.bbappend` applies only to `noblesse-r08`, targeting
the actual QtBase input implementation; other watches and devices retain
Qt defaults. The one pinned patch covers:

1. **evdev fallback**: Use `EVIOCGNAME` and `EVIOCGBIT(EV_REL)` to
   recognize an **exact `tizen_detent` named, REL_WHEEL-capable device**.
   Only on that device, ignore `REL_X` and `REL_Y` motion, but retain
   normal `REL_WHEEL` to Qt wheel event conversion. On ioctl failure,
   leave upstream behavior unchanged rather than guessing the device.
2. **libinput preferred route**: Recognize exact `tizen_detent` event
   device name. Discard **only pointer motion and absolute pointer motion**
   from it, preserving all scroll-axis events. Real mice, touchscreens,
   keyboard/button input, and other watch devices remain untouched.
3. **No raw event capture or daemon**: This is a normal QtBase input
   backend fix, not an extra service. No event handler index, `chmod`,
   `EVIOCGRAB`, sleep loop, synthetic keypress, firmware modification,
   watch installation or network transport is added.

## Scope and honesty of the CI gate

The fast CI downloads three **unchanged upstream QtBase v6.11.3**
files, applies the real BitBake patch with `git apply --check`, checks
preservation of existing wheel/axis/touch/key calls, and runs synthetic
contract regressions. The device's live SDB capability is *additional
evidence*, not a CI fixture pretending to be on-watch navigation.

The QtBase source patch has **not yet been compiled to target AArch64
through Yocto**, packaged into the real R08 image, or tested on a
working UgLy|OS device. Also **not demonstrated**: whether the
Watch3's bezel is classified by the custom distro's libinput/udev as
a pointer with scroll capabilities, whether the LinuxFB compositor
opens it with adequate permissions, or whether scroll events reach
actual launcher menus and Settings. LinuxFB screen initialization and
watch recovery remain unverified. A host Qt synthetic wheel pass is
not a Linux kernel to Wayland client input-routing proof.

## Next gates in order

1. Run the existing free pinned-source PR CI. Inspect every diff hunk.
2. Stage a separately authorized target QtBase rebuild with the patch
   when sstate/runtime prerequisites justify the cost. Check the
   resulting AArch64 package, Qt input backend configuration and
   dependencies before proposing image integration.
3. After a safely recoverable UgLy|OS boot is independently proven,
   verify real bezel turns generate exactly one scroll action in both
   directions and **zero** stray cursor motion; check normal swipe,
   touch, notifications, Settings and all six existing button mappings.
4. Only after standard scrolling is proven, add opt-in system-wide
   Bezel Engine commands, confirmation shortcuts and haptic support.

This work does **not** authorize flashing or change the stock watch.
