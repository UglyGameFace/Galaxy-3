# UgLy|OS roadmap and Notification Center 2.0

Target: Galaxy Watch3 SM-R840X R08, based on pinned AsteroidOS.
All software work is **off-device**; custom bootloader acceptance, stock rescue,
physical display/haptics and safe flashing remain **unverified**.

## Verified implemented in the repository

- Custom selectable Orbit, Focus, and Signal watchfaces
- Appearance accents and light touch-effect settings
- Fast List, Compact Grid, Stoner Lounge, Gamer Arcade launchers
- Persistent pinned Favorites Dock across those four launchers (merged PR #32)
- Exact-video smoke boot asset, native Psplash package and early-boot initramfs verification (merged PR #30)
- Offline first-boot NO-GO and recovery evidence gate (merged PR #31)

**Not proved:** any of these custom OS changes actually booting on the Watch3.

## Current, single active task: Notification Center 2.0

### Stage 1: user-facing watch improvements (this PR)
- Fix the actual pinned NotificationView's incorrectly wired Dismiss button:
  request removal instead of invoking the default notification action
- Notification previews: Full text / Title only / Hide content
- Three duration settings: 3, 5 (stock default), 10 seconds
- One Notification settings page in pinned AsteroidOS Settings
- Use the existing Nemo.Configuration store with shared namespaced keys
- Machine-scoped launcher/Settings source patches and pinned-source CI

This is **preview-only privacy**, not a lockscreen authentication system.
Opening a notification deliberately reveals its content. No hardware-side
delivery, OS installation or mobile Bluetooth claim is made.

### Stage 2: watch UI & safety (future)
- Readable, scrollable conversation lists and sensible notification grouping,
  respecting actual notification sender IDs and available metadata
- Better priority/quiet experiences; do not wake the OLED during ambient mode
- Built-in snooze/dismiss-all exists upstream; avoid duplicating it
- Accessibility and long-text readability, with round-screen Qt host proofs
- App controls only after actual Android-side app/package data is available

### Stage 3: Android companion reliability (future, separate architecture)
- Study Gadgetbridge (currently preferred by the upstream quick-start guide)
  and AsteroidOSSync, especially Android 17 Bluetooth foreground services,
  notification permissions, reconnects, idempotent updates, removed entries,
  and privacy/permission prompts
- Preserve compatibility with documented AsteroidOS BLE Notification Profile
- Support selective per-app mirroring and phone DND semantics where Android
  exposes them, using opt-in permissions, NOT broad secret retention
- On Samsung S25 Ultra, validate actual Android Bluetooth restrictions; no
  claim of tested paired hardware before Watch3 has booted AsteroidOS

### Stage 4: interaction protocol experiments (explicitly blocked)
- Direct watch-side quick replies, reply templates, actions, and phone-side
  dismiss acknowledgments require a **tested bidirectional extension**
- Current published Notification Feedback characteristic is not standardized
  for watch -> phone actions. No promise of instant WhatsApp/SMS replies
  until this capability is implemented and tested on both ends.

## Other UgLy|OS work after notifications

1. Smart Hub: fifth optional category-aware launcher. Preparation exists
   but was intentionally paused, not committed or merged.
2. Better configurable quick settings, widgets and supported real complications
   for battery, calendar, phone link, notifications and weather.
3. Android companion sync: reliable media control, phone-finding, camera
   shutter when supported, notification controls and connectivity diagnostics.
4. Offline utility experiences like notes and task management, with a
   keyboard/input design suitable for a small 360x360 round screen.
5. Physical bezel, hardware buttons, accessible haptics and sensor capabilities,
   gated by actual Watch3 kernel/driver evidence.
6. Signed upgrades and rollback, **only after** an independently verified
   install/bootloader/full stock restore method exists.

Do not promise Google Wallet certification, Samsung ECG/BP equivalence,
phone-call answering or cellular hardware that this device/OS cannot provide.

## Technical references

- Watch notification implementation: pinned asteroid-launcher at
  `0ba0eb50a68fc6f1019312d511ec3e2fd1b48f31`
- Watch Settings implementation: pinned asteroid-settings at
  `60340bd1c27a7b9e4884bd61c0563d091bc8b240`
- Upstream BLE specification:
  https://wiki.asteroidos.org/index.php/BLE_profiles
- AsteroidOS Android quick-start:
  https://wiki.asteroidos.org/index.php/Quick_Start_Guide
- Existing site-wide roadmap:
  docs/watch3-asteroid-enhancements-roadmap.md

No installation, flashing or unverified hardware operations are part of
this document or the active notification PR.
