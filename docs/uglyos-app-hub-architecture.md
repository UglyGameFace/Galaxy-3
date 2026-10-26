# UgLy|OS Connect + native App Hub: feasible Google/Samsung integration

Target: Galaxy Watch3 SM-R840X NOBLESSE-LARGE-BT R08.
Research milestone (2026-10-26). **Physical custom OS boot and stock rescue
remain UNVERIFIED. This milestone does not install anything.**

## What an UgLy Store can and cannot be

AsteroidOS is ARM64 Linux/OpenEmbedded/Qt Quick and uses native opkg .ipk
packages. Its wiki explicitly states a graphical app store does not currently
exist. The first goal is an independently verifiable **native watch app catalog
and ultimately a native on-watch store UI**, not Google Play APK installation.

A Google Play or Galaxy Store APK does not run directly in the current
AsteroidOS image. An Android runtime, framework, Play Services,
certification, and architecture/graphics integration are missing.
Simply renaming APK to .ipk is not a port. **Wear OS and Google Wallet are
not supported** and must not appear with Install buttons.

Google's new US Play Catalog Access program (from July 22, 2026) is for
eligible **Android app stores**, with organization verification, fees,
agreements and platform policies. Downloads go through Google Play;
it does not authorize serving Android APKs for native Linux watch use.
Third-party Android app store enrollment is a different track from a
native Linux/opkg app catalog.

Official sources:
- https://wiki.asteroidos.org/index.php/Watchface_and_Package_Installation
- https://wiki.asteroidos.org/index.php/Creating_an_Asteroid_app
- https://support.google.com/googleplay/android-developer/answer/17117200?hl=en
- https://support.google.com/googleplay/android-developer/answer/17118006?hl=en
- https://support.google.com/wearos/answer/12059876

## Google + Samsung integrations: Android phone as the compatibility bridge

Build the future **UgLy|OS Connect** Android companion using the existing
AsteroidOS Bluetooth sync protocol where supported. Reuse protocol work
from Gadgetbridge/AsteroidOSSync, complying with each project's GPL
license obligations if reusing code. New watches paired to Gadgetbridge
need explicit verification of the real device BLE implementation.

- **Notifications (first priority).** Mirror phone notifications with
  opt-in app filters and privacy mode, manage dismiss/action parity
  only when the Bluetooth protocol and Android permission permits.
  Existing UgLy|OS PR #33 improves **watch UI** notification previews,
  privacy settings and Dismiss handling. This does not by itself build
  the Android companion or verify R08 BLE.
- **Google Calendar.** Use Android system calendar integration or a
  properly consented OAuth scope on the *phone*, then send small
  agenda entries to a native watch view. No embedded Google account
  passwords or copied refresh tokens on the watch.
- **Google Maps / navigation.** Phone computes route and turn events
  with authorized APIs; watch renders minimal turn cues and simple
  vibration only after haptics are verified. No claim that
  Google Maps for Wear OS runs on this device.
- **Samsung Health / Google Health Connect.** Samsung documents that
  Samsung Health can sync data to Android Health Connect with the
  user's permission. Start with explicit optional, revocable read
  permission and aggregated step/sleep data in a phone-side proof.
  Never assume Watch3-to-custom-AsteroidOS health sensors automatically
  continue recording into Samsung Health. Physical sensor and
  calibration data paths are still unverified. Direct Samsung
  Health Data SDK deployment requires partner verification/approval.
- **Calls/music/media.** Forward only Android companion actions supported
  by its Android permissions and real AsteroidOS Bluetooth protocol.
  Do not claim microphone, cellular calls, NFC payments or music
  device codec integration without hardware-specific testing.

Official source:
- https://wiki.asteroidos.org/index.php/Quick_Start_Guide
- https://wiki.asteroidos.org/index.php/Synchronization_Clients
- https://developer.samsung.com/health/health-connect-faq.html
- https://developer.android.com/health-and-fitness/health-connect/get-started
- https://developer.samsung.com/health/data/guide/app-verification.html

## Development sequence and strict gates

1. **This PR: catalog and platform contracts.** Typed JSON records
   distinguish native watch source packages, future Android bridges,
   and known-incompatible APK/Wear OS apps. A strict stdlib Python
   validator blocks all installability claims and unsafe source URLs.
   The generated static HTML is a mobile-usable read-only preview
   with search and platform filters. It has no network code and no
   download or install action; CI generates an inspectable artifact.
2. **Native UgLy Store watch UI.** After validating the proposed
   Qt Quick UX off-device, package the watch catalog reader as a
   separate machine-scoped .ipk with no installer privileges.
   Check true native IPK and image inclusion as prior PRs did.
3. **Signed package feed and install permissions.** Require signed
   feed metadata, exact package SHA-256, trusted repository source,
   dependency and ABI checks, explicit user confirmation, storage
   budget, and safe atomic rollback. This step is BLOCKED until
   stock rescue and first-boot conditions are independently verified.
   The catalog must not enable opkg installation just because metadata
   is valid or an admin clicks a button.
4. **UgLy|OS Connect Android starter.** Build a standalone phone APK
   with a Bluetooth pairing status page, opt-in notification-forwarding
   prototype and permission controls. Verify compatibility with
   actual upstream protocol. Do not replace the existing pairing
   client without a working proof and consent.
5. **Phone-side integrations.** Health Connect read-only test,
   authorized Google Calendar events, navigation cues and phone
   media commands, one provider at a time with explicit privacy
   controls and simulator/live-phone test separation.

## App Hub preview commands (Android Termux or CI)

    cd ~/Galaxy-3
    git pull --ff-only
    python tools/build_uglyos_app_hub.py \
      --catalog app-hub/catalog.json \
      --output app-hub-preview/index.html

The HTML file works offline: open it in a phone browser to inspect
categories. It is a preview of the *catalog*, not a working app store.
It contains honest source/compatibility links, no APK downloads and
no software install buttons.

## Current implementation gates

- R08 native AsteroidOS .ipk software may be built off-device:
  source/packaging is a **software milestone**, not a hardware result.
- PR #33 notification-preview improvements are integrated into main.
- Smart Hub launcher is parked; do not merge unrelated QML changes
  into this Android/store workstream.
- Unknown bootloader, signed-image acceptance, stock full recovery,
  device BLE/graphics and health sensor drivers remain separate gates.
- Do not claim Google Play Services compatibility, Samsung
  certification, Google Wallet, Galaxy Store support, or on-watch
  Samsung Health synchronization.

**Never flash any off-device artifact from this project to SM-R840X.**
