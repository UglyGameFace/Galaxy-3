// SPDX-License-Identifier: MIT
// Auto-derived from reviewed app-hub/catalog.json by tools/generate_uglyos_watch_catalog.py
// Offline-only static compatibility data. No downloads or install action.
var entries = [
  {
    "id": "uglyos-launchers",
    "name": "UgLy|OS Launchers",
    "category": "Personalization",
    "kind": "native-watch",
    "platform": "asteroidos-opkg",
    "state": "source-built",
    "summary": "Four custom layouts with a local favorites dock.",
    "installable": false
  },
  {
    "id": "uglyos-watchfaces",
    "name": "UgLy|OS Watchfaces",
    "category": "Personalization",
    "kind": "native-watch",
    "platform": "asteroidos-opkg",
    "state": "source-built",
    "summary": "Three optional Qt watchfaces that leave original faces available.",
    "installable": false
  },
  {
    "id": "asteroid-flashlight",
    "name": "AsteroidOS Flashlight",
    "category": "Utilities",
    "kind": "native-watch",
    "platform": "asteroidos-opkg",
    "state": "upstream-source",
    "summary": "Upstream native Qt utility; R08 package and display behavior not verified.",
    "installable": false
  },
  {
    "id": "asteroid-music",
    "name": "AsteroidOS Music",
    "category": "Media",
    "kind": "native-watch",
    "platform": "asteroidos-opkg",
    "state": "upstream-source",
    "summary": "Upstream music UI; Watch3 audio hardware not verified.",
    "installable": false
  },
  {
    "id": "android-notifications",
    "name": "Android Notification Bridge",
    "category": "Connected",
    "kind": "phone-bridge",
    "platform": "android-companion",
    "state": "existing-upstream-option",
    "summary": "Build on Gadgetbridge or AsteroidOSSync notification support; future UgLy|OS bridge not built.",
    "installable": false
  },
  {
    "id": "samsung-health-connect",
    "name": "Samsung Health via Health Connect",
    "category": "Wellness",
    "kind": "phone-bridge",
    "platform": "android-companion",
    "state": "research-backed",
    "summary": "Consent-based data from Samsung Health through phone Health Connect; no UgLy|OS integration exists yet.",
    "installable": false
  },
  {
    "id": "google-calendar",
    "name": "Google Calendar Companion",
    "category": "Connected",
    "kind": "phone-bridge",
    "platform": "android-companion",
    "state": "planned",
    "summary": "Calendar data through an authorized phone-side account integration. No OAuth implementation yet.",
    "installable": false
  },
  {
    "id": "google-maps",
    "name": "Phone-to-Watch Directions",
    "category": "Navigation",
    "kind": "phone-bridge",
    "platform": "android-companion",
    "state": "planned",
    "summary": "Phone handles Maps and permissions; watch receives compact navigation prompts when bridge exists.",
    "installable": false
  },
  {
    "id": "google-play-apks",
    "name": "Google Play APKs on Watch",
    "category": "Compatibility",
    "kind": "unsupported",
    "platform": "android-apk",
    "state": "not-compatible",
    "summary": "Wear OS and Android APKs require an Android runtime and services; not a native AsteroidOS package.",
    "installable": false
  },
  {
    "id": "google-wallet",
    "name": "Google Wallet on Watch",
    "category": "Compatibility",
    "kind": "unsupported",
    "platform": "wear-os",
    "state": "not-compatible",
    "summary": "Google Wallet requires supported Wear OS, NFC and Google Play Services; no verified R08 path.",
    "installable": false
  }
];
