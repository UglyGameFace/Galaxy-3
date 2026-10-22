# Watch3 R08: next off-device QtWayland wl_shm integration gate

## Preconditions (do not rebuild the whole operating system)

- The R08 `libqlinuxfb.so` ARM64 plugin was actually compiled and packaged
  in [QtBase build #39593317503](https://github.com/UglyGameFace/Galaxy-3/actions/runs/39593317503).
- The host-only `QSGSimpleTextureNode` smoke uses a CPU-created pixel image,
  `QT_QUICK_BACKEND=software`, Xvfb and a pixel assertion. Its successful
  result was reported after updating the Ubuntu 22.04 development dependencies.
  This is **not** a Wayland protocol test or target Qt 6.11.3 runtime proof.
- Both R08 shader-mask patches are scoped to `noblesse-r08`; preserve the
  upstream compositor on other devices.

## Implemented host prototype (2026-10-21; CI result not yet verified)

The first off-device implementation now exists under
[`tests/qt_wayland_shm_roundtrip/`](../tests/qt_wayland_shm_roundtrip/)
with a separate QWidget Wayland client, a minimal QtWayland 6.2.4 QML
compositor, a C++ protocol/pixel observer, a Python process supervisor,
and a bounded [GitHub Actions workflow](../.github/workflows/watch3-r08-wayland-shm-roundtrip.yml).

The compositor C++ code requires a real `QWaylandView::currentBuffer()`
for which `QWaylandBufferRef::isSharedMemory()` is true, asserts the
buffer has the expected green pixels, and independently asserts those pixels
in `QQuickWindow::grabWindow()` from the software compositor. The
supervisor checks that the Wayland socket appears and that a **separate**
Wayland client process is still alive; it cleans up children on all exits.

The workflow installs Qt Wayland compositor and XDG shell QML support from
Ubuntu 22.04, verifies the installed Qt CMake development modules and
runs under Xvfb with explicit deadlines. A failure must be diagnosed using
the actual job logs, **not** interpreted as hardware failure or papered over
with additional speculative package names.

**Still not proven:** target Qt 6.11.3 cross-compiled compositor, packaging into the R08 image, and watch framebuffer output.


## Verified real Wayland shared-memory round-trip (2026-10-21)

GitHub Actions [run #39695926149](https://github.com/UglyGameFace/Galaxy-3/actions/runs/39695926149/job/119553160094) **passed**. The actual job logs confirm CMake configuration, both executable builds, compositor startup, a separate Wayland client connection, an observed `wl_shm` buffer, the expected client pixel values, Qt Quick's software renderer, and matching pixels captured from the compositor output. Key lines:

```text
PASS[protocol]: compositor received actual wl_shm buffer
PASS[pixels]: compositor output contains the Wayland client's green pixels
PASS[roundtrip]: separate Wayland QWidget client -> real wl_shm -> software compositor pixels
```

The log includes a failed EGL-display initialization warning, yet the verified software-scenegraph test succeeded. The separate client's connection-broken diagnostic followed the successful compositor shutdown. A Qt QML deprecated signal-handler parameter warning is also present; this is a cleanup issue, not a failed gate.

**Scope limit:** This pass used Ubuntu 22.04's host Qt 6.2.4 packages under Xvfb, not cross-compiled target Qt 6.11.3, the actual ARM64 rootfs, the Watch3 framebuffer device, its boot chain, or on-device display. Do not authorize flashing on the strength of this result.

## Free runner and pinned QtWayland source gate (October 22, 2026)

The [free runner capacity probe](https://github.com/UglyGameFace/Galaxy-3/actions/runs/39773040330)
**passed** on GitHub's public-repository `ubuntu-22.04` runner. Its actual
logs measured **85.8 GiB available disk**, **14.8 GiB available RAM** and
**4 CPU cores**. The earlier QtBase package build used the same class of
runner and passed 2,171 tasks in under six hours. This is evidence that
carefully bounded off-device stages can run without paid hosting. It does
**not** prove that the full AsteroidOS build fits within six hours or disk
limits on every fresh runner.

The corrected [rootfs validator regression](https://github.com/UglyGameFace/Galaxy-3/actions/runs/39773769137)
also **passed**. The previous failing run was caused by a safety assertion
matching `ubuntu-22.04` in an explanatory comment; all 16 ELF tests passed
even in that earlier run.

The existing [AsteroidOS metadata preflight](../.github/workflows/watch3-r08-asteroidos-preflight.yml)
now performs one additional **free, non-compiling** test:
`bitbake -c unpack qtwayland`. It checks that the effective R08 QtWayland
recipe uses Qt **6.11.3** and Git revision
`35bfd4e8e146fb49fa95f4d58028661a910b2705`, then inspects the
actual BitBake-unpacked `qwaylandquickitem.cpp` for the `wl_shm` software
texture conversion. The target-source test is capped at 20 minutes and
the entire job at 45 minutes. Its first run is
[39774432709](https://github.com/UglyGameFace/Galaxy-3/actions/runs/39774432709);
**passed** with real pinned QtWayland source unpack and the source-level wl_shm software-rendering assertions.

Neither stage compiles target QtWayland nor produces an image. The next
expensive stage should be planned from measured disk usage and a realistic
free cache budget, never by assuming the full image is already ready.

## Actual R08 AsteroidOS machine package passed (October 22, 2026)

The **free, hosted** [GitHub Actions run #39830173492](https://github.com/UglyGameFace/Galaxy-3/actions/runs/39830173492)
**completed successfully**, including actual BitBake install, package creation,
IPK output, and package QA. The job log records:

```text
NOTE: Tasks Summary: Attempted 571 tasks of which 0 didn't need to be rerun and all succeeded.
PASS: Display.ROUND=true
PASS: Capabilities.HAS_WLAN=true
PASS: Capabilities.HAS_SPEAKER=true
PASS: Identity.MACHINE=noblesse-r08
PASS: validated actual R08 machine identity in packaged target payload
```

The workflow compared `do_install` output against the actual packaged
`etc/asteroid/machine.conf` and independently validated both. Its
[diagnostic artifact](https://github.com/UglyGameFace/Galaxy-3/actions/runs/39830173492/artifacts/12449103629)
includes the generated identity file and logs (not a firmware image).

Two R08-only build safety improvements were necessary: the upstream
`asteroid-machine-config` recipe creates its file using Python, so
`INHIBIT_DEFAULT_DEPS:noblesse-r08 = "1"` avoids unnecessary cross-gcc/glibc
toolchain dependencies; the free hosted build uses an 8 GiB free-disk
and 100K free-inode stop threshold after the accidental 200M-inode guard
blocked a previous run. The workflow also explicitly fetches the pinned
historical AsteroidOS commit before checkout to avoid master-branch drift.

**Compositor configuration dependency budget: measured and improved.**
[Run #39843007333](https://github.com/UglyGameFace/Galaxy-3/actions/runs/39843007333)
**passed** and measured **126 recipes / 1,475 task IDs** with
`qtbase-native`, `qtdeclarative-native`, and `qttools-native`
in the original upstream keyboard-map toolchain. QtTools 6.11's
`kmap2qmap` symbol lookup handles `VolumeDown` and `VolumeUp`
but not the `MenuKB` and `Sleep` symbols used in the pinned
upstream `keys.kmap` file; using it unchanged may omit buttons.

A strict, `noblesse-r08`-only
[Qt6 keymap encoder](../meta-noblesse/recipes-asteroid/asteroid-launcher/asteroid-launcher-configs/r08-qmap.py)
now encodes **all six physical input keycodes** into the Qt QDataStream
`.qmap` format. It rejects any unexpected input to prevent a silent
incorrect map. The [host Qt6 compatibility run #39845554241](https://github.com/UglyGameFace/Galaxy-3/actions/runs/39845554241)
**passed** all nine Python regression tests, fetched the real pinned
AsteroidOS `keys.kmap`, generated the 88-byte binary, and used a compiled
Qt6 QDataStream reader to verify all six `Qt::Key` values.

The [R08-only recipe override](../meta-noblesse/recipes-asteroid/asteroid-launcher/asteroid-launcher-configs_%.bbappend)
retains the three upstream compositor environment files and
`keys.kmap`, but substitutes the host-Qt6-validated conversion
for `qttools-native`. Other AsteroidOS machines still use their
original recipe and QtTools tool. The revised
[dependency graph #39845884696](https://github.com/UglyGameFace/Galaxy-3/actions/runs/39845884696)
is checking that the heavy native Qt dependency chain was removed.
The guarded [configuration IPK build #39846145882](https://github.com/UglyGameFace/Galaxy-3/actions/runs/39846145882)
will inspect the actual packaged LinuxFB settings and check the
six-button file's fixed SHA256 if its dependency budget gate passes.
**Neither run's conclusion was verified at the time of this edit.**

The successful machine package does **not** prove any Qt compositor
binary, installed graphical root filesystem, framebuffer device,
boot chain, or on-watch display. No flashing is authorized.

## R08 target image graphics dependency gate (2026-10-21)

After host Qt 6.2.4 `wl_shm` round-trip success, the next task is target
**package closure**, not another host Wayland prototype or cold QtBase build.

New [graphics-image metadata checker](../tools/check_watch3_graphics_image_env.py)
and [regression tests](../tests/test_watch3_graphics_image_env.py)
run in the existing [AsteroidOS BitBake preflight](../.github/workflows/watch3-r08-asteroidos-preflight.yml).
The checker examines effective `bitbake -e` values for `asteroid-image`,
`asteroid-launcher`, `qtbase`, `qtwayland`, and `qtdeclarative` using
`MACHINE=noblesse-r08` and `DISTRO=asteroid`.

It fails if the image omits the launcher or the Wayland distro feature;
if the launcher drops hard runtime dependencies on `qtbase-plugins`,
`qtwayland-plugins`, `qtdeclarative-qmlplugins`, or
`asteroid-launcher-configs`; if one of those plugin/QML packages is not in
the corresponding Qt module's effective `PACKAGES`; or if its `FILES`
split does not cover the plugin/QML installation directory.
It also requires QtBase's `gui` and `linuxfb` PACKAGECONFIG.

**Ten local regression tests passed.** The *actual BitBake environment
result is not yet confirmed*. The validator tests metadata only; it does
not inspect target `.ipk` payloads, prove final rootfs package installation,
or run target Qt 6.11.3 binaries. The existing six-hour QtBase LinuxFB
build remains manual-only.

Future physical file/rootfs inspection must establish the ARM64 LinuxFB
plugin, Wayland client QPA plugin, QtWayland compositor library, launcher
binary, launcher configuration and actual Qt Quick QML imports inside one
target image. That is a separate gate, not a license to flash the watch.

## Actual ARM64 rootfs contents gate (prepared, not executed on an image)

[The post-build file validator](../tools/validate_watch3_graphics_rootfs.py)
can inspect an **already-extracted** R08 AsteroidOS root filesystem. Its
[sixteen regression tests](../tests/test_watch3_graphics_rootfs.py) ran
successfully against synthetic fixtures before committing. This tool is
**now wired into a separately guarded, manual-only graphical rootfs
build workflow**. The workflow executes `bitbake -c rootfs asteroid-image`
and reads `IMAGE_ROOTFS` plus `IMAGE_MANIFEST` from the actual effective
BitBake environment before invoking the validator. It does not run on pushes,
cannot proceed without `BUILD_OFF_DEVICE_ROOTFS_ONLY` confirmation, and
requires at least 120 GiB free disk and 12 GiB available memory. The optional
`watch3-yocto` self-hosted runner keeps Yocto caches between builds.
That full-rootfs workflow is self-hosted-only due its 120 GiB capacity gate;
it is **not** required for the free source/package checks.

The separate [five-minute regression workflow](../.github/workflows/watch3-r08-graphics-validator-check.yml)
runs on changes to the rootfs checker and graphical workflow, without
building Qt or an image. Its corrected
[October 22 run #39773769137](https://github.com/UglyGameFace/Galaxy-3/actions/runs/39773769137)
**passed**.
**No full graphical rootfs build has been run in this task**, and its
real ARM64 artifacts remain unverified.

The validator additionally checks ELF64 little-endian executable/shared-object
types and a real, in-file program-header table. Two new fixture tests reject
a fake ARM64 file containing only an ELF identification header or a truncated
program-header table. The updated 16-test suite passed locally against files
whose Git blob hashes matched the committed source and tests.

It verifies the existence and ELF64 AArch64 machine ID of the
`/usr/bin/asteroid-launcher` program, LinuxFB `libqlinuxfb.so` QPA
plugin, a Wayland-client `libqwayland*.so` QPA plugin, and the
`libQt6WaylandCompositor.so.*` runtime library. It also checks the
launcher systemd user service, exact R08 compositor environment settings,
and the QtQuick QML module's `qmldir`. The optional package manifest check
requires the installed-package names to include
`asteroid-launcher`, `asteroid-launcher-configs`, `qtbase-plugins`,
`qtwayland-plugins`, and `qtdeclarative-qmlplugins`.

Use it only after a real target image or already-built rootfs is available:

```sh
python3 tools/validate_watch3_graphics_rootfs.py PATH_TO_EXTRACTED_ARM64_ROOTFS \
  --installed-packages PATH_TO_INSTALLED_PACKAGE_NAMES.txt
```

This is a **file-and-package presence** gate, not a successful target
runtime launch, graphics/ELF dependency loader test, watch framebuffer
probe, boot validation or a recovery guarantee. The script never executes
the target binaries, touches the watch, or changes the image. Do not
confuse the synthetic regression pass with real ARM64 rootfs validation.
The actual source build remains a separate expensive manual decision; this change only prepares its validation.

## Real end-to-end acceptance criteria

Validate the separate, **off-device only** QtWayland prototype against these criteria:

1. Starts a minimal **QtWaylandCompositor** with one `WaylandOutput`, an
   `XdgShell` and a view of the client's surface, under Xvfb using
   `QT_QPA_PLATFORM=xcb` and `QT_QUICK_BACKEND=software`.
2. Establishes a private `XDG_RUNTIME_DIR` (mode 0700) and a unique
   `WAYLAND_DISPLAY` socket, and confirms the compositor actually listens.
3. Starts a *separate process* using the Wayland QPA plugin, not LinuxFB.
   For this specific test, a CPU-painted QWidget or equivalent buffer source
   is preferable to a GPU-backed client.
4. Confirms the compositor **receives a wl_shm-backed buffer**, rather than
   merely discovering that QtWayland source contains `isSharedMemory()`.
   Capture a runtime observation at the compositor/buffer boundary.
5. Grabs the **compositor output window**, not the client's own window,
   and compares a known interior RGB pixel with the actual client content.
6. Fails with separate diagnostics for package prerequisites, compositor
   startup, missing socket, client connection/surface, buffer type, missing
   frames, and incorrect output pixels.
7. Enforces a short time limit and kills all child processes on success or
   failure, ensuring no leaked sockets or hanging GitHub Actions jobs.

Ubuntu 22.04 offers `qt6-wayland-dev`, `qt6-wayland` and
`qml6-module-qtwayland-compositor` for a host-side Qt 6.2.4 test. These
**must be independently verified at configure time**. The target is the
already-pinned QtWayland 6.11.3, so a host pass is necessary but not sufficient.
Keep this gate isolated from the successful QtBase package job and **do not
run a six-hour cold Yocto build** for protocol testing.

After a host round-trip pass, a separate target-runtime/package check must
verify the actual ARM64 QtWaylandCompositor, Qt Wayland client QPA, QML imports
and LinuxFB backend coexist in the R08 rootfs. That is the earliest point to
consider a full off-device graphical image build. Neither step authorizes
watch flashing; recovery and boot-chain safety are still unresolved.

## Sources

- [Qt official Minimal QML compositor example](https://doc.qt.io/qt-6/qtwaylandcompositor-minimal-qml-example.html):
  compositor, output, shell extension and surface item
- [QtWayland 6.11.3 `QWaylandQuickItem`](https://github.com/qt/qtwayland/blob/6.11.3/src/compositor/compositor_api/qwaylandquickitem.cpp):
  `wl_shm` buffer, image upload and simple texture node
- [Ubuntu Jammy QtWayland source packages](https://packages.ubuntu.com/source/jammy/misc/qt6-wayland)
- [Ubuntu Jammy compositor QML module](https://packages.ubuntu.com/jammy/amd64/qml6-module-qtwayland-compositor)
