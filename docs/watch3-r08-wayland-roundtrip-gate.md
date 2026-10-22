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
Standard hosted runners must pass the same capacity gate.

The separate [five-minute regression workflow](../.github/workflows/watch3-r08-graphics-validator-check.yml)
runs on changes to the rootfs checker and graphical workflow, without
building Qt or an image. Its first CI result is not yet verified.
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
