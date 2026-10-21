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

## Real end-to-end acceptance criteria

Create a separate, **off-device only** QtWayland integration test which:

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
