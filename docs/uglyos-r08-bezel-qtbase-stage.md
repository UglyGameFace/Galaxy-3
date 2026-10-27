# R08 bezel: real BitBake input patch gate before ARM64 QtBase build

## Verified starting point

PR #45 merged on October 27, 2026. Its machine-scoped QtBase 6.11.3
filter applies to the pinned **evdev fallback** and **libinput preferred**
code in host GitHub CI. Stock Watch3 Tizen separately advertised a
`tizen_detent` handler with both `REL_WHEEL` and auxiliary `REL_X`.

The existing `watch3-r08-qt-staged-runtime.yml` and
`watch3-r08-qt-linuxfb-package.yml` both offer **manually dispatched**
offline ARM64 QtBase compilation and reuse signed Yocto sstate snapshots
when compatible. They did not independently prove that the new `qtbase`
machine-only `bbappend` was effective **on the actual BitBake target**
before compilation.

## This implementation

The shared `tools/verify_watch3_qtbase_bezel_stage.py` rejects an
ineffective patch **before expensive target compilation**.

In both existing manually triggered QtBase workflows:

1. Read real `bitbake -e qtbase` and verify effective `PN=qtbase`,
   `MACHINE=noblesse-r08`, `DISTRO=asteroid`, `PV=6.11.3`,
   the `noblesse-r08` override, exactly one bezel patch in `SRC_URI`,
   and the expected patch directory in `FILESPATH`. Require
   `linuxfb` and `libinput` in `PACKAGECONFIG`.
2. Run **`bitbake -c patch qtbase`**, using pinned Yocto sources and the
   existing cache. This is a real BitBake fetch/unpack/patch stage, not
   a `git apply` substitute. It is not a C++ cross-compile.
3. Read `bitbake -e qtbase` again, resolve actual `S` and check that
   three QtBase input source files have the named-detent guards **and**
   retain Qt wheel, touch, key, button and libinput axis paths.
4. Fail if any check is missing; do not start the costly
   `bitbake -c package qtbase` step. Discard full BitBake environment
   dumps after validation, rather than uploading host information.

This reuses the **existing source patch**, existing machine-only recipe
and the **existing** QtBase workflows. No duplicate input daemon,
default enablement, firmware installation or speculative changed keys.

## Evidence labels

The new fast PR workflow tests the validator with controlled fixtures and
checks both manual workflows actually invoke the prebuild gate. Its
success **does not** mean the real BitBake do_patch stage or ARM64 build
has run. That happens only if one of the existing build workflows is
manually dispatched. Even a passing real target compile does not prove
physical Watch3 wheel delivery, LinuxFB/libinput recognition, protected
bootloader acceptance or stock recovery. Do not flash.

After an actual QtBase build succeeds, inspect the modified binaries and
package dependencies, then tackle verified runtime input dispatch in the
safe boot/recovery program. Never mark the watch navigation operational
from synthetic host wheel tests alone.
