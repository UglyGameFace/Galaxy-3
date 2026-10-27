# R840X FOTA package executable inventory using read-only SDB sync LIST

## Confirmed field evidence and research direction

On 2026-10-27 the owner recovered the 87,036-byte ARM ELF32 executable
from `/usr/apps/com.samsung.fota-consumer/bin/fota-service` through
authenticated SDB sync RECV. It matches SHA-256
`008c67e782eb3d97b0ddb7abc7606b86dc493576c24de476a2110d6e5a681757`
and is documented in Issue #47. Offline Thumb-2 disassembly established:

- SAP file transfer creates/uses `/opt/usr/data/fota/save/delta.tar`.
- `on_receive_complete` calls `chmod(path_from_callback, 0666)`.
  The callback's actual path, Tizen SMACK restrictions, process user/group,
  directory permissions and subsequent package verification remain unverified.
- `launch_fota_consumer` calls a D-Bus proxy, with binary strings
  `fota.consumer` and `/fota/consumer`. The firmware verifier/installer is
  not proven to be inside the extracted FOTA service itself.

A public Tizen wearable inventory lists two apps with executables inside
this same `com.samsung.fota-consumer` package: `fota-service` and
`fota-syspopup`, corroborating the 1.1.3 package family.
Reference: https://gist.github.com/avipars/bf4ebf3efa1bcceb77025b8b9159a6df

## Fixed, passive directory inspection

This tool requests exactly one SDB `sync: LIST` from the already authenticated
Watch3, for the **constant** directory:

    /usr/apps/com.samsung.fota-consumer/bin

It does not allow custom remote paths, arbitrary shell commands, package
installation, FOTA/D-Bus/SAP messages, process launches, firmware writes, or
bootloader access. The client checks SDB packet stream IDs and limits
directory response size, entry count and filename length. It records ONLY
alphanumeric FOTA-related basenames, file types, file sizes and aggregate
redacted counts; it never records arbitrary filenames or private watch data.

After merging the CI-green PR, in Termux run:

    cd ~/Galaxy-3 && git pull --ff-only
    python tools/watch3_r08_fota_bin_inventory.py --watch-ip 10.0.0.65
    cat ~/watch3-r840x-fota-package-inventory.json

Use the watch's current IP if it changes. The result is saved mode 0600
on the phone and will **not overwrite** an existing report. If SDB sync
LIST is denied/unsupported, the program reports an error without trying
a different service or filesystem path. Shell `ls` previously returned
access denied for the service executable; successful `sync: RECV` indicates
the two access paths may differ, but `LIST` has **not yet been physically
validated** on R840X.

This inventory is not the FOTA installer: discovering names merely informs
which binaries, if any, are candidates for **read-only offline** analysis.
Even if a helper is found, its privilege level, archive checks and firmware
signature boundary remain unsolved. Do not modify or replace `delta.tar`
on the only working watch.

Current primary goal remains authenticated **unsigned-kernel execution and
a verified stock recovery path**, both still unproven. Issue #47 remains
the single active task; this source inventory is one evidence gate.
