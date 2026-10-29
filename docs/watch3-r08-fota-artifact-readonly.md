# SM-R840X: original FOTA artifacts for offline analysis

Issue #47. October 29, 2026. Android/Termux only; no PC or paid tools.
The objective remains a working bootloader/recovery route. Artifact acquisition
does not demonstrate root, an unlocked bootloader or stock restoration.

## Evidence already obtained

The owner's authenticated Wi-Fi SDB successfully copied these originals:

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| Accessory `fota-service` | 87,036 | `008c67e782eb3d97b0ddb7abc7606b86dc493576c24de476a2110d6e5a681757` |
| Configured `/usr/bin/fota-consumer` | 89,980 | `19ad8468c5e73821359b140cd99f8c3bc072b2d73ed7766b082b88f26c676a1a` |

Their [reviewed handoff](watch3-r840x-consumer-trust-boundaries.md) connects
the accessory's state notifications to archive processing. The consumer's
separate `Install` branch calls imported `sync_agent_dm_fota_install`.
Its ELF names `libsync-agent.so.0` as a dependency. The dependency's bytes
and runtime implementation have not yet been obtained.

The failed `rw-update-prepare.sh` read did not produce a new script or ZIP.
It does not need to be repeated for the operation below. The original
consumer capture on the phone is reused.

## One-run sync-agent capture

After the integrated change is available on main, run in Termux:

```sh
cd ~/Galaxy-3 && git switch main && git pull --ff-only
python tools/watch3_r08_fota_artifact_pull.py \
  --component sync-agent --watch-ip 10.115.12.131 \
  --archive ~/storage/downloads/watch3-sync-agent-evidence.zip
```

Use the watch's current local Wi-Fi IP if it has changed. This uses the
existing SDB key; no Android `sdb` executable or SDK installation is needed.
The Downloads directory must already be available through Termux storage.

One run:

1. Verifies the original consumer's exact hash/length locally at
   `~/watch3-r840x-fota-unit-evidence/fota-configured-executable.bin` and
   confirms its recorded dependency. It does not recopy the consumer.
2. Runs a fixed `ldconfig -p` query and filters the cache for the exact
   SONAME. This prints the existing cache; it does not rebuild it or load
   either vendor executable. There is no `ldd` or arbitrary shell input.
3. Accepts exactly one observed system-library path in that SONAME family.
   Missing tools, denied queries, absent entries and ambiguity get distinct
   report states. It does not guess another path when resolution fails.
4. Reuses the existing bounded SDB RECV implementation to copy one library.
   Checks ARM ELF32, ET_DYN, the actual DT_SONAME, and a public defined
   `sync_agent_dm_fota_install` function in mapped executable bytes.
5. Rechecks the same cache entry before publishing the private copy.
6. Saves a report and creates the requested ZIP. A denied/missing read also
   produces a report-only ZIP, with a nonzero exit status.

The upstream [ldconfig manual](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
defines `-p` as printing candidate libraries in the existing cache. Its
availability on this installed watch is still to be established by this run.

Attach `watch3-sync-agent-evidence.zip` here for examination. It is an
original vendor artifact for private analysis; keep it out of GitHub.
It is not an executable update or a file to send back to the watch.

## Outputs and failures

The new private folder is `~/watch3-r840x-sync-agent-evidence` (0700).
Files are 0600, never overwritten:

- `sync-agent-report.json`: state/stage, source pin, observed cache path,
  hash/length, selected ELF facts and public function definition addresses.
- `libsync-agent.so.0.bin`: present only after identity/export checks and
  the cache recheck succeed.

The ZIP contains only those explicitly named files. Raw cache output,
arbitrary library strings, credentials and SDB authorization material are
not included in the report. Existing files or a ZIP name collision stop
before contacting the watch. Pre-existing evidence is preserved.

`SYNC_AGENT_LIBRARY_COPIED` proves a readable candidate with the expected
SONAME/function was obtained from the observed cache path. A stable cache
entry does not prove that an active consumer loaded this file: no process
was started, and `runtime_provider_observed` remains false.

For this mode, an explicit remote RECV error is retained categorically as
`REMOTE_REPORTED_ACCESS_DENIED` or `REMOTE_REPORTED_NO_SUCH_FILE` when
recognized. Unrecognized or conflicting text stays ambiguous. Raw error
text is never exposed. Earlier collectors retain their established error
messages; no repeat denied-script read is requested.

Failure to create the output directory/ZIP destination is a local setup
error. A failure after directory creation preserves a JSON report whenever
local storage allows it. The firmware remains unchanged by this collector.

## Compatibility and validation

The original `fota-service` and `updateclient` CLI profiles, default paths,
single-RECV requests, privacy behavior and legacy error strings are preserved.
The new dependency mode is explicit. There are no arbitrary remote filename
or shell command options. Executable-path validation is unchanged; the
library reader accepts only the evidenced SONAME family under system library
directories after cache resolution.

The offline ELF parser now also reports DT_SONAME and allowlisted public
function definitions. An undefined import, hidden/local symbol or address
outside file-backed executable memory is not reported as an implementation.
Its existing exact-original consumer review is unchanged.

Tests cover the complete fake-SDB flow, both shell encodings, cache errors,
wrong library identity, undefined functions, cache changes, output collisions,
failure packaging and a real POSIX shell query fixture. CI additionally
cross-compiles an original tiny ARM Thumb library and compares its parsed
function definition with GNU readelf; it never executes the generated code.
Original Samsung binaries remain private and are not sent to CI.

## Android/Termux local save compatibility

The earlier Termux `os.link` failure was a local save portability bug.
Both existing profiles and the dependency mode use exclusive O_CREAT/O_EXCL
local copies, not hard links. Temporary partial transfers are removed;
existing owner files are preserved. No SDB SEND, package install, FOTA
request, root-mode change, reboot or partition write is performed.
