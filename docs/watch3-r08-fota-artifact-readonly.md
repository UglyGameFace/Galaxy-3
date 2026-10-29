# SM-R840X: original FOTA artifacts for offline analysis

Issue #47. October 29, 2026. Android/Termux only; no PC or paid tools.
The objective remains working recovery and UgLy|OS boot. This operation
acquires the missing installation implementation for offline examination.

## Actual previous result

The owner's `watch3-sync-agent-evidence.zip` contains only a 782-byte report.
Its state is `DEPENDENCY_CACHE_TOOL_UNAVAILABLE` at `linker_cache`.
The original consumer pin was verified and the watch answered, but no path
or library was acquired. The report cannot identify which shell helper was
unavailable. ZIP SHA-256:
`b13d005fb5432e3cbe0c4ca41de682c9901ac276fa9eecc504b6f51f4a8161f4`.

The collector now reuses the existing SDB directory LIST implementation,
followed by the existing RECV reader. It does not use a watch shell,
`ldconfig`, `grep`, a linker-cache command or an SDK executable.

## Run the corrected capture

The new directory and ZIP names preserve the earlier failure evidence:

```sh
cd ~/Galaxy-3 && git switch main && git pull --ff-only &&
python tools/watch3_r08_fota_artifact_pull.py \
  --component sync-agent --watch-ip 10.115.12.131 \
  --output-dir ~/watch3-r840x-sync-agent-native-evidence \
  --archive ~/storage/downloads/watch3-sync-agent-native-evidence.zip
```

Use the current watch IP if it changed. The existing SDB key and original
consumer capture are reused. Attach `watch3-sync-agent-native-evidence.zip`
from Downloads for analysis; the original vendor library remains private.

## Native discovery and identity checks

1. Verify the original 89,980-byte consumer's local SHA-256
   `19ad8468c5e73821359b140cd99f8c3bc072b2d73ed7766b082b88f26c676a1a`
   and its actual DT_NEEDED dependency `libsync-agent.so.0`.
2. Use authenticated SDB LIST for `/usr/lib`; if no candidate is listed or
   that directory denies LIST, inspect `/lib`. These are standard
   [system-library roots](https://man7.org/linux/man-pages/man8/ldconfig.8.html),
   not an attestation of the actual loaded provider. Discovery is limited
   to those two directories and the exact evidenced SONAME/version family.
3. Prefer an actually listed `libsync-agent.so.0` file/link. Without that
   name, accept only one listed versioned candidate. Ambiguity is reported.
   No file path is copied merely because a directory is a standard location.
4. Copy the selected path using the original bounded SDB RECV transport.
   Check ARM ELF32, ET_DYN, DT_SONAME and a public defined
   `sync_agent_dm_fota_install` function in mapped executable bytes.
5. Recheck the selected directory entry's name/kind/byte count, save the
   private original and report, and package the explicit files into a ZIP.

Directory processing is bounded to 8,192 entries and 512 KiB per library
directory. Only matching library names and aggregate counts are reported;
other names stay private. Original inventory modes retain their smaller limits.
The binary transfer remains bounded to 8 MiB.

The report schema is `uglyos-r840x-sync-agent-dependency-v2`. It records
`resolution_method=SDB_SYNC_LIST`, attempts and `observed_path`. The obsolete
cache-query fields are removed. A stable entry is a metadata observation;
it does not establish unchanged file contents or an active loaded provider.
`runtime_provider_observed` remains false.

## Files and failures

The selected new folder is private (0700), with 0600 files:

- `sync-agent-report.json`: state/stage, original-consumer pin, directory
  observations, selected path, binary hash/length and selected ELF facts.
- `libsync-agent.so.0.bin`: published only after identity and recheck succeed.

The ZIP contains only the report and validated library. After output-folder
creation, a failed read also produces a report-only ZIP whenever local
storage permits it, and the command returns nonzero. No extra packaging
command chained with `&&` is needed. Existing folders/files/ZIPs are preserved.

A reported remote read denial or missing file is retained categorically
without exposing its raw text. Empty/denied directory results do not prove
the library is absent from the whole device. A copied candidate does not
demonstrate root, an unlocked bootloader, signature bypass or stock recovery.

## Compatibility and validation

Existing `fota-service` and `updateclient` profiles, default paths,
executable-path validation and legacy remote-error strings are unchanged.
No arbitrary remote path or shell command argument is exposed.

Tests exercise complete native LIST/RECV capture and ZIP packaging, large
library inventories, filtered names, SONAME preference, ambiguous versions,
the second system-library root, denied reads, wrong identity, undefined
functions, changed entry metadata, output collisions and diagnostic ZIPs.
The compiled ARM Thumb ELF/readelf comparison remains required in CI.
No Samsung binary is executed or sent to CI.

The earlier Termux `os.link` portability repair is preserved: validated
local files use exclusive O_CREAT/O_EXCL copies. This collector performs no
SDB SEND, service activation, update request, root-mode change, reboot or
partition write. Physical validation of this corrected capture is pending.
