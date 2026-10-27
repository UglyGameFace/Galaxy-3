# SM-R840X: inspect an EXISTING PIT locally without talking to the watch

**Hard rule, October 27, 2026:** Owner's only SM-R840X R08 must remain
working on stock Tizen. Do not issue any 1,024-byte Odin command, request
PIT from the watch, flash, exploit, factory reset or downgrade. This tool
accepts **only a local pre-existing PIT file**, and optionally a JSON
inventory from the already existing **offline** BL/AP/CSC metadata tool.
No repair firmware package or R840X PIT bytes were acquired for this PR.

## Why a new offline PIT parser instead of running Ragnarök `print-pit`

- The owner's 4-byte ASCII `ODIN`→`LOKE` AP transport was physically
  proven and stock Tizen rebooted afterward. This does **not** prove
  acceptance of a 1,024-byte Odin command or valid stock rescue.
- Ragnarök's `print-pit` and `save-pit` send an Odin **session-start**
  and PIT request/transfer commands. The name is not evidence of
  read-only hardware behavior. Neither has been tested on SM-R840X.
- The previously built `audit_watch3_r840x_odin_components.py`
  merely identifies *.pit filenames in untrusted ZIP/TAR listings.
  It **does not parse** the partition names or check possible
  correspondence to image filenames.
- Pinned Ragnarök `pit/src/deserialize.rs` describes 132-byte
  entries but its version-1 reader advances through an additional
  32-bit word before the name compared to Heimdall's layout, while
  retaining the fixed 132-byte entry stride. That is a **potential
  source parser inconsistency**, not proof that all PIT revisions
  should be interpreted the same. Source:
  [Ragnarök at f9164d2](https://github.com/AsteroidOS/ragnaroek/blob/f9164d2c227369ba711d89f12eef99186df61387/pit/src/deserialize.rs).

## Independently cross-checked binary framing

Pinned original Heimdall source commit
`3997d5cc607e6c603c6e7c0d07e42e9868c62af2`:

- [libpit.h](https://github.com/Benjamin-Dobell/Heimdall/blob/3997d5cc607e6c603c6e7c0d07e42e9868c62af2/libpit/source/libpit.h):
  28-byte header and 132-byte entries.
- [libpit.cpp](https://github.com/Benjamin-Dobell/Heimdall/blob/3997d5cc607e6c603c6e7c0d07e42e9868c62af2/libpit/source/libpit.cpp):
  magic `76 98 34 12`; number of entries at byte 4;
  partition name at **entry+36**, flash filename at **entry+68**,
  FOTA filename at **entry+100**, each up to 32 bytes.
- [Ragnarök PIT.md, pinned](https://github.com/AsteroidOS/ragnaroek/blob/f9164d2c227369ba711d89f12eef99186df61387/PIT.md):
  corroborates magic and 132-byte entry size but documents uncertain
  vendor-specific numeric-field meanings.

The new tool interprets **only the common framing and text names**,
with strict file bounds, ASCII/NULL-name validation, duplicate
partition-name checks and rejection of nonzero unknown trailers.
It deliberately does **not** guess:

- Whether an actual file uses PIT variant V1 or V2.
- Physical sector size, partition start offsets, storage unit, field
  flags, filesystem, or whether a raw entry ID is a partition number.
- Whether a PIT belongs to **this SM-R840X** or installed
  `R840XXXU1AUA2`, or whether model build/rollback matches.
- Samsung signatures or trust of the package publisher.

A successfully parsed sample remains `NO_GO`.

## Termux only AFTER an authentic candidate file exists

If and only if you have a lawfully obtained, trusted local PIT file
from a firmware archive, place it wherever you prefer on Android
and inspect it **without connecting to your watch**:

```sh
cd ~/Galaxy-3 && git pull --ff-only
python tools/audit_watch3_r840x_pit_offline.py \
  "/sdcard/Download/candidate-r840x.pit" \
  --report ~/watch3-r840x-pit-offline.json
cat ~/watch3-r840x-pit-offline.json
```

The path above is a **placeholder**, not a file discovered on the
user's device. The script never downloads a PIT, never connects to
Samsung/Tizen services and never touches the watch.

Optionally supply a previously generated local JSON from the existing
**offline** Odin ZIP/TAR metadata scanner, in order to compare
**unverified filenames only**:

```sh
python tools/audit_watch3_r840x_pit_offline.py \
  "/sdcard/Download/candidate-r840x.pit" \
  --component-report ~/watch3-r08-odin-contents.json \
  --report ~/watch3-r840x-pit-crossmatch.json
```

The comparison can list matched and missing image **names**, but it
does not inspect cryptographic signatures or prove that the file
would restore that partition. The report is private mode 0600,
created exclusively with no overwrites.

## CI and stopping conditions

Only **generated synthetic PIT bytes and fake component JSON** enter
CI, on Ubuntu 22.04 and 24.04. Tests reject bad magic, excessive
entries, truncated records, path-like filenames, duplicate names,
nonzero trailing data, symlinked or oversized files, bad component
schemas and report replacement. They check that two alternate numeric
field layouts preserve the same text fields while their interpretation
remains `UNKNOWN_NOT_INTERPRETED`.

**Still required before any actual custom boot:** a trustworthy
complete exact-model stock rescue archive, matching authentic PIT,
verified rollback/signing acceptance, and independently demonstrated
recovery on a **sacrificial** SM-R840X or qualified fixture.
A passed synthetic parser is **not** a flashing or repair milestone.
