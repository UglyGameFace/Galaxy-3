# SM-R840X FOTA reachability: read-only facts before any archive claim

Issue #47. November 20, 2026.

The October 2026 consumer review established the shape of the one
remaining free route: `fota-consumer` extracts an archive-supplied
nested program and executes it with no signature gate observed
inside the consumer, and its update entry is driven by the vconf
key `db/fotaconsumer/ui_state` (states 60/65). The open question is
not the consumer's internals but reachability: can the owner's
UID 5001 SDB shell (`User::Shell`, zero effective capabilities)
even see the places that path needs?

- The archive directory `/opt/usr/data/fota/save`: its metadata,
  the POSIX permission class that applies to the shell, and
  whether the shell may list it at all.
- Its parent `/opt/usr/data/fota` and the recovery handoff
  directory `/opt/data/recovery`, plus whether the
  `DELTA.PATH` node exists there.
- The two consumer vconf keys, `db/fotaconsumer/ui_state` and
  `db/fotaconsumer/state`, read with `vconftool get` only.

## The collector

`tools/watch3_r840x_fota_reachability_readonly.py` runs exactly
eight fixed allowlisted SDB shell probes
(`FOTA_REACHABILITY_PROBES` in `tools/watch3_r08_android_sdb.py`):
`id -u`, `ls -ldn` on the three directories, `ls` on the archive
directory, `ls` on the DELTA.PATH node, and the two vconf gets.
It creates no file, sets no key, calls no FOTA method, and writes
nothing to the watch. Reports retain only categories (UID class,
presence, owner/group relation to the shell, the shell's
READ/WRITE/TRAVERSE permission class, listing and entry-count
classes, vconf state classes); raw output, entry names, numeric
ids, sizes and dates are discarded before the report is written.

```sh
cd ~/Galaxy-3 && git switch main && git pull --ff-only &&
python tools/watch3_r840x_fota_reachability_readonly.py \
  --reachability-ip <CURRENT_WATCH_IP> \
  --report ~/watch3-fota-reachability-20261120.json
```

## How the result may be read

- `archive_dir_shell_access_class` is the POSIX permission class
  that applies to the shell (owner if the directory is owned by
  UID 5001, group if its group is GID 100, otherwise other). A
  `WRITE` name means only that the bit is set for the shell's
  class. No write is ever attempted by this collector, and SMACK
  may still deny what POSIX allows — a write bit is a reason to
  design a later, separately authorized step, not proof that
  placing an archive would succeed.
- `archive_dir_listing_class` is empirical for reading: `LISTABLE`
  means the shell listed the directory (entry names discarded);
  `ACCESS_DENIED` / `ABSENT` close that part of the question.
- `vconf_get_answered` means a get was answered (a state class or
  a missing-key answer). Read reachability of the state keys does
  not prove set permission; this collector never sets a key, and
  changing `ui_state` toward state 60 would be an update trigger,
  not a read.
- Any `UNDETERMINED` field is a failed probe, not evidence.

Root, bootloader unlock and stock recovery remain unproven, and
firmware writes remain NO-GO regardless of this report.

## Result — November 20, 2026 physical run

The owner ran the collector on the physical watch and all eight
probes classified:

- `shell_uid`: `SHELL_UID_5001` — the probe chain ran as the
  expected shell identity.
- `fota_parent_dir_metadata` (`/opt/usr/data/fota`): PRESENT,
  owner/group other, shell class `READ_TRAVERSE`.
- `fota_save_dir_metadata` (`/opt/usr/data/fota/save`): PRESENT,
  owner/group other, shell class `READ_WRITE_TRAVERSE`.
- `fota_save_dir_listing`: `LISTABLE`, entry-count class
  `ONE_TO_FIVE` (names discarded). The shell listed the archive
  directory on the live system, so read/traverse reachability is
  empirical, not only a mode-bit reading.
- `recovery_dir_metadata` (`/opt/data/recovery`): PRESENT,
  shell class `NO_ACCESS`.
- `delta_path_node`: `ACCESS_DENIED` — consistent with the
  recovery directory granting the shell no traversal.
- `vconf_ui_state` and `vconf_consumer_state`: both
  `ACCESS_DENIED`; `vconf_get_answered` is false.

Reading: archive placement is POSIX-open for the shell's class
and its read side is proven live; an actual file creation was
not attempted, so a SMACK denial at create time is not excluded.
The trigger side is closed to the shell: it cannot read the
consumer's vconf state keys, and per the consumer review the
state-60 transition is performed by the accessory service, not
by any shell tool; the recovery handoff directory and
DELTA.PATH are likewise closed. The one trigger door this
collector deliberately did not touch is a D-Bus method call to
`fota.consumer` — a service invocation, not a read, whose
shell-send outcome remains UNDETERMINED from the earlier
provenance work. This result is not root, not an update
trigger, and changes nothing about the firmware-write NO-GO.
