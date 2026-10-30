# SM-R840X D-Bus FOTA sender-policy evidence

Issue #47, October 30, 2026. The original `/bin/bapd` contains a
verified `dbus-connected` callback that sends an outgoing
`fota.consumer.LaunchFota` request under a local-state guard.
This is **not** proof that the owner's SDB shell can send this request
or that the consumer would allow, accept or install an update.

## One bounded read-only policy capture

This is a new read-only mode using the established authenticated SDB
transport and existing LIST and RECV implementations. It never runs
Samsung binaries, sends D-Bus method calls, starts services, changes
SMACK/Cynara labels, reads partitions or writes any file to the watch.

The following fixed standard system-bus files are queried once each:

- `/usr/share/dbus-1/system.conf`
- `/etc/dbus-1/system.conf`
- `/etc/dbus-1/system-local.conf`

The following two fixed policy directories are listed once each:

- `/usr/share/dbus-1/system.d`
- `/etc/dbus-1/system.d`

Only FOTA/firmware/update-named .conf filenames reported as regular files,
with valid byte sizes (at most 64 KiB), are selected for a bounded
read-only RECV. At most eight names are accepted per directory. A
truncated/empty/denied LIST is **not** an exhaustive inventory.
The collector does not follow arbitrary includes, symlinks, user-selected
paths, or names from uncontrolled external input.

It parses XML in memory, rejects entity declarations and oversized files,
and retains only selected rules relevant to the FOTA bus name, wildcard
ownership or method-call traffic. It stores short selected attributes,
read-result categories, byte counts and SHA-256 digests, not full raw XML
or unrelated policy records. Original configuration bytes remain on watch.

An incomplete capture is an expected outcome: policy may use a different
daemon configuration path or additional included files. Even a valid
`<allow send_destination="fota.consumer"/>` is **not** sufficient proof
of a permitted sender, because policy order, scope, denied rules and Tizen
SMACK/Cynara still matter. The report always records effective user access
as UNDETERMINED.

## Android Termux command (after merged CI-green PR)

```sh
cd ~/Galaxy-3 && git switch main && git pull --ff-only
python tools/watch3_r840x_dbus_policy_readonly.py \
  --watch-ip 10.115.12.131 \
  --report ~/watch3-r840x-dbus-policy-evidence.json
cat ~/watch3-r840x-dbus-policy-evidence.json
```

Use the watch's *current* local IP if it has changed. Existing SDB
authorization and Termux Python are reused, with no new purchases.
The local report is created with mode 0600, never overwrites an earlier
report, and is safe to inspect before sharing. It contains no raw
filesystem tree, unrelated service/policy file bodies or watch secrets.

## How to interpret

- `PARTIAL_STANDARD_POLICY_EVIDENCE`: bounded read-only queries completed,
  with specific success or failure statuses per source.
- `LIST_COMPLETE`: one standard directory was iterated; nonmatching
  policy names and nonstandard includes remain unknown.
- `EMPTY_OR_INACCESSIBLE` / denied RECV: no evidence was obtained from
  that path; **not** proof that a policy or service is absent.
- `relevant_rules`: static XML fragments only; never automatically
  evaluate them as effective authorization.
- `user_shell_authorized_for_fota=UNDETERMINED`: intentionally unchanged,
  including when an allow rule is observed.

Reference: https://dbus.freedesktop.org/doc/dbus-daemon.1.html
(section on system.conf, system.d, policy ordering and include rules).

**NO-GO for firmware/bootloader/recovery writes** until exact R840X
stock rescue, signature acceptance and fallback are independently verified.
The collector does not bypass those requirements.


## October 30 physical result: FOTA sender policy overlap

The owner's original redacted `uglyos-r840x-dbus-policy-evidence-v1`
report was returned by the physical SM-R840X without calling the consumer.
The read-only fixed-path queries observed:

| Source | Observed facts |
| --- | --- |
| `/usr/share/dbus-1/system.conf` | 4,353-byte valid XML; 3 includes, 2 includedirs, default deny for `send_type=method_call` |
| `/etc/dbus-1/system.conf` | 833-byte valid XML, no selected FOTA method rules |
| `/etc/dbus-1/system-local.conf` | Missing / denied / unreadable; no file bytes |
| `/etc/dbus-1/system.d/fota-consumer.conf` | 811-byte valid XML; named send allows for users `root`, `fota` and `system`, plus a default deny targeting FOTA method calls and a **later default allow** with the `fota.consumer` destination and interface |
| `/etc/dbus-1/system.d/com.samsung.updateservice.conf` | 1,546-byte valid XML, separate `com.samsung.updateservice` default method-call deny |

The FOTA file reports source SHA-256
`499ae912f2397720c952f27143d2112427509b95335c91d5b0ec7749e6999fec`;
the original report's core system.conf SHA-256 is
`df59ef6b3bd808b8b131fc5eef7c45dd98622d5a52473ab3dd1f4f542b0d7cb1`.

The override policy directory reports 103 other/unreported *entries*,
not 103 confirmed independent FOTA policy rules. The vendor policy
directory reports two unrelated entries. This initial collector
deliberately discards unrelated policy files and some original rule
attributes, so it cannot prove merged effective authorization.

**Important correction to a naive interpretation:** dbus-daemon applies
later matching send rules after earlier rules within the applicable
policy scope. The interface-scoped default allow in the original
FOTA file is therefore a **possible exception** to the earlier
default FOTA method-call deny when the message interface matches.
The record does NOT establish actual access for the watch's
`User::Shell`, since file inclusion order, other policy blocks,
user/group/mandatory policy precedence, matching constraints omitted
from the v1 projection, bus UID, SMACK/Cynara and consumer-side
authorization remain unverified. Do not attempt `LaunchFota` to test it.

Reference: https://manpages.debian.org/unstable/dbus/dbus-daemon.1.en.html

### Reuse the existing captured JSON offline

After the merge, no new watch contact is needed to review the evidence:

```sh
cd ~/Galaxy-3 && git switch main && git pull --ff-only
python tools/watch3_r840x_dbus_policy_readonly.py \
  --offline-report ~/watch3-r840x-dbus-policy-evidence.json \
  --report ~/watch3-r840x-dbus-policy-static-review.json
cat ~/watch3-r840x-dbus-policy-static-review.json
```

This validates the previous report's version, preserves its SHA-256,
reports the extracted default send-rule sequence and explicitly
listed FOTA user allowances. It **never** produces a permission
verdict. The output is private mode 0600 and never overwrites
an existing file. This reviewer does not open SDB, D-Bus or the watch.
The prior `--watch-ip` capture workflow remains supported without change.

**Next real evidence gate:** establish the actual bus daemon config
load order, omitted relevant rules and applicable user/SMACK/Cynara
restrictions by lawful read-only inspection. Exact-model stock
recovery and signed-image acceptance are independent prerequisites
for any firmware or partition write. Keep issue #47 open.


## Focused original-attribute capture after the successful static review

The owner completed the offline review, source report SHA-256
`334cb44218801bab510dd1ba23b055527a7eba3cb3592b5bd3b425dd7a15a4f7`.
It confirmed `["deny", "allow"]` within the **filtered v1** projection,
but the v1 collector discarded `send_path`, `send_member`,
`send_requested_reply`, possible other message matching attributes,
and the ordered include paths. Therefore its `potential_default_allow_after_deny`
is a reason to inspect a stronger record, **not** effective permission.

The new opt-in `--focused-detail-ip` mode uses the existing authorized
SDB **read-only RECV** implementation to read exactly three previously
observed paths, each once and each capped at 64 KiB:

- `/usr/share/dbus-1/system.conf`
- `/etc/dbus-1/system.conf`
- `/etc/dbus-1/system.d/fota-consumer.conf`

It does **not** walk the 103 other policy-directory entries, invoke
`LaunchFota`, open a D-Bus connection, start a service, execute a
Samsung binary, or write to the watch. It extracts the ordered
`<include>`, `<includedir>` and `<policy>` elements, all known
`send_*`/`receive_*` attributes, and records names of any
unsupported/invalid attributes rather than dropping constraints silently.
It compares each SHA-256 with the owner's October 30 observed capture
and reports any mismatch. Nothing is reloaded or changed on the watch.

Run **once**, from the Android/Termux environment with your current
already-authorized watch IP, after merging a green PR:

```sh
cd ~/Galaxy-3 && git switch main && git pull --ff-only
python tools/watch3_r840x_dbus_policy_readonly.py \
  --focused-detail-ip 10.115.12.131 \
  --report ~/watch3-r840x-dbus-focused-original-rules.json
cat ~/watch3-r840x-dbus-focused-original-rules.json
```

The reporter creates a new private mode-0600 JSON file and refuses to
overwrite one. A denied file is recorded as denied/unknown, never
treated as absent policy. If the watch IP changed, replace the example
IP. No root, firmware mode, flash, recovery transition or extra
hardware is necessary.

**Still unknown afterwards:** which D-Bus daemon config actually
runs, whether later policies in other files change precedence,
the daemon-authenticated UID for `User::Shell`, Tizen SMACK/Cynara
authorization, receiver-side checks and exact-model rescue.
Even a matching allow in these three files does not resolve those
questions or authorize firmware writes. Issue #47 remains open.
