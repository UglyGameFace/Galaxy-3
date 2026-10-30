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
