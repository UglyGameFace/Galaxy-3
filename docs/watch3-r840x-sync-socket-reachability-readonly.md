# SM-R840X sync-agent event socket: read-only reachability facts

Issue #47. November 20, 2026.

The October 2026 sync-agent review established a second trigger
candidate next to the vconf state keys: the consumer's `Install`
method ends in the library call `sync_agent_dm_fota_install`,
which sends **event 4** over an AF_UNIX stream socket. The
endpoint is configuration-derived in the original library:
`/tmp/agent_fw_event_` plus the configured key `omadm`, i.e.
`/tmp/agent_fw_event_omadm`. The library's generic listener code
binds its socket and chmods it `0777`, but the captured
consumer-side initializer sets `RunEventHandler=0`, so that
library instance is a client, not the listener — the receiving
process is the separate OMA-DM daemon, whose event-4 callback is
reviewed in the OMA-DM install record. What no review could
settle is reachability: does that socket node exist on the live
watch, and what permission class would the owner's UID 5001 SDB
shell (`User::Shell`, zero effective capabilities) hold on it?

- The socket node `/tmp/agent_fw_event_omadm`: presence, node
  kind, and the POSIX permission class that applies to the
  shell (for a socket, the write bit is the connect permission).
- Its parent `/tmp`: the shell's traversal class.
- The OMA-DM directory `/opt/usr/data/fota/oma-dm` and the
  presence of its `.oma-dm-agent-enabled` marker — the marker
  whose absence makes the consumer's `LaunchFota` callback
  actively launch the OMA-DM agent (see the LaunchFota handler
  map).

## The collector

`tools/watch3_r840x_sync_socket_reachability_readonly.py` runs
exactly five fixed allowlisted SDB shell probes
(`SYNC_SOCKET_REACHABILITY_PROBES` in
`tools/watch3_r08_android_sdb.py`): `id -u`, `ls -ldn` on `/tmp`,
the socket node and the OMA-DM directory, and `ls` on the
marker node. It opens no socket, sends no event, creates no
file, sets no key, and writes nothing to the watch. Reports
retain only categories (UID class, presence, node kind,
owner/group relation to the shell, the shell's permission
class); raw output, numeric ids, sizes and dates are discarded
before the report is written.

```sh
cd ~/Galaxy-3 && git switch main && git pull --ff-only &&
python tools/watch3_r840x_sync_socket_reachability_readonly.py \
  --socket-ip <CURRENT_WATCH_IP> \
  --report ~/watch3-sync-socket-reachability-20261120.json
```

## How the result may be read

- `event_socket_shell_access_class` is the POSIX permission
  class that applies to the shell (owner if the node is owned
  by UID 5001, group if its group is GID 100, otherwise other).
  A `WRITE` name means only that the connect-permission bit is
  set for the shell's class. No connection is ever attempted by
  this collector, and SMACK may still deny what POSIX allows.
- `event_socket_presence` = `PRESENT` proves a listener created
  the node at some point; it does not prove a receiver is
  accepting right now, which process owns it, or what its
  event-4 callback would do with a request. `ABSENT` closes the
  socket door on this boot; `OTHER_KIND` (a stale regular file)
  is its own fact and is not a live channel.
- `omadm_marker_presence` is about the consumer's launch gate,
  not the socket: `ABSENT` means a `LaunchFota` call would take
  the branch that actively launches the OMA-DM agent.
- Any `UNDETERMINED` field is a failed probe, not evidence.

Root, bootloader unlock and stock recovery remain unproven, and
firmware writes remain NO-GO regardless of this report.
