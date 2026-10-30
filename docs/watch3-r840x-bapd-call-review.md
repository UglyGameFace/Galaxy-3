# R840X physical bapd FOTA call-edge review

October 30, 2026; issue #47. This is **static instruction and import-relocation evidence**, not a working root, bootloader unlock, firmware signature bypass, recoverable custom boot, or proof of D-Bus policy authorization.

## Verified on owner's original ARM ELF32

Private original: `/bin/bapd`, 103,356 bytes, SHA-256
`429d9611c47b2cebc8918294f076ce013c1947f74441b374b306e29d300b67ea`.
Keep the copied original ZIP and extracted Samsung executables outside Git.

The exact-input offline analyzer `tools/watch3_r840x_bapd_call_review.py`
checks actual Thumb-2 BLX instructions, resolves ARM PLT stubs to dynamic
`R_ARM_JUMP_SLOT` relocations/symbol names, confirms register moves and
PC-relative literal pools (not simply string presence):

| Evidence | Verified result |
| --- | --- |
| `0xab2a` | BLX `0x3e74` -> GOT `0x28a50` -> `g_variant_new` |
| `0xab58` | BLX `0x43e0` -> GOT `0x28c14` -> `g_dbus_connection_call` |
| Parameter format | `(is)`, literal at `0x14538` |
| Bus name / interface | `fota.consumer`, literal at `0x14540` |
| Object path | `/fota/consumer`, literal at `0x14550` |
| Method | `LaunchFota`, literal at `0x14560` |

The call constructs a firmware-consumer D-Bus request. The analysis is
pinned to one exact binary; another build must not inherit conclusions.
Instructions confirm call construction, **not** who is authorized to
invoke this path or whether the consumer accepts any update payload.

## Run offline from Termux

From the existing extracted private inventory, the `helper-03.bin` file
corresponds to `/bin/bapd` in the owner report.

```sh
cd ~/Galaxy-3 && git switch main && git pull --ff-only
python tools/watch3_r840x_bapd_call_review.py \
  --input ~/watch3-r840x-privilege-inventory-evidence/helper-03.bin \
  --report ~/watch3-r840x-bapd-call-review.json
```

The output file is created only if absent, with mode 0600. No Samsung
binary is executed, no SDB/network connection is made, no firmware-update
method is invoked, and no partition is accessed. The original bytes never
enter the published report.

## Next blocking questions

1. Compare the verified call with the original consumer's published D-Bus
   interface XML and service activation/policy, and the BAPD trigger path.
   Do this **offline**. Separate what the binary sends from what security
   policy permits. Do not call `LaunchFota` as a physical experiment.
2. Confirm exact R840X signed stock restoration material, rollback rules,
   and repeatable rescue. Do not assume R840 retail firmware works on R840X.
3. Resolve incomplete privilege inventory (64 retained, 82 dropped records,
   44 more copy plans unselected), directory aliases and stat errors.

Hardware status remains **NO-GO for any firmware or recovery write**.


## October 30 continuation: original callback registration and guard

The exact original `/bin/bapd` was inspected offline. This extends the
previous verified D-Bus callsite to its registering callback and state gate.

| Address | Original instruction evidence | Limit |
| --- | --- | --- |
| `0xac7c` | Direct Thumb `BL` to `bo_add_callback` at `0x4e10` | Static event registration |
| `0xac84` | PC-relative callback pointer resolves to `0xaad1` (entry `0xaad0`) | The callback contains the FOTA request |
| `0xac88` | PC-relative event name resolves to `0x12134` (`dbus-connected`) | Internal event, not an untrusted external trigger |
| `0xaafe`–`0xab00` | Local state compared with zero; `BNE` skips to `0xab74` | Nonzero state skips the request |
| `0xab58` | Previously verified `g_dbus_connection_call` to `fota.consumer.LaunchFota` | Call construction, not authorization |

The original callback appears to send a FOTA launch request in response
to its internal `dbus-connected` event if the local state permits. The
source of the state value, runtime event reachability, D-Bus sender
policy, receiver identity, and archive/signature checks are not established.

Standard D-Bus system-bus permissions include policy rules such as
`send_destination` and user/context-specific allow/deny rules. Additional
Tizen SMACK/Cynara checks may apply. The actual R840X effective policy
files have not been recovered, so there is NO evidence that SDB's
`User::Shell` principal could send this request. Earlier systemd unit
evidence reports configured `User=fota`, not root.

Official D-Bus policy documentation:
https://dbus.freedesktop.org/doc/dbus-daemon.1.html

The existing offline Termux invocation now emits `callback_registration`
in its private JSON result. There is no reason to rerun live root mode,
invoke `LaunchFota`, or execute a Samsung helper to prove this static
finding. Next: verify policy and signature/restoration boundaries using
authentic read-only evidence.
