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
