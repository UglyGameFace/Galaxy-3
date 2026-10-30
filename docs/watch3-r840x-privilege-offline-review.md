# SM-R840X: offline privilege-inventory review

October 30, 2026. Galaxy Watch3 SM-R840X, NOBLESSE-LARGE-BT R08,
R840XXXU1AUA2, CSC PAP candidate. Issue #47.

**Firmware writes, root, bootloader unlocking and stock recovery are unproven.**

## Evidence

The owner-supplied `watch3-privilege-inventory.zip` has SHA-256
`2454c2cbe7826a14984669bfad0e0da8ca92cfcacc51cfb59afd67c833c6083d`.
It contains 14 members including eight original ARM ELF32 inputs. Original
Samsung binaries remain PRIVATE and must not be committed to GitHub.

The self-consistent capture has matching report/raw probe and verified
temporary-stage cleanup `UGLYOS_STAGE_REMOVED`. Its no-root/no-write flags
are false. Self-consistency is not cryptographic remote attestation.

The physical reader reported UID/EUID 5001/5001, zero effective/permitted
capabilities and inheritable mask `0x2000c2`. Inheritable capability bits do
not themselves establish a working privilege increase.

There were **64 retained candidate records** and **82 dropped candidate
records** due to capture bounds. A separate **44 eligible original-copy
plans** were not selected because only eight copies were allowed. The 82
dropped records are not necessarily 82 unique programs. The entry counts
for `/bin` and `/usr/bin` match, as do `/sbin` and `/usr/sbin`: possible aliases,
not yet proven. No retained candidate has setuid/setgid mode bits.
Stat errors are present: 36 each for the two bin spellings, 2 each for the
sbin spellings, and 5 for `/usr/lib`. A scan-complete directory flag is
NOT evidence of a complete privilege inventory.

## Original helper findings

| Original | Observed static markers | Confidence limit |
| --- | --- | --- |
| `/bin/bapd` | `_fota_launch_cb`, `fota.consumer.LaunchFota`, `/fota/consumer` | Concrete firmware-service integration; authorization and call edge unverified |
| `/bin/csc-util` | `csc_svc_config_upgrade_pre_config_for_fota_mode`, `...normal_booting` | CSC mode preparation, not a confirmed installer or flasher |
| `/usr/bin/launch_app` | No matched FOTA literal | Earlier SMACK exec-label transition is not a root grant |
| `/bin/amd`, `/bin/csr-server`, `/bin/data-provider-master`, `/bin/dfms`, `/bin/dotnet` | No matched FOTA/recovery literals | A bounded text scan does not rule out indirect behavior |

All eight original inputs passed length and SHA-256 checks, and each is
an ARM ELF32 executable. No Samsung original was run. The firmware markers
are string-presence observations, not disassembled/validated call edges.

## Reproduce with Android / Termux, no device connection

```sh
cd ~/Galaxy-3 && git switch main && git pull --ff-only
python tools/watch3_r840x_privilege_offline.py \
  --archive ~/storage/downloads/watch3-privilege-inventory.zip \
  --report ~/watch3-privilege-offline-review.json
```

The tool verifies bounded ZIP members, duplicate/path/symlink rejection,
raw-probe consistency, safety and cleanup fields, selected candidates,
ARM ELF32 headers, original byte counts and SHA-256 digests. The output
is a 0600 JSON file created exclusively; original executable bytes are
never copied into the report. No SDB, network, helper execution or watch write.

## Next engineering target

Map the **original `/bin/bapd` FOTA callback** with actual call/relocation
evidence offline, and compare its call boundary with the previously examined
consumer D-Bus interface, caller policy and package registration. Establish
which caller can legitimately invoke `fota.consumer.LaunchFota` without
triggering that method on the watch as an experiment. Independently verify
same-variant signed restoration provenance and rescue before any flash.
A follow-up privilege capture must address root-directory aliasing, dropped
records and stat failures rather than pretending the bounded inventory
is exhaustive.

**No-Go** for flashing, FOTA invocation, partition writes, blind Odin/PIT,
or running a privilege-bearing Samsung helper.
