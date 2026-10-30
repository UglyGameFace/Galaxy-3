# Original R840X sync-agent: installation request and receiver boundary

Issue #47, October 29, 2026. The owner's corrected native capture succeeded.
This review concerns the original bytes, never execution of the vendor code.

## Original and independent checks

| Item | Observed value |
| --- | --- |
| Uploaded ZIP | `watch3-sync-agent-native-evidence.zip` |
| ZIP SHA-256 | `331b97505a06dc0a3c8dd45cf08b3e42d269151f9e1dd1f756818eb5c8ba374e` |
| Report bytes / SHA-256 | 4,211 / `1ca7769233737b333ad7310c248562eda9c3700f6c10882a75d4f15654aead8d` |
| Copied path | `/usr/lib/libsync-agent.so.0` |
| Library bytes / SHA-256 | 647,076 / `3fbebb3d55a7e6a132f3516af88280e63278a4b3bf51cb61cca194614b605a97` |
| GNU build ID | `07783d299457ad74f7c232f1941446060aa6a1a9` |
| ELF | ARM32 little endian, ET_DYN, EABI5 soft float |
| DT_SONAME | `libsync-agent.so.0` |

The directory LIST showed a 647,076-byte regular `libsync-agent.so.0.3.5`
and a 22-byte `libsync-agent.so.0` symlink. RECV used the listed SONAME link.
The link's kind/size metadata was stable. Its target was not independently
read with readlink, and no active process's loaded-library mapping was observed.

`readelf` independently confirmed the ELF metadata, SONAME and build ID.
On the actual original, the standard-library Thumb decoder and Capstone 5.0.6
matched 30 selected calls; ARM PLT instructions and R_ARM_JUMP_SLOT records
resolved 20 of those calls. Ten selected control/argument instruction checks
and two literal references were also checked directly. A private review JSON
and disassembly retain the detailed results outside the repository.
Linear disassembly of literal pools is not treated as executable control flow.

Addresses below are unrelocated ELF virtual addresses, not measured runtime PCs.

## Install requests event 4

The consumer's previously reviewed `Install` path calls this library's
`sync_agent_dm_fota_install`. Its definition is Thumb entry `0x48889`, code
address `0x48888`, size 176 bytes.

| Instruction address | Verified behavior |
| --- | --- |
| `0x488b6`, `0x488b8` | Preserve the API argument in r1; put event 4 in r0 |
| `0x488ba` | Call the local request helper at `0x48048` |
| `0x48084` | Create an event through `sync_agent_create_event` |
| `0x480ca`–`0x480d0` | Bound event-1 and select the actual TBB entry |
| `0x480d7` | Event-4 entry resolves to `0x480e8` |
| `0x480ee` | Append the retained argument as an integer event parameter |
| `0x48122` | Call `sync_agent_send_event`, defined at `0x4f4a4` |
| `0x48138` | Read an integer result from the reply |

The public wrapper returns success only for helper result 1. This is an IPC
request/result wrapper, not an observed flash operation. The separately
exported `force_install` wrapper selects event `0x16`; its name does not prove
a signature bypass or bootloader unlock.

## Socket and callback are configuration driven

The sending implementation creates an AF_UNIX/SOCK_STREAM socket at `0x4f4f8`.
It obtains the event's configured request type through `0x43c50`, retrieves
the configured endpoint at `0x430bc`, copies the endpoint into sockaddr_un,
then calls connect at `0x4f5e0`, write at `0x4f5f4` and read at `0x4f61c`.
Endpoint construction elsewhere in the same library uses `/tmp/agent_fw_event_`
plus a configured key. The actual key and live receiving process are not yet observed.

The generic listener's code calls bind at `0x447f4`, chmod with `0x1ff` (0777)
at `0x44804`, accept at `0x448ba`, and read at `0x44906`. It obtains an event ID,
looks up a callback at `0x449f2`, and calls the resulting pointer through r3 at
`0x44a02`. These are properties of generic library code. They do not show that
this exact listener is running, that an owner shell can connect under SMACK,
which callback handles event 4, or what privilege/validation that callback has.

The important original configuration reference is concrete:

- `sync_agent_dm_fota_init` resolves
  `/usr/share/oma-dm-cfg/fw-init/omadmfotaui_fw_config.xml` at `0x483ac`
  and passes it to `sync_agent_init` at `0x483ae`.
- Initialization reaches the XML parser at `0x54894`.
- The parser handles `Event-Key`, `Event-Config` and `RunEventHandler`, then
  reaches event setup at `0x54d76` and the optional handler start at `0x54d90`.

The receiving callback and its configuration are the next boundary. Sending
an installation event is not necessary to identify their declared files.

## MD5 is a separate routine

The exported `sync_agent_file_md5_validation` starts at `0x53030`. It calls
the local file-digest helper at `0x530ae`, converts 16 digest bytes to hex,
then compares the generated string with a caller-supplied string through
strlen at `0x53170` and memcmp at `0x5317a`. The compared result controls a
false/true output byte at `0x5319c`/`0x531c6`.

This demonstrates a digest-comparison implementation. It does not establish
where the expected digest originates, whether the receiving updater uses it,
or whether firmware signatures are enforced later. The reviewed public install
wrapper does not call this routine; that does not settle the backend's checks.

The library also imports libgcrypt digest/HMAC primitives. The earlier report's
empty `crypto_verification` allowlist is not evidence that all cryptography is
absent. The generic analyzer now reports those public gcry_md APIs separately
under `other_crypto`, and exposes the defined MD5 API as an allowlisted export.

## Next phone operation: receiver context

The context reader verifies the already copied library locally against its
exact hash/length before contacting the watch. It reads the exact initialization
XML above, follows only complete absolute XML references inside
`/usr/share/oma-dm-cfg/`, and copies normal ELF paths explicitly declared by
those XML fields under system library or `/usr/bin`/`/usr/sbin` directories.
Copied ELF files are parsed without loading them and remain candidates, not
attested runtime receivers. Relative names and command lines are retained in
the private XML but are not guessed or interpreted as commands.

```sh
cd ~/Galaxy-3 && git switch main && git pull --ff-only &&
python tools/watch3_r08_fota_framework_context.py \
  --watch-ip 10.115.12.131 \
  --archive ~/storage/downloads/watch3-sync-agent-context-evidence.zip
```

Attach `watch3-sync-agent-context-evidence.zip` from Downloads. The reader
prints progress for each read, uses a new 0700 output folder, saves 0600 files,
and creates a diagnostic ZIP even if a remote read fails. Previous library
and failure evidence is preserved. Existing destinations are never overwritten.

Limits: 16 XML files of at most 64 KiB each, 4 ELF files of at most 8 MiB each,
4,096 nodes and 64 complete references per XML. DTDs/entities and unsupported
encodings are rejected. No watch-side helper, shell, event submission, service
activation, SDB SEND, root-mode change, reboot or partition write is used.
Physical validation of this context capture remains pending.

The analyzer's `--component sync-agent` profile can reproduce the original
library's pinned generic ELF report locally. The 30-edge instruction review
above is a separate actual-byte review, not a claim made by synthetic CI fixtures.
Root, bootloader unlock, custom boot and tested stock restoration remain unproven.
