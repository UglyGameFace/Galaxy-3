# Original R840X OMA-DM Install and pre-update verification

Issue #47, October 30, 2026. The receiver capture supplied the original
OMA-DM daemon, backend initializer, event definitions and three plugins.
Event 4 registers a concrete callback. The daemon verifies a pre-update
archive's certificate chain and signature before executing its inner helper.
The device plugin can continue into update preparation after that helper
fails. Neither observation establishes acceptance of unsigned firmware,
root, an unlocked bootloader, custom boot or a working recovery.

## Original evidence

The uploaded `watch3-sync-agent-receiver-evidence.zip` has SHA-256
`b07635c319f89c64daef262e6fac700af785cb3c852a342e6f3bd310e77ccdc9`.
Its 14 members comprise the 16,247-byte report and 13 copied files. The report
hash is `b5a3f65bcf8013e963a3c944564fcbad082247a344e35e4fa25dd4aa4166f3b0`.
All member names, byte counts and hashes were checked against the report;
the originals remain private and were not executed or uploaded to CI.

| Source | Bytes | SHA-256 |
| --- | ---: | --- |
| `/usr/bin/oma-dm-agent` | 525,584 | `32057c3ba2537b2632a5d73dc1397b919ad3bf9c58c446b11e48e3837ab99a05` |
| `/usr/share/oma-dm-cfg/fw-init/omadm_fw_config.xml` | 5,296 | `f8ba15dde1bca536e16ee08149206d428b605e839667151a3d55056c49a7500e` |
| `/usr/share/oma-dm-cfg/ipc/eventconfig_omadm` | 687 | `e018dd015274c8186233d7917783f4968fbcc47c46e459116974ce8e90444d31` |
| `/usr/lib/sync-agent/dm-private/libplugin-di-slp-device-dm.so` | 36,184 | `98c21b99b0c443e75f42e00cc990f6e4374fa8c398f8d3e8c82a4585d9f2f357` |

The daemon and device plugin are ARM32 little-endian ET_DYN. Their GNU build
IDs are respectively `8116f8b9fea599079e18ee6306a873e68311df58` and
`eb356fba7a32100bf6a3fa09347e8e9c96b9a7df`. `readelf` separately confirms
their metadata and symbols. On these exact bytes, a private verifier matches
25 selected calls using the standard-library Thumb decoder and Capstone 5.0.6,
checks 18 PLT/GOT symbol bindings, seven branch targets, eight literal references
and the event-4 TBB entry. These selected checks are not whole-program analysis.

The capture state is `CONTEXT_PARTIAL_OR_UNAVAILABLE`: seven XML, two opaque
configuration files and four ELF files were copied. LIST observed the
453-byte `oma-dm-agent.service`, but its RECV failed with
`REMOTE_MISSING_DENIED_OR_UNREADABLE`. That response does not distinguish a
missing file, a permission failure or another read failure. No live receiver,
UID or loaded plugin binding was observed.

## Event 4 registration

The event file's exact row is `4, 1, 0, 30, EVENT_INSTALL`. This identifies
the event number and label; the third field is not evidence of a UID or an
authorization check. The original backend XML selects Agent-Key/Event-Key
`omadm` and RunEventHandler `1`. Daemon main resolves that exact initializer
at `0xe104` and calls `sync_agent_init` at `0xe106`.

Addresses here are unrelocated ELF virtual addresses, not measured runtime PCs.

| Daemon address | Reviewed behavior |
| --- | --- |
| `0x2617c` | TBB selects event ID minus one, within the bounded 1–22 range |
| `0x26183` | Event-4 table byte `0x81` selects `0x26282` |
| `0x26282`, `0x26284` | Resolve Thumb callback pointer `0x23749`, code `0x23748` |
| `0x2619c` | Register callback through `sync_agent_set_event_callback` |
| `0x237a8` | Callback reads an integer event parameter |
| `0x23848` | Callback opens a management object |
| `0x23ac2` | Callback calls `fumo_serviceEngine_task_request` at `0x1f22c` |
| `0x1f28a` | That helper calls `sync_agent_request_async_task` |

This extends the [original library review](watch3-r840x-sync-agent-install-path.md)
from a generic callback registry to this daemon's specific Install registration.
The complete asynchronous dispatch, active process privileges and final
firmware-validation chain are still open.

## The daemon's pre-update helper verifies a signed archive

Daemon `_pre_update_client` is at `0x187e8`. It first extracts
`pre_update.tar` from an outer archive. It then calls `verify_FOTA_image`
at `0x188ea`, passing the archive path and the literal public trust-certificate
path `/usr/share/oma-dm-cfg/certi/FOTA_ROOT.cer`. Outer archive parsing therefore
occurs before this check; do not describe the entire workflow as verifying
before any parsing.

Inside `verify_FOTA_image` (`0x179d0`), `X509_verify_cert` is called at
`0x17f34`; a result other than 1 branches away at `0x17f3a`. Digest operations
lead to `EVP_PKEY_verify` at `0x18314`; a result other than 1 branches away
at `0x1831a`. The reviewed return handling distinguishes successful verification
from errors. OpenSSL's official 1.1.1 documentation corroborates the return
semantics for [certificate-chain validation](https://docs.openssl.org/1.1.1/man3/X509_verify_cert/)
and [public-key signature verification](https://docs.openssl.org/1.1.1/man3/EVP_PKEY_verify/).

Back in the helper, `0x18918`/`0x1891a` select the zero-result success path.
A nonzero result leads to logging and deletion of the pre-update archive.
The success path extracts the requested inner helper through `_system_command`
at `0x1899a`, then invokes that helper at `0x18a00`. The daemon's command
wrapper at `0x13b48` uses fork and execve, checked at `0x13ba2` and `0x13c9c`.
No update archive was supplied or executed during this analysis.

The analyzer previously omitted `EVP_PKEY_verify` and `X509_verify_cert` from
its import allowlist. Its earlier empty crypto-verification list was a reporting
gap, not evidence that this daemon lacked signature verification. Both APIs
are now reported. Digest primitives remain a separate category. Exact-source
profiles `oma-dm-agent` and `dm-device-plugin` reject changed bytes and
caller-supplied substitute pins. Import lists alone do not establish call flow.

The standalone `/usr/bin/fota-consumer` has a different implementation of
`_pre_update_client` at `0x437c`. Do not transfer this daemon's newly reviewed
check to that separate binary or describe both functions as identical.

## Device-plugin continuation keeps final validation unresolved

The device plugin's exported execute function (`0x1e80`) resolves
`pre_update_client_2` at `0x2662` and calls its imported `_pre_update_client`
at `0x2666`. The captured daemon exports that symbol. This establishes static
symbol compatibility; a live dynamic binding has not been observed.

The result comparison at `0x266a` branches on a nonzero return at `0x266c`
to `0x27a4`. That path logs and optionally removes working contents, then
rejoins `0x2670` through `0x27c4` or `0x27f6`. The subsequent path calls the
preparation routine at `0x270a`, targeting `0x44cc`.

That routine contains a command writing DELTA.PATH (`0x4514`), a call using
`/usr/bin/rw-update-prepare.sh FOTA` (`0x45be`) and a reboot-helper call
(`0x45e2` to `0x4440`, which calls `device_power_reboot` at `0x4448`).
Other return checks exist; this is not a claim that every invocation reboots.
The helper's failed signature check alone does not prove the whole installation
aborts. Conversely, continuation does not demonstrate that unsigned firmware
will pass the remaining updater, recovery or bootloader checks.

## Completed firmware-focused capture

The original backend XML declares an MO plugin with Type `FUMO` and path
`/usr/lib/sync-agent/dm-private/libplugin-mo-fumo.so`. The four-ELF cap was
consumed by the daemon, HTTP plugin and two device plugins. It skipped FUMO
without attempting a read; FUMO was not observed missing or denied.

`--firmware-focus` verifies the existing library plus the captured daemon and
backend XML before any watch connection. It selects the unique MO/FUMO
declaration, then performs only two bounded native RECV operations: the plugin
and the daemon-referenced public certificate. It performs no directory discovery,
shell command, service activation, event submission or firmware write. Existing
captures stay intact. Any partial result still produces a diagnostic ZIP.

On the owner's phone:

```sh
cd ~/Galaxy-3 && git switch main && git pull --ff-only &&
python tools/watch3_r08_fota_framework_context.py \
  --watch-ip 10.115.12.131 --firmware-focus \
  --archive ~/storage/downloads/watch3-firmware-focus-evidence.zip
```

The owner supplied that ZIP successfully. The command above is acquisition
history; do not repeat it. ZIP SHA-256:
`461b424a40ef512b4bdca83fcfa6ab8682a7202226a5b643e8e6eb98c10cdabb`.
The 2,721-byte report has SHA-256
`5c0c84556b05024613e4f36c173b3fd3a2662e144d0f9bcb0ef7eb2346908d34`.
Its state is `FIRMWARE_FOCUS_CAPTURED`; all three member names, sizes and
hashes match. The original 5,032-byte FUMO plugin has SHA-256
`e3993a58bfc904730a0e753de188e5ab61cef7fb9e52de75899270477ed99458`
and GNU build ID `06d04977f8e458215a73fa1153ff9795896b3bf6`.

### FUMO's four exported functions provide metadata

| Code address | Export | Reviewed behavior |
| --- | --- | --- |
| `0x79c` | `sync_agent_plugin_get_server_id_list` | Allocates a list containing `*` |
| `0x878` | `sync_agent_plugin_get_mo_value` | Handles `PkgName`, `PkgVersion`, `State`; State copies `10` plus NUL |
| `0x994` | `sync_agent_plugin_set_function_get_devinfo` | Logging stub in this original |
| `0x9ec` | `sync_agent_plugin_initialize` | Logs and returns 1 |

The private independent review checks all 17 immediate calls in these four
exports with the Thumb decoder, Capstone and the real PLT/GOT relocations.
They resolve only to logging, malloc, calloc and strcmp. The `State` copy uses
the three literal bytes at `0xca0`. This is static plugin metadata, not a live
firmware state or an installation routine. The pinned `fumo-plugin` analyzer
profile now reports these exact exports. No plugin code was executed.

### The captured trust anchor is a public certificate

The 1,058-byte DER certificate has SHA-256
`196a09eb31f957fcca49bae20c427070c38cca59cddefaf1874ab2173c20a70c`.
Its public key is RSA-2048; the certificate is self-issued, has CA=true, and
its self-signature verifies with SHA-512/RSA. Its encoded validity interval is
2013-11-21 01:46:01 UTC through 2068-08-24 01:46:01 UTC. That interval is not
an observation of the watch's clock or of actual package acceptance. This is
a public trust anchor, not the firmware signing private key. The certificate's
own signature algorithm does not establish which digest an update archive uses.

### Additional daemon task mapping

Original-byte checks now link task registration to `make_fumo_serviceEngine_process_task_spec`
at `0x1eb76`. Registration uses task ID 8 at `0x1eb84`/`0x1eb86`; the Install
request helper also uses ID 8 at `0x1f286`/`0x1f28a`. The task-spec builder
resolves Thumb callback pointer `0x1fead` at `0x21468` and passes it to
`sync_agent_alloc_simple_task_spec` at `0x2147c`.

That callback calls `service_engine_start` at `0x2005e`; a state-dependent
path calls `fumo_exec` at `0x2f088`. Its `/Update` branch calls
`firmware_update_operation` at `0x3770e`, which calls
`fumo_engine_state_operation` at `0x373a8`. Eight further calls, two PLT/GOT
bindings, the callback literal and both task-ID instructions were checked
against original bytes. These are static segments with intervening state
checks; a complete live event-to-flash execution has not been observed.

The current next phone operation is the
[standard root-mode attempt and conditional boot/recovery backup](watch3-r840x-native-root-and-backup.md).
The phone retains its SDB key; this workspace cannot authenticate directly.

The acquisition tests use explicitly synthetic pins and fake SDB responses.
The separate private review above uses the owner's actual bytes. CI fixtures
do not prove a physical exploit, root, unlocked bootloader or recovery. Exact
R840X bootloader/recovery bytes, a tested stock-restoration route and accepted
custom boot remain unresolved; Issue #47 stays open.
