# R840X: Software-only Tizen FOTA service inventory (read-only)

**Active issue:** [#47](https://github.com/UglyGameFace/Galaxy-3/issues/47). Target only SM-R840X demo board R08, owner requires Android/Termux only, no purchases. **This is not a custom boot method, privilege escalation, OTA trigger, or recovery test.**

## Evidence and scope

- Samsung's [July 2021 wearable bulletin](https://security.samsungmobile.com/serviceWeb.smsb?year=2021&month=7) lists CVE-2021-25436 (FOTA processing via Samsung Accessory Protocol) and CVE-2021-25437 (FOTA replacement), both affecting Watch3 **firmware before the July 2021 update**. Firmware identifier `R840XXXU1AUA2` suggests January 2021, but actual component version/vulnerability on physical R840X has NOT been independently established.
- [Tizen watch internals from SM-R805U](https://github.com/sbose78/tizen-watch-internals) identifies a `sapd` companion protocol daemon and an OMA-DM agent with a socket at `/tmp/agent_fw_event_omadm`. It is a different model and firmware. The OMA-DM socket is **not necessarily** the FOTA vulnerability endpoint.
- A [public wearable app inventory](https://gist.github.com/avipars/bf4ebf3efa1bcceb77025b8b9159a6df) lists package `com.samsung.fota-consumer` with `fota-service` at `/usr/apps/com.samsung.fota-consumer/bin/fota-service` and `com.samsung.tizen.update-client`. It is not evidence those paths are present on the exact R840X.

## Fixed passive probes (no arbitrary shell or interaction)

The existing authenticated, restrictive SDB client uses four literal read-only requests:
- `ls -ld /usr/apps/com.samsung.fota-consumer/bin/fota-service`
- `ls -ld /usr/apps/com.samsung.tizen.update-client`
- `ls -ld /tmp/agent_fw_event_omadm`
- `ps`

The only output saved is a bounded categorical redacted JSON report; raw process listings, arguments, PIDs, phone addresses and device identifiers are never serialized. `PRESENT_AT_REFERENCE_PATH` is a direct `ls` observation, `ABSENT_AT_REFERENCE_PATH` means only that the named *reference path* is missing, and `NAME_SEEN_IN_PS` does not establish that a process is usable or privileged. Missing utilities, unreadable paths and malformed outputs are **UNAVAILABLE** rather than a fabricated negative.

This tool does NOT call into the FOTA service, open the OMA-DM socket, send Samsung Accessory Protocol frames, request a firmware update, install anything, reboot the watch, or attempt an exploit.

## On owner's Termux, after merged CI-green PR

```sh
cd ~/Galaxy-3 && git pull --ff-only
python tools/watch3_r08_android_sdb.py --watch-ip 10.0.0.65 --fota-path-only
cat ~/watch3-r08-fota-path-redacted.json
```

Update the watch IP if it changes. The previous real-watch evidence confirmed authenticated SDB `PASS[tcp]`, `PASS[sdb]`, `PASS[shell]` at `10.0.0.65`, and `/usr/sbin/sdbd-tarlauncher` is absent. The TV archive-root route is retired.

**Next technical decision:** use actual R840X observations to choose which component to inspect offline from authenticated owner-acquired Tizen firmware. Mere presence is not an exploit or bootloader unlock. With no full verified R840X backup/restore, do not write bootloader or firmware partitions on the only working watch.
