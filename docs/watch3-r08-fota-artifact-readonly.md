# SM-R840X: read-only FOTA executable extraction

**Active task:** Issue #47, UgLy|OS boot and recovery. This is an exploratory data-collection method, NOT a custom-boot method.

## Why

The live R840X established that the Samsung TV archive-root method cannot work in its published form because the required sdbd-tarlauncher binary is absent. Samsung's July 2021 advisory (https://security.samsungmobile.com/serviceWeb.smsb?month=7&year=2021) explicitly identifies two **Watch3** FOTA vulnerabilities, CVE-2021-25436 (Samsung Accessory Protocol processing) and CVE-2021-25437 (replacement of FOTA update files).

A separate first-hand Tizen watch package inventory (https://gist.github.com/avipars/bf4ebf3efa1bcceb77025b8b9159a6df) identifies the executable /usr/apps/com.samsung.fota-consumer/bin/fota-service. **Its existence and readability on the owner's R840X are NOT established.**

We can investigate an exact-watch binary instead of hunting for leaked public firmware, if unprivileged SDB access permits the read.

## Read-only operation

Run the script ONLY after its PR's synthetic CI passes and it is merged:

    cd ~/Galaxy-3 && git pull --ff-only
    python tools/watch3_r08_fota_artifact_pull.py --watch-ip 10.0.0.65

Replace the IP if the watch has changed Wi-Fi networks.

The script reuses already authorized SDB and sends exactly one fixed sync: RECV request for the path above. It has no remote filename input, no package installation, shell command, SEND/push, root operation, raw partition access, reboot or flash. It streams at most 8 MiB; refuses malformed packets, failures and unexpected ELF architecture; and removes incomplete files.

On success, it writes only two LOCAL Termux files:
- ~/watch3-r840x-fota-service-readonly.bin: the executable to analyze offline. Do not run, share publicly, or commit to GitHub.
- ~/watch3-r840x-fota-artifact-evidence.json: SHA-256, byte count, ELF architecture, and explicit unproven-boot flags. No device IP, keys, hardware serial or private process data.

On failure, NO_ARTIFACT means no readable binary was collected. A missing/unreadable target can reflect permission and SMACK restrictions; it is not proof that the vulnerability was patched. Do not attempt to bypass permissions with raw partition writes.

## Evidence and safety

- Samsung's official SDB documentation explicitly supports pulling files from a device **only when permissions allow**: https://github.com/Samsung/tizen-docs/blob/master/docs/sdk-tools/baseline-sdk/common-tools/smart-development-bridge.md
- A separate wire-level study confirms SDB sync framing and adb compatibility on its tested setup: https://github.com/RoboA-PLAYZ/blue-penny/blob/main/docs/tizen-sdb-protocol.md . This does not establish the R840X's sync service behavior.
- No exploit payloads, update-file substitutions, crafted FOTA requests, or firmware writes are in scope. The owner's only working watch has no proven rescue image or custom-boot support.

After an authentic binary is retrieved, analyze its headers and service parsing logic OFFLINE, compare with an independently authenticated later version if available, and independently establish whether any execution primitive crosses root/kernel and bootloader signature boundaries. A retrieved file is research evidence, not a bootloader unlock.
