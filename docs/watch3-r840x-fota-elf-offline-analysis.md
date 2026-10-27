# SM-R840X: authentic FOTA ELF offline static analysis

**Single active issue:** #47, Android/Termux only. No purchases or physical watch changes.

## New physical result from owner, 2026-10-27

Authenticated SDB sync RECV successfully copied the fixed service binary
/usr/apps/com.samsung.fota-consumer/bin/fota-service, after the Android
os.link() save bug was fixed in PR #58.

The actual extraction report showed:

- 87,036 bytes
- ARM_ELF32, little-endian
- SHA-256: 008c67e782eb3d97b0ddb7abc7606b86dc493576c24de476a2110d6e5a681757
- Source: the owner-connected physical Watch3 over its private Wi-Fi IP.
  The extraction report has target_model_authenticated=false. This is
  physical SDB provenance, not cryptographic model attestation.

No root, CVE triggering, unsigned-kernel boot or stock recovery was attempted.

## Analyze locally on Android, without executing watch code

After this PR merges, run in Termux:

    cd ~/Galaxy-3 && git pull --ff-only
    python tools/analyze_watch3_r08_fota_elf.py
    cat ~/watch3-r840x-fota-static-analysis.json

Input: ~/watch3-r840x-fota-service-readonly.bin, kept private on phone.
Output: ~/watch3-r840x-fota-static-analysis.json, created with mode 0600;
never overwritten. If the size/hash differs, analysis fails closed.
No package installations, binutils, SDB, on-watch shell, network activity,
FOTA requests, executable loading, shelling out or root commands.

The dependency-free bounded Python standard-library parser:
- validates ARM ELF32 headers, program/section tables and dynamic structures;
- reports ELF type, stack permissions and indicative RELRO flags;
- reads DT_NEEDED shared libraries including a stripped ELF fallback;
- shows selected undefined dynamic API imports where symbol tables exist;
- counts predetermined text hints, never serializing raw private strings,
  full process arguments, addresses, identifiers or non-allowlisted symbols;
- distinguishes unavailable/stripped metadata from proven negative behavior.

**Do not infer exploitability** from embedded strings, function names,
shared libraries, import tables or ELF flags. Samsung's official
July 2021 Watch3 FOTA bulletin documents CVE-2021-25436 and CVE-2021-25437:
https://security.samsungmobile.com/serviceWeb.smsb?year=2021&month=7
The installed firmware build ID predates July by its name, but actual
extracted-code vulnerability, reachable input parsing, elevated privileges
and alternate-kernel acceptance are not established.

## Decision after new JSON

Use authentic static dependency and import evidence to prioritize FOTA
file parsing, signature validation and update-path access-control research.
Absence from a short import allowlist does not prove an API is absent.
For deeper disassembly, the owner may privately attach the ELF to the
conversation, but must not run, publish or commit the binary.

A userland execution primitive would not by itself bypass Samsung's
kernel signature enforcement or prove stock recovery. Remain read-only on
the owner's only functional R840X.
