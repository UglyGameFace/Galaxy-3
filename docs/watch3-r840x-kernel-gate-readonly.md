# SM-R840X kernel-route gate: read-only facts before any LPE research

Issue #47. November 20, 2026.

The November 2026 kernel survey reduced the public local
privilege-escalation landscape for this watch's Linux 4.9.59 kernel
to gate questions that are answerable read-only:

- Is the kernel/userspace 32-bit or 64-bit? (`uname -m`) Public PoCs
  are architecture-specific; the R810 evidence (dzImage, Thumb-2)
  suggests 32-bit, but this watch has never stated its own class.
- Does an Android Binder device node exist? The one candidate family
  with a reliable public exploit lineage, CVE-2019-2215, lives in the
  Binder driver. Tizen's IPC is D-Bus, so Binder may not be compiled
  in at all. No node, no route — regardless of patch state.
- Is unprivileged eBPF disabled? The 4.9-era eBPF verifier bugs need
  `CONFIG_BPF_SYSCALL` plus unprivileged access; the sysctl value
  closes or narrows that family without touching it.

## The collector

`tools/watch3_r840x_kernel_gate_readonly.py` runs exactly four fixed
allowlisted SDB shell probes (`KERNEL_GATE_PROBES` in
`tools/watch3_r08_android_sdb.py`): `uname -m`, `ls /dev/binder`,
`ls /dev/binderfs/binder-control`, and
`cat /proc/sys/kernel/unprivileged_bpf_disabled`. It opens no device,
loads nothing, submits nothing, and writes nothing to the watch.
Reports retain only categories (machine class, node presence class,
BPF class); raw output is discarded before the report is written.

```sh
cd ~/Galaxy-3 && git switch main && git pull --ff-only &&
python tools/watch3_r840x_kernel_gate_readonly.py \
  --kernel-gate-ip <CURRENT_WATCH_IP> \
  --report ~/watch3-kernel-gate-20261120.json
```

## How the result may be read

- `BINDER_NODE_ABSENT_GATE_CLOSED`: both node probes absent. The
  Binder LPE family is closed for this device; kernel-LPE research
  should stop, as the D-Bus provenance line did.
- `BINDER_NODE_PRESENT_GATE_OPEN`: research may continue into
  whether Samsung's 4.9.59 tree carries the CVE-2019-2215 fix. Node
  presence proves nothing about patch state, reachability under
  SMACK, or exploitability, and authorizes no exploit attempt.
- Any `UNDETERMINED` field is a failed probe, not evidence.

Root, bootloader unlock and stock recovery remain unproven, and
firmware writes remain NO-GO regardless of this report.
