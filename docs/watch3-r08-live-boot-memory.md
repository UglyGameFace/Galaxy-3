# R08 boot research: live Tizen RAM region vs historical reference

**Boot/stock recovery remains NO-GO** until a physically verified reversible loader and exact R840X stock restoration exist. This measurement only helps reject invented memory addresses.

## The discrepancy that matters

The historical [Samsung R08 DTS](https://github.com/UsrBinLuna/kernel_samsung_galileo/blob/ec258e12887d37362b59e3291c1d3e5363c24bff/arch/arm64/boot/dts/exynos/exynos9110-tizen_noblesse_large_bt-r08.dtsi) says:

- `memory@80000000 reg=<0x0 0x80000000 0x60000000>`, describing a **1.5 GiB address window**;
- `linux,initrd-start=0x84000000`, `linux,initrd-end=0x841fffff`, approximately 2 MiB of historical early RAM disk allocation;
- `root=/dev/ram0` in `/chosen/bootargs`.

This is a **pinned historical source file**. It does not prove how much DRAM the installed R840X physically has, or whether those addresses are safe to reuse during a future alternate boot. The Galaxy Watch3 is commonly specified with **1 GB RAM**, and runtime reserved memory or device-tree source variants may explain the difference. `/proc/meminfo` is Linux's usable memory estimate; `/proc/iomem` can describe resource regions but may be masked for a normal SDB user. Neither authorizes a kernel jump.

## Already authenticated watch access: read-only SDB only

Run after this PR merges using your current watch Wi-Fi IP (the address below was previously observed but may have changed):

```sh
cd ~/Galaxy-3 && git pull --ff-only
python tools/watch3_r08_android_sdb.py --watch-ip 10.54.86.131 --boot-memory-only
cat ~/watch3-r08-boot-memory-redacted.json
```

The existing authenticated SDB client executes exactly:

```text
cat /proc/meminfo
cat /proc/iomem
```

The new option is **mutually exclusive** with all other modes. It neither enters wireless download nor opens a block device, writes partitions, captures keys, reboots, installs packages, changes kernel settings or transmits any exploit. No arbitrary shell command flag is added.

Only `MemTotal` and exact `System RAM` spans from `/proc/iomem` are saved to the local JSON. All other lines containing unique identifiers, reserved hardware resources, physical device addresses or driver details are dropped. If the watch masks `/proc/iomem`, the report says `LIVE_MEMTOTAL_ONLY` rather than fabricating a usable memory map. Malformed or overlapping regions are not accepted.

**Success means only a read-only memory observation**. No installed DRAM capacity, safe alternate-loader address, bootloader exploit, privileged memory access, exact PIT, or signed recovery is thereby verified.

## Next concrete boot-chain gate

Use the real RAM results to eliminate invalid *hypothetical* in-memory loader layouts and reconcile the vendor DTS. Independently locate an authenticated R840X bootloader/recovery source or a documented board service interface. Dynamic loader testing still requires a safely recoverable device and stock rescue, preferably an expendable matching unit. Do not flash.
