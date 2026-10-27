"""Synthetic boot-memory inventory tests. Never connect, read partitions or flash."""
from datetime import datetime, timezone
import io
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
from contextlib import redirect_stdout

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from watch3_r08_boot_memory import summarize_memory
from watch3_r08_android_sdb import BOOT_MEMORY_PROBES, ALLOWED_PROBES, SdbError, collect, Connection, main

MEM = """MemTotal:         923412 kB
MemFree:           28420 kB
MemAvailable:     482312 kB
Device-Serial:    PRIVATE-SERIAL
"""
IOMEM = """00000000-00000fff : LOW SECRET
 80000000-9fffffff : System RAM
   80000000-800fffff : Kernel code
 a0000000-bfffffff : System RAM
 c0000000-c0000fff : SECRET-MMIO
"""


class BootMemoryTests(unittest.TestCase):
    def test_actual_system_ram_ranges_only_and_never_a_bootloader_pass(self):
        r = summarize_memory({"meminfo": MEM, "iomem": IOMEM}, {},
                            datetime(2026, 10, 27, tzinfo=timezone.utc))
        self.assertEqual(r["status"], "LIVE_RAM_REGIONS_OBSERVED")
        self.assertEqual(r["memtotal_kib"], 923412)
        self.assertEqual(r["system_ram_bytes"], 0x40000000)
        self.assertEqual(r["system_ram_ranges"], [
            {"start": "0x80000000", "end_inclusive": "0x9fffffff"},
            {"start": "0xa0000000", "end_inclusive": "0xbfffffff"},
        ])
        self.assertFalse(r["physical_ram_size_proven"])
        self.assertFalse(r["custom_boot_accepted"])
        self.assertFalse(r["recovery_proven"])
        self.assertFalse(r["firmware_changed"])
        for secret in ("PRIVATE", "SECRET", "Kernel code", "0xc0000000"):
            self.assertNotIn(secret, str(r))

    def test_historical_r08_dts_not_mistaken_for_live_evidence(self):
        r = summarize_memory({}, {})
        self.assertEqual(r["status"], "LIVE_MEMORY_UNAVAILABLE")
        self.assertIsNone(r["memtotal_kib"])
        self.assertEqual(r["system_ram_ranges"], [])
        self.assertFalse(r["reference_dts_is_live_proof"])
        self.assertIn("0x80000000", r["reference_dts_ram_window"])
        self.assertIn("0x84000000", r["reference_dts_initrd_window"])

    def test_masked_iomem_is_not_physical_memory_confirmation(self):
        r = summarize_memory(
            {"meminfo": MEM, "iomem": "00000000-00000000 : System RAM\n"}, {})
        self.assertEqual(r["status"], "LIVE_MEMTOTAL_ONLY")
        self.assertEqual(r["memtotal_kib"], 923412)
        self.assertIsNone(r["system_ram_bytes"])
        self.assertEqual(r["system_ram_ranges"], [])

    def test_fails_closed_malformed_and_overlapping_ranges(self):
        for bad in (
            "80000000-9fffffff : System RAM\n90000000-bfffffff : System RAM\n",
            "80000000-9fffffff : System RAM\n  NOT A RANGE System RAM\n",
            "00000000-3fffffff : System RAM\n",
            "80000000-80000000 : System RAM\n",
            "80000000-9fffffff : System RAM\n" * 25,
        ):
            with self.subTest(bad=bad[:45]):
                r = summarize_memory({"meminfo": MEM, "iomem": bad}, {})
                self.assertNotEqual(r["status"], "LIVE_RAM_REGIONS_OBSERVED")
                self.assertEqual(r["system_ram_ranges"], [])
        r = summarize_memory({"meminfo": MEM, "iomem": IOMEM},
                             {"iomem": "permission denied"})
        self.assertEqual(r["status"], "LIVE_MEMTOTAL_ONLY")

    def test_duplicate_or_invalid_memtotal_not_saved(self):
        for value in ("MemTotal: 999999999999 kB\n",
                      "MemTotal: 1000 kB\n",
                      "MemTotal: 923412 kB\nMemTotal: 923412 kB\n",
                      "MemTotal: three kB\n"):
            with self.subTest(value=value):
                r = summarize_memory({"meminfo": value}, {})
                self.assertIsNone(r["memtotal_kib"])

    def test_sdb_mode_has_no_other_commands_or_root_paths(self):
        self.assertEqual(BOOT_MEMORY_PROBES, {
            "meminfo": "cat /proc/meminfo",
            "iomem": "cat /proc/iomem",
        })
        for cmd in BOOT_MEMORY_PROBES.values():
            self.assertIn(cmd, ALLOWED_PROBES.values())
            for bad in ("dd ", "/dev/", "reboot", "mount", "sh ", "od ", "flash"):
                self.assertNotIn(bad, cmd)
        with self.assertRaisesRegex(SdbError, "probe sets"):
            collect("192.168.0.3", Path("/not-used"), probes={"rogue": "id"})
        with self.assertRaisesRegex(SdbError, "allowlist"):
            Connection(None, Path("/not-used")).shell("cat /dev/mmcblk0")

    def test_cli_uses_exact_two_probes_and_local_privacy_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / "redacted.json"
            with patch.object(sys, "argv", [
                "watch3_r08_android_sdb.py", "--watch-ip", "192.168.2.3",
                "--boot-memory-only", "--report", str(dest)
            ]), patch("watch3_r08_android_sdb.collect",
                     return_value=({"meminfo": MEM, "iomem": IOMEM}, {})) as caller:
                with redirect_stdout(io.StringIO()):
                    self.assertEqual(main(), 0)
            self.assertIs(caller.call_args.kwargs["probes"], BOOT_MEMORY_PROBES)
            result = dest.read_text()
            self.assertIn("LIVE_RAM_REGIONS_OBSERVED", result)
            self.assertNotIn("PRIVATE-SERIAL", result)
            self.assertNotIn("SECRET-MMIO", result)


if __name__ == "__main__":
    unittest.main()
