"""Synthetic-only tests; never requires SDB or communicates with a watch."""
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "tools"))
import probe_watch3_audio_readonly as probe


class ProbeTests(unittest.TestCase):
    def test_rejects_truncated_remote_output(self):
        ok, msg = probe.interpret("W3_AUDIO_PROBE_V1\nFOUND|calliope_sram.bin|READABLE|/vendor/firmware/calliope_sram.bin")
        self.assertFalse(ok)
        self.assertIn("Incomplete", msg)

    def test_reports_observed_not_device_firmware_identity(self):
        example = (
            "SDB daemon banner ignored\nW3_AUDIO_PROBE_V1\n"
            "FOUND|calliope_sram.bin|READABLE|/vendor/firmware/calliope_sram.bin\n"
            "FOUND|APDV_AUDIO_SLSI.bin|PRESENT_NOT_READABLE|/lib/firmware/APDV_AUDIO_SLSI.bin\n"
            "CARD| 0 [Exynos9110Sound ]: Exynos9110-Sound - Exynos9110-Sound\n"
            "PCM|00-00: ABOX RDMA0 : : playback 1\n"
            "W3_AUDIO_PROBE_END\n")
        ok, report = probe.interpret(example)
        self.assertTrue(ok)
        self.assertIn("calliope_sram.bin (core): READABLE", report)
        self.assertIn("calliope_dram.bin (core): NOT_OBSERVED_IN_TESTED_PATHS", report)
        self.assertIn("APDV_AUDIO_SLSI.bin (auxiliary): PRESENT_NOT_READABLE", report)
        self.assertIn("CARD_MATCH_OBSERVED", report)
        self.assertIn("not proof of absence", report)
        self.assertIn("No firmware contents read", report)

    def test_empty_alsa_is_not_a_successful_card_claim(self):
        example = "W3_AUDIO_PROBE_V1\nCARD_NOT_ACCESSIBLE\nPCM_NOT_ACCESSIBLE\nW3_AUDIO_PROBE_END\n"
        ok, report = probe.interpret(example)
        self.assertTrue(ok)
        self.assertIn("NOT_ACCESSIBLE_OR_EMPTY", report)
        self.assertNotIn("CARD_MATCH_OBSERVED", report)

    def test_remote_script_only_reads(self):
        source = probe.REMOTE_SCRIPT
        self.assertIn(" /proc/asound/cards", source)
        self.assertIn(" /proc/asound/pcm", source)
        self.assertIn("W3_AUDIO_PROBE_END", source)
        for banned in ("sdb root", "dd if=", "mount ", "chmod ", "chown ",
                       "rm -", "mv ", "cp ", "amixer ", "aplay ", "modprobe ",
                       "insmod ", "tee ", "flash ", "sudo "):
            self.assertNotIn(banned, source)


if __name__ == "__main__":
    unittest.main()
