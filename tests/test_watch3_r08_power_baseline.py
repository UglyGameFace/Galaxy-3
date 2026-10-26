"""Synthetic off-device Watch3 gauge, comparison and SDB allowlist tests."""
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from watch3_r08_power_baseline import compare_snapshots, summarize_power
from watch3_r08_android_sdb import (
    Connection, POWER_PROBES, VERSION, SdbError, collect, frame, receive,
)

SAMPLE = (
    "POWER_SUPPLY_NAME=usb\nPOWER_SUPPLY_TYPE=USB\n"
    "POWER_SUPPLY_STATUS=Charging\n"
    "POWER_SUPPLY_NAME=battery\nPOWER_SUPPLY_TYPE=Battery\n"
    "POWER_SUPPLY_CAPACITY=79\nPOWER_SUPPLY_STATUS=Discharging\n"
    "POWER_SUPPLY_SERIAL_NUMBER=PRIVATE-WATCH-SECRET\n"
    "POWER_SUPPLY_VOLTAGE_NOW=3900000\n"
)


class FakeSocket:
    def __init__(self, raw: str):
        self.incoming = (
            frame(b"CNXN", VERSION, 256 * 1024, b"device::\x00") +
            frame(b"OKAY", 42, 2) +
            frame(b"WRTE", 42, 2, raw.encode()) +
            frame(b"CLSE", 42, 2)
        )
        self.sent = bytearray()

    def recv(self, length):
        piece, self.incoming = self.incoming[:length], self.incoming[length:]
        return piece

    def sendall(self, buf):
        self.sent.extend(buf)

    def settimeout(self, *_):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *_):
        pass


class BatteryBaselineTests(unittest.TestCase):
    def test_one_battery_not_usb_and_no_raw_data_leak(self):
        at = datetime(2026, 10, 26, 15, tzinfo=timezone.utc)
        report = summarize_power({"battery_uevent": SAMPLE}, {}, at)
        self.assertEqual(report["status"], "OBSERVED_TIZEN_BATTERY")
        self.assertEqual(report["capacity_percent"], 79)
        self.assertEqual(report["charging_state"], "Discharging")
        report_json = json.dumps(report)
        for secret in ("PRIVATE", "3900000", "USB", "usb", "battery_uevent="):
            self.assertNotIn(secret, report_json)
        self.assertTrue(report["captured_at_utc"].startswith("2026-10-26"))

    def test_unavailable_data_never_invents_battery_number(self):
        for raw in ("", "cat: /sys/class/power_supply/*/uevent: No such file",
                    "POWER_SUPPLY_NAME=battery\nPOWER_SUPPLY_TYPE=Battery\n"
                    "POWER_SUPPLY_CAPACITY=101\n",
                    "POWER_SUPPLY_NAME=battery\nPOWER_SUPPLY_TYPE=Battery\n"
                    "POWER_SUPPLY_CAPACITY=not-a-number\n"):
            with self.subTest(raw=raw):
                report = summarize_power({"battery_uevent": raw}, {})
                self.assertEqual(report["status"], "CAPACITY_UNAVAILABLE")
                self.assertIsNone(report["capacity_percent"])
        self.assertIsNone(summarize_power({}, {"battery_uevent": "No access"})
                          ["capacity_percent"])

    def test_ambiguous_multiple_batteries_fail_closed(self):
        two = SAMPLE + (
            "POWER_SUPPLY_NAME=other\nPOWER_SUPPLY_TYPE=Battery\n"
            "POWER_SUPPLY_CAPACITY=80\nPOWER_SUPPLY_STATUS=Discharging\n"
        )
        self.assertIsNone(summarize_power({"battery_uevent": two}, {})
                          ["capacity_percent"])

    def test_only_one_fixed_probe_through_real_sdb_protocol(self):
        fake = FakeSocket(SAMPLE)
        with patch("watch3_r08_android_sdb.socket.create_connection",
                   return_value=fake) as connect:
            observed, errors = collect("192.168.1.22", Path("/unused"),
                                       probes=POWER_PROBES)
        self.assertEqual(connect.call_count, 1)
        self.assertFalse(errors)
        self.assertIn("battery_uevent", observed)
        self.assertEqual(summarize_power(observed, errors)["capacity_percent"], 79)
        frames = []
        incoming = type("Reader", (), {"recv": lambda _, n: self._read(n)})()
        self._raw = bytes(fake.sent)
        while self._raw:
            frames.append(receive(incoming))
        openings = [x[3] for x in frames if x[0] == b"OPEN"]
        self.assertEqual(openings, [b"shell:cat /sys/class/power_supply/*/uevent\x00"])
        with self.assertRaisesRegex(SdbError, "allowlist"):
            Connection(FakeSocket(""), Path("/unused")).shell("power_supply")

    def _read(self, n):
        data, self._raw = self._raw[:n], self._raw[n:]
        return data

    def test_compare_rate_is_coarse_and_nonzero_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            start = Path(tmp) / "start.json"
            end = Path(tmp) / "end.json"
            t = datetime(2026, 10, 26, 15, tzinfo=timezone.utc)
            initial = summarize_power({"battery_uevent": SAMPLE}, {}, t)
            later = summarize_power({"battery_uevent": SAMPLE.replace(
                "CAPACITY=79", "CAPACITY=76")}, {}, t+timedelta(hours=3))
            start.write_text(json.dumps(initial))
            end.write_text(json.dumps(later))
            result = compare_snapshots(start, end)
            self.assertEqual(result["observed_pp_per_hour"], 1)
            self.assertEqual(result["result"], "COARSE_DISCHARGE_OBSERVATION")
            self.assertNotIn("PRIVATE", json.dumps(result))
            later["capacity_percent"] = 79
            end.write_text(json.dumps(later))
            self.assertIsNone(compare_snapshots(start, end)["observed_pp_per_hour"])
            later["charging_state"] = "Charging"
            end.write_text(json.dumps(later))
            with self.assertRaisesRegex(ValueError, "Discharging"):
                compare_snapshots(start, end)

    def test_compare_rejects_misordered_short_malformed_missing_and_symlinks(self):
        with tempfile.TemporaryDirectory() as tmp:
            first, second = Path(tmp)/"a.json", Path(tmp)/"b.json"
            t = datetime(2026, 10, 26, 15, tzinfo=timezone.utc)
            start = summarize_power({"battery_uevent": SAMPLE}, {}, t)
            end = summarize_power({"battery_uevent": SAMPLE}, {}, t+timedelta(minutes=10))
            first.write_text(json.dumps(start))
            second.write_text(json.dumps(end))
            with self.assertRaisesRegex(ValueError, "30 minutes"):
                compare_snapshots(first, second)
            second.write_text('{"malformed":true}')
            with self.assertRaisesRegex(ValueError, "schema"):
                compare_snapshots(first, second)
            second.unlink()
            second.symlink_to(first)
            with self.assertRaisesRegex(ValueError, "regular"):
                compare_snapshots(first, second)


if __name__ == "__main__":
    unittest.main()
