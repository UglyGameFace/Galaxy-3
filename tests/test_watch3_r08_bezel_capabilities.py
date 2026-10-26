"""Synthetic Watch3 bezel input-capability tests; NO device, event stream, or flash."""
from contextlib import redirect_stdout
from datetime import datetime, timezone
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from watch3_r08_bezel_capabilities import summarize_bezel
from watch3_r08_android_sdb import (
    ALLOWED_PROBES, BEZEL_PROBES, Connection, SdbError, VERSION,
    collect, frame, main, receive,
)

DEVICE_BLOCK = (
    'I: Bus=0019 Vendor=0001 Product=0001 Version=0100\n'
    'N: Name="tizen_detent"\n'
    'P: Phys=SENSITIVE-HARDWARE-PATH\n'
    'S: Sysfs=/devices/private-identifier/input/input22\n'
    'U: Uniq=PRIVATE-SERIAL\n'
    'H: Handlers=event18\n'
    'B: PROP=0\n'
    'B: EV=17\n'
    'B: REL=103\n'  # REL_X + REL_X? bit 1, REL_WHEEL bit 8
    'B: KEY=30000\n'
)
OTHER_BLOCK = (
    'I: Bus=0019 Vendor=0001 Product=0002 Version=0100\n'
    'N: Name="sec_touchscreen"\n'
    'H: Handlers=mouse0 event1\n'
    'B: EV=b\n'
    'B: KEY=ffffffffffffffffffff\n'
)
REGISTRY = OTHER_BLOCK + "\n" + DEVICE_BLOCK + "\n"


class FakeSocket:
    def __init__(self, raw):
        self.incoming = (
            frame(b"CNXN", VERSION, 256 * 1024, b"device::\0") +
            frame(b"OKAY", 9, 2) +
            frame(b"WRTE", 9, 2, raw.encode()) +
            frame(b"CLSE", 9, 2)
        )
        self.outgoing = bytearray()

    def recv(self, size):
        out, self.incoming = self.incoming[:size], self.incoming[size:]
        return out

    def sendall(self, value):
        self.outgoing.extend(value)

    def settimeout(self, *_):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *_):
        pass


class BezelCapabilityTests(unittest.TestCase):
    def test_tizen_detent_wheel_bit_and_private_metadata_redaction(self):
        stamp = datetime(2026, 10, 26, tzinfo=timezone.utc)
        report = summarize_bezel({"input_devices": REGISTRY}, {}, stamp)
        self.assertEqual(report["status"], "BEZEL_REL_WHEEL_ADVERTISED")
        self.assertEqual(report["input_name"], "tizen_detent")
        self.assertEqual(report["event_handler"], "event18")
        self.assertTrue(report["ev_rel_supported"])
        self.assertTrue(report["rel_wheel_supported"])
        self.assertTrue(report["rel_x_supported"])
        self.assertFalse(report["live_rotation_observed"])
        self.assertFalse(report["qt_wheel_delivery_observed"])
        self.assertFalse(report["firmware_changed"])
        output = json.dumps(report)
        for secret in ("SENSITIVE", "PRIVATE", "sec_touchscreen", "30000",
                       "Bus=0019", "ffffffff", "input22", "mouse0"):
            self.assertNotIn(secret, output)

    def test_not_hardcoded_event18_and_no_live_claim(self):
        reg = REGISTRY.replace("event18", "event7")
        report = summarize_bezel({"input_devices": reg}, {})
        self.assertEqual(report["event_handler"], "event7")
        self.assertFalse(report["live_rotation_observed"])

    def test_missing_wheel_bit_does_not_claim_support(self):
        report = summarize_bezel({"input_devices": REGISTRY.replace("REL=103", "REL=3")}, {})
        self.assertEqual(report["status"], "BEZEL_WHEEL_NOT_ADVERTISED")
        self.assertIs(report["rel_wheel_supported"], False)

    def test_ambiguous_and_bad_probes_fail_closed(self):
        samples = (
            "",
            "cat: /proc/bus/input/devices: permission denied",
            REGISTRY + DEVICE_BLOCK + "\n",
            REGISTRY.replace("N: Name=\\"tizen_detent\\"", "N: Name=\\"other\\""),
            REGISTRY.replace("H: Handlers=event18", "H: Handlers=event18 event19"),
            REGISTRY.replace("H: Handlers=event18", "H: Handlers=mouse0"),
            REGISTRY.replace("B: REL=103", "B: REL=xyz"),
            REGISTRY.replace("B: EV=17", "B: EV=1"),
            REGISTRY.replace("B: REL=103", "B: REL=103\nB: REL=103"),
        )
        for raw in samples:
            with self.subTest(first=raw[:80]):
                report = summarize_bezel({"input_devices": raw}, {})
                self.assertEqual(report["status"], "BEZEL_CAPABILITY_UNAVAILABLE")
                self.assertIsNone(report["event_handler"])
        self.assertEqual(
            summarize_bezel({"input_devices": REGISTRY}, {"input_devices": "denied"})["status"],
            "BEZEL_CAPABILITY_UNAVAILABLE"
        )
        self.assertEqual(summarize_bezel({}, {})["status"], "BEZEL_CAPABILITY_UNAVAILABLE")

    def test_only_fixed_text_registry_query_over_authenticated_sdb(self):
        fake = FakeSocket(REGISTRY)
        with patch("watch3_r08_android_sdb.socket.create_connection",
                   return_value=fake) as connection:
            actual, problems = collect("192.168.0.22", Path("/no-key"),
                                       probes=BEZEL_PROBES)
        connection.assert_called_once()
        self.assertFalse(problems)
        self.assertEqual(summarize_bezel(actual, {})["event_handler"], "event18")
        self.assertEqual(BEZEL_PROBES, {"input_devices": "cat /proc/bus/input/devices"})
        self.assertEqual(ALLOWED_PROBES["input_devices"], "cat /proc/bus/input/devices")
        remaining = bytes(fake.outgoing)
        class Reader:
            def recv(self, size):
                nonlocal remaining
                data, remaining = remaining[:size], remaining[size:]
                return data
        frames = []
        while remaining:
            frames.append(receive(Reader()))
        self.assertEqual(
            [x[3] for x in frames if x[0] == b"OPEN"],
            [b"shell:cat /proc/bus/input/devices\0"]
        )
        with self.assertRaisesRegex(SdbError, "allowlist"):
            Connection(fake, Path("/no-key")).shell("cat /dev/input/event18")
        with self.assertRaisesRegex(SdbError, "probe sets"):
            collect("192.168.0.22", Path("/no-key"), probes={"bad": "cat /etc/shadow"})

    def test_cli_redacted_report_and_unavailable_does_not_say_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            for data, errors, expected in (
                ({"input_devices": REGISTRY}, {}, "PASS"),
                ({}, {"input_devices": "denied"}, "UNAVAILABLE"),
            ):
                dest = Path(tmp)/("bezel-" + expected + ".json")
                args = ["watch3_r08_android_sdb.py", "--watch-ip", "192.168.0.22",
                        "--bezel-only", "--report", str(dest)]
                captured = io.StringIO()
                with patch.object(sys, "argv", args), patch(
                    "watch3_r08_android_sdb.collect", return_value=(data, errors),
                ) as conn, redirect_stdout(captured):
                    self.assertEqual(main(), 0)
                self.assertIs(conn.call_args.kwargs["probes"], BEZEL_PROBES)
                self.assertIn(expected, captured.getvalue())
                self.assertNotIn("SENSITIVE", dest.read_text())
                self.assertNotIn("PRIVATE", dest.read_text())
                if expected == "UNAVAILABLE":
                    self.assertNotIn("PASS:", captured.getvalue())
                    self.assertIsNone(json.loads(dest.read_text())["event_handler"])


if __name__ == "__main__":
    unittest.main()
