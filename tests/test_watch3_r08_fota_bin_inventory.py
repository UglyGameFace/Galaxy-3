"""Synthetic Watch3 SDB sync LIST peer only. No physical watch or OTA."""
from __future__ import annotations

import json
from pathlib import Path
import stat
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from watch3_r08_android_sdb import VERSION, frame, receive
from watch3_r08_fota_bin_inventory import (
    FOTA_BIN_DIRECTORY, LOCAL_STREAM, SYNC_HEADER, DENT_HEADER,
    InventoryError, SyncListDecoder, collect, inventory,
)


class FakeSocket:
    def __init__(self, incoming):
        self.incoming = incoming
        self.sent = bytearray()

    def recv(self, count):
        data, self.incoming = self.incoming[:count], self.incoming[count:]
        return data

    def sendall(self, data):
        self.sent.extend(data)

    def settimeout(self, timeout):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def dent(name, mode=stat.S_IFREG | 0o755, size=87036):
    bname = name if isinstance(name, bytes) else name.encode()
    return DENT_HEADER.pack(b"DENT", mode, size, 1000, len(bname)) + bname


def done():
    return DENT_HEADER.pack(b"DONE", 0, 0, 0, 0)


def peer(fragments):
    return FakeSocket(
        frame(b"CNXN", VERSION, 262144, b"device::\x00")
        + frame(b"OKAY", 52, LOCAL_STREAM)
        + frame(b"OKAY", 52, LOCAL_STREAM)
        + b"".join(frame(b"WRTE", 52, LOCAL_STREAM, item) for item in fragments)
    )


def sent_frames(sent):
    fake = FakeSocket(bytes(sent))
    values = []
    while fake.incoming:
        values.append(receive(fake))
    return values


class FotaBinInventoryTests(unittest.TestCase):
    def test_auth_sdb_sends_one_exact_directory_only(self):
        directory = dent("fota-service") + dent("fota-syspopup", size=1234) + done()
        sock = peer([directory[:3], directory[3:18], directory[18:60], directory[60:]])
        report = inventory(sock, Path("/unused"))
        self.assertEqual(report["status"], "FOTA_PACKAGE_BIN_DIRECTORY_LISTED")
        self.assertEqual(report["total_entries"], 2)
        self.assertEqual([i["name"] for i in report["entries"]],
                         ["fota-service", "fota-syspopup"])
        self.assertEqual(report["entries"][0]["size_bytes"], 87036)
        self.assertFalse(report["watch_write_performed"])
        frames = sent_frames(sock.sent)
        self.assertEqual([f[0] for f in frames[:3]], [b"CNXN", b"OPEN", b"WRTE"])
        self.assertEqual(frames[1][3], b"sync:\x00")
        self.assertEqual(frames[2][3],
                         SYNC_HEADER.pack(b"LIST", len(FOTA_BIN_DIRECTORY))
                         + FOTA_BIN_DIRECTORY)
        self.assertEqual(sum(f[0] == b"WRTE" for f in frames), 1)
        self.assertEqual(sum(f[0] == b"OKAY" for f in frames), 4)
        self.assertNotIn(b"SEND", bytes(sock.sent))
        self.assertNotIn(b"RECV", bytes(sock.sent))
        self.assertNotIn(b"DELE", bytes(sock.sent))

    def test_redacts_unknown_and_traversal_names(self):
        result = SyncListDecoder()
        result.feed(dent("fota-service") + dent("otherfile")
                    + dent("../../secret") + dent(b"\xff-private")
                    + dent("fota-APP", mode=stat.S_IFLNK | 0o777)
                    + done())
        report = result.report()
        self.assertEqual(report["total_entries"], 5)
        self.assertEqual(report["redacted_other_entries"], 3)
        self.assertEqual([e["name"] for e in report["entries"]],
                         ["fota-APP", "fota-service"])
        self.assertEqual(report["entries"][0]["kind"], "SYMLINK")
        serial = json.dumps(report)
        self.assertNotIn("secret", serial)
        self.assertNotIn("otherfile", serial)

    def test_fail_reply_never_leaks_remote_message(self):
        msg = b"permission denied for PRIVATE_WATCH_ID_1234"
        sock = peer([SYNC_HEADER.pack(b"FAIL", len(msg)) + msg])
        with self.assertRaisesRegex(InventoryError,
                                    "FOTA_DIRECTORY_MISSING_DENIED_OR_UNREADABLE") as err:
            inventory(sock, Path("/unused"))
        self.assertNotIn("PRIVATE_WATCH_ID", str(err.exception))

    def test_wrong_frame_stream_cannot_produce_inventory(self):
        sock = FakeSocket(
            frame(b"CNXN", VERSION, 262144, b"device::\x00")
            + frame(b"OKAY", 52, LOCAL_STREAM)
            + frame(b"WRTE", 99, LOCAL_STREAM, done())
        )
        with self.assertRaisesRegex(InventoryError,
                                    "SDB_DIRECTORY_STREAM_ID_MISMATCH"):
            inventory(sock, Path("/unused"))

    def test_declined_sync_open_fails_closed(self):
        sock = FakeSocket(
            frame(b"CNXN", VERSION, 262144, b"device::\x00")
            + frame(b"CLSE", 0, LOCAL_STREAM)
        )
        with self.assertRaisesRegex(InventoryError,
                                    "SDB_SYNC_DIRECTORY_SERVICE_REFUSED"):
            inventory(sock, Path("/unused"))

    def test_refuses_malformed_directory_wire_records(self):
        for entry in (
            b"UNKN",
            DENT_HEADER.pack(b"DENT", 0, 10, 0, 129),
            DENT_HEADER.pack(b"DONE", 1, 0, 0, 0),
            done() + b"private trailing bytes",
        ):
            with self.subTest(entry=entry[:4]):
                decoder = SyncListDecoder()
                with self.assertRaises(InventoryError):
                    decoder.feed(entry)

    def test_incomplete_stream_rejected(self):
        sock = peer([dent("fota-service")])
        with self.assertRaisesRegex(Exception, "closed"):
            inventory(sock, Path("/unused"))

    def test_local_network_only(self):
        with self.assertRaisesRegex(Exception, "Only local-network"):
            collect("8.8.8.8", Path("/unused"))

    def test_many_entries_rejected(self):
        decoder = SyncListDecoder()
        with self.assertRaisesRegex(InventoryError, "TOO_MANY_ITEMS"):
            decoder.feed(dent("fota-service") * 513)

    def test_no_arbitrary_remote_paths_or_sdb_write_protocol(self):
        from watch3_r08_fota_bin_inventory import __file__ as script
        source = Path(script).read_text()
        for banned in ('b"SEND"', 'b"RECV"', 'b"DELE"', '"shell:"',
                       "execve(", "subprocess", "os.system(", "eval("):
            self.assertNotIn(banned, source)
        self.assertEqual(FOTA_BIN_DIRECTORY,
                         b"/usr/apps/com.samsung.fota-consumer/bin")


if __name__ == "__main__":
    unittest.main()
