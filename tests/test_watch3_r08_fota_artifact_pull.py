"""No-watch fake SDB peer for exact-path, bounded, read-only FOTA artifact pull."""
from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
import socket
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from watch3_r08_android_sdb import VERSION, frame, receive
from watch3_r08_fota_artifact_pull import (
    ArtifactPullError, FOTA_EXECUTABLE, LOCAL_STREAM, MAX_BINARY_BYTES,
    SYNC_HDR, ReadOnlySyncDecoder, capture, pull_fota,
)


class FakeSocket:
    def __init__(self, incoming: bytes):
        self.incoming = incoming
        self.sent = bytearray()
        self.timeout = None

    def recv(self, count):
        chunk, self.incoming = self.incoming[:count], self.incoming[count:]
        return chunk

    def sendall(self, data):
        self.sent.extend(data)

    def settimeout(self, timeout):
        self.timeout = timeout

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False


def elf32(body=b"content"):
    head = bytearray(20)
    head[:4] = b"\x7fELF"
    head[4] = 1
    head[5] = 1
    head[18:20] = (40).to_bytes(2, "little")
    return bytes(head) + body


def sdb_peer(sync_frames: list[bytes]) -> FakeSocket:
    incoming = (
        frame(b"CNXN", VERSION, 256 * 1024, b"device::\x00")
        + frame(b"OKAY", 42, LOCAL_STREAM)
        + frame(b"OKAY", 42, LOCAL_STREAM)
        + b"".join(frame(b"WRTE", 42, LOCAL_STREAM, piece) for piece in sync_frames)
    )
    return FakeSocket(incoming)


def requests(sent: bytes):
    sock = FakeSocket(sent)
    frames = []
    while sock.incoming:
        frames.append(receive(sock))
    return frames


class FotaArtifactTests(unittest.TestCase):
    def test_successful_split_sync_payload_is_binary_exact_and_read_only(self):
        binary = elf32(b"\x00\xff\x99" * 18)
        data = SYNC_HDR.pack(b"DATA", len(binary)) + binary
        done = SYNC_HDR.pack(b"DONE", 0)
        # Fragment even the nested 8-byte DATA header.
        sock = sdb_peer([data[:3], data[3:10], data[10:], done])
        out = io.BytesIO()
        result = pull_fota(sock, Path("/no-auth-needed"), out)
        self.assertEqual(out.getvalue(), binary)
        self.assertEqual(result["status"], "READABLE_BINARY_COPIED_FROM_AUTHENTICATED_SDB")
        self.assertEqual(result["sha256"], hashlib.sha256(binary).hexdigest())
        self.assertEqual(result["elf_kind"], "ARM_ELF32")
        self.assertEqual(result["bytes"], len(binary))
        self.assertFalse(result["root_obtained"])
        self.assertFalse(result["watch_write_performed"])
        emitted = requests(bytes(sock.sent))
        self.assertEqual([f[0] for f in emitted[:3]], [b"CNXN", b"OPEN", b"WRTE"])
        self.assertEqual(emitted[1][3], b"sync:\x00")
        self.assertEqual(emitted[2][3], SYNC_HDR.pack(b"RECV", len(FOTA_EXECUTABLE)) + FOTA_EXECUTABLE)
        self.assertEqual(sum(f[0] == b"OKAY" for f in emitted), 4)
        self.assertEqual(sum(f[0] == b"WRTE" for f in emitted), 1)
        self.assertNotIn(b"SEND", bytes(sock.sent))
        self.assertNotIn(b"DELE", bytes(sock.sent))
        self.assertNotIn(b"exec", bytes(sock.sent).lower())

    def test_aarch64_elf_header_is_recognized(self):
        header = bytearray(20)
        header[:4] = b"\x7fELF"
        header[4:6] = b"\x02\x01"
        header[18:20] = (183).to_bytes(2, "little")
        sock = sdb_peer([SYNC_HDR.pack(b"DATA", len(header)) + bytes(header),
                         SYNC_HDR.pack(b"DONE", 0)])
        self.assertEqual(pull_fota(sock, Path("/unused"), io.BytesIO())["elf_kind"],
                         "AARCH64_ELF64")

    def test_watch_denial_is_categorized_without_leaking_message(self):
        msg = b"private-watch-serial: permission denied"
        sock = sdb_peer([SYNC_HDR.pack(b"FAIL", len(msg)) + msg])
        with self.assertRaises(ArtifactPullError) as exc:
            pull_fota(sock, Path("/unused"), io.BytesIO())
        self.assertEqual(str(exc.exception), "REMOTE_FILE_MISSING_DENIED_OR_UNREADABLE")
        self.assertNotIn("serial", str(exc.exception))

    def test_refusal_before_open_is_not_success(self):
        sock = FakeSocket(frame(b"CNXN", VERSION, 256 * 1024, b"device::\x00")
                          + frame(b"CLSE", 0, LOCAL_STREAM))
        with self.assertRaisesRegex(ArtifactPullError, "SDB_SYNC_SERVICE_REFUSED"):
            pull_fota(sock, Path("/unused"), io.BytesIO())

    def test_no_done_is_not_mistaken_for_success(self):
        binary = elf32()
        sock = sdb_peer([SYNC_HDR.pack(b"DATA", len(binary)) + binary,
                         SYNC_HDR.pack(b"DATA", 0)])
        with self.assertRaisesRegex(Exception, "closed"):
            pull_fota(sock, Path("/unused"), io.BytesIO())

    def test_zero_byte_done_and_invalid_elf_are_rejected(self):
        sock = sdb_peer([SYNC_HDR.pack(b"DONE", 0)])
        with self.assertRaisesRegex(ArtifactPullError, "INVALID_SYNC_DONE"):
            pull_fota(sock, Path("/unused"), io.BytesIO())
        sock = sdb_peer([SYNC_HDR.pack(b"DATA", 5) + b"hello",
                         SYNC_HDR.pack(b"DONE", 0)])
        with self.assertRaisesRegex(ArtifactPullError, "NOT_LITTLE_ENDIAN_ELF"):
            pull_fota(sock, Path("/unused"), io.BytesIO())

    def test_oversize_rejected_before_writing_body(self):
        sock = sdb_peer([SYNC_HDR.pack(b"DATA", MAX_BINARY_BYTES + 1)])
        with self.assertRaisesRegex(ArtifactPullError, "UNBOUNDED_SYNC_MESSAGE"):
            pull_fota(sock, Path("/unused"), io.BytesIO())

    def test_wrong_sdb_stream_fails_closed(self):
        sock = FakeSocket(
            frame(b"CNXN", VERSION, 256 * 1024, b"device::\x00")
            + frame(b"OKAY", 42, LOCAL_STREAM)
            + frame(b"WRTE", 41, LOCAL_STREAM, SYNC_HDR.pack(b"DONE", 0))
        )
        with self.assertRaisesRegex(ArtifactPullError, "STREAM_ID_MISMATCH"):
            pull_fota(sock, Path("/unused"), io.BytesIO())

    def test_capture_saves_only_local_private_binary_no_watch_writes(self):
        binary = elf32(b"proven")
        sock = sdb_peer([SYNC_HDR.pack(b"DATA", len(binary)) + binary,
                         SYNC_HDR.pack(b"DONE", 0)])
        with tempfile.TemporaryDirectory() as td:
            file = Path(td) / "sample.bin"
            with patch("watch3_r08_fota_artifact_pull.socket.create_connection",
                       return_value=sock):
                result = capture("10.0.0.65", Path("/unused"), file)
            self.assertEqual(file.read_bytes(), binary)
            self.assertEqual(file.stat().st_mode & 0o077, 0)
            self.assertEqual(result["bytes"], len(binary))
            with self.assertRaisesRegex(ArtifactPullError, "LOCAL_OUTPUT_ALREADY_EXISTS"):
                capture("10.0.0.65", Path("/unused"), file)

    def test_failure_removes_phone_temp_and_keeps_no_artifact(self):
        msg = b"No such file or directory"
        sock = sdb_peer([SYNC_HDR.pack(b"FAIL", len(msg)) + msg])
        with tempfile.TemporaryDirectory() as td:
            dest = Path(td) / "fota.bin"
            with patch("watch3_r08_fota_artifact_pull.socket.create_connection",
                       return_value=sock):
                with self.assertRaises(ArtifactPullError):
                    capture("10.0.0.65", Path("/unused"), dest)
            self.assertFalse(dest.exists())
            self.assertEqual(list(Path(td).iterdir()), [])

    def test_nonlocal_and_injected_paths_rejected_before_socket(self):
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaisesRegex(Exception, "Only local-network"):
                capture("8.8.8.8", Path("/unused"), Path(td) / "x.bin")
        self.assertNotIn(b"/dev/mmc", FOTA_EXECUTABLE)
        self.assertNotIn(b"..", FOTA_EXECUTABLE)
        self.assertEqual(FOTA_EXECUTABLE.count(b"/"), 5)


if __name__ == "__main__":
    unittest.main()
