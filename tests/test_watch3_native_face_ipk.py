"""Regression tests for Yocto's real control.tar.gz + data.tar.zst IPK."""
from __future__ import annotations
import gzip
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from validate_watch3_native_face_ipk import read_real_ipk, verify_native_ipk, PackageError
from validate_uglyos_face_package import FACES


def tar_bytes(files, with_dirs=False):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as tar:
        if with_dirs:
            dirs = set()
            for name in files:
                p = Path(name).parent
                while str(p) != ".":
                    dirs.add(p.as_posix())
                    p = p.parent
            for dirname in sorted(dirs):
                item = tarfile.TarInfo("./" + dirname)
                item.type = tarfile.DIRTYPE
                item.mode = 0o755
                tar.addfile(item)
        for name, data in files.items():
            item = tarfile.TarInfo("./" + name)
            item.size = len(data)
            item.mode = 0o644
            tar.addfile(item, io.BytesIO(data))
    return output.getvalue()


class NativeIpkTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.source = self.root / "src"
        self.source.mkdir()
        self.stage = self.root / "image"
        self.pkgdest = self.root / "packages-split"
        self.payload = {}
        for name in FACES:
            data = ("// " + name).encode()
            self.payload[f"usr/share/asteroid-launcher/watchfaces/{name}"] = data
            (self.source / name).write_bytes(data)
        edition = json.dumps({"display_name": "UgLy|OS", "slug": "uglyos",
                              "base_system": "AsteroidOS", "boot_status": "not-boot-tested",
                              "install_status": "not-flashable"}).encode()
        self.payload["usr/share/uglyos/edition.json"] = edition
        (self.source / "uglyos-edition.json").write_bytes(edition)
        for root in (self.stage, self.pkgdest / "watch3-faces"):
            for path, data in self.payload.items():
                f = root / path
                f.parent.mkdir(parents=True, exist_ok=True)
                f.write_bytes(data)
        self.info = {"D": str(self.stage), "PKGDEST": str(self.pkgdest),
                     "datadir": "/usr/share", "PV": "1.0", "PR": "r0",
                     "PACKAGE_ARCH": "noblesse_r08"}
        self.file = self.root / "watch3-faces_1.0-r0_noblesse_r08.ipk"
        self.write_ipk()

    def write_ipk(self, *, control=None, payload=None, method="zst"):
        control = control or {
            "Package": "watch3-faces", "Version": "1.0-r0",
            "Architecture": "noblesse_r08", "Depends": "asteroid-launcher"}
        control_text = "".join(f"{key}: {value}\n" for key, value in control.items()).encode()
        package_payload = tar_bytes(self.payload if payload is None else payload, with_dirs=True)
        if method == "zst":
            package_payload = subprocess.run(["zstd", "-q", "-c"], input=package_payload,
                                             capture_output=True, check=True).stdout
        else:
            package_payload = gzip.compress(package_payload, mtime=0)
        parts = {"debian-binary": b"2.0\n",
                 "control.tar.gz": gzip.compress(tar_bytes({"control": control_text}), mtime=0),
                 "data.tar.zst" if method == "zst" else "data.tar.gz": package_payload}
        for name, content in parts.items():
            (self.root / name).write_bytes(content)
        if self.file.exists():
            self.file.unlink()
        subprocess.run(["ar", "q", str(self.file), *parts], cwd=self.root,
                       capture_output=True, check=True)

    def test_reads_yocto_zstandard_data_and_directory_entries(self):
        fields, files = read_real_ipk(self.file)
        self.assertEqual(fields["Architecture"], "noblesse_r08")
        self.assertEqual(files, self.payload)
        self.assertEqual(len(verify_native_ipk(self.info, self.source, self.file)), 64)

    def test_accepts_gzip_data_variant(self):
        self.write_ipk(method="gz")
        verify_native_ipk(self.info, self.source, self.file)

    def test_rejects_changed_payload(self):
        payload = dict(self.payload)
        payload["usr/share/uglyos/edition.json"] = b"tampered"
        self.write_ipk(payload=payload)
        with self.assertRaisesRegex(PackageError, "payload mismatch"):
            verify_native_ipk(self.info, self.source, self.file)

    def test_rejects_wrong_architecture(self):
        self.write_ipk(control={"Package":"watch3-faces", "Version":"1.0-r0",
                                "Architecture":"arm64", "Depends":"asteroid-launcher"})
        with self.assertRaisesRegex(PackageError, "Architecture"):
            verify_native_ipk(self.info, self.source, self.file)

    def test_rejects_missing_runtime_dependency(self):
        self.write_ipk(control={"Package":"watch3-faces", "Version":"1.0-r0",
                                "Architecture":"noblesse_r08", "Depends":"libc6"})
        with self.assertRaisesRegex(PackageError, "runtime dependency"):
            verify_native_ipk(self.info, self.source, self.file)

    def test_rejects_unexpected_archive_payload(self):
        payload = dict(self.payload)
        payload["etc/unsafe"] = b"extra"
        self.write_ipk(payload=payload)
        with self.assertRaisesRegex(PackageError, "payload paths differ"):
            verify_native_ipk(self.info, self.source, self.file)


if __name__ == "__main__":
    unittest.main()
