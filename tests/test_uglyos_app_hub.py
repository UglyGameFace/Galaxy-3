"""UgLy|OS App Hub catalog must never make APK/opkg apps installable."""
from __future__ import annotations

from copy import deepcopy
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"tools"))
from build_uglyos_app_hub import CatalogError, load, render, validate


class CatalogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.path=ROOT/"app-hub/catalog.json"
        cls.data=load(cls.path)

    def test_real_catalog_is_strict_and_all_install_buttons_disabled(self):
        validate(self.data)
        self.assertEqual(self.data["schema_version"],1)
        self.assertGreaterEqual(len(self.data["entries"]),10)
        self.assertTrue(all(x is False for x in self.data["policy"].values()))
        self.assertTrue(all(x["installable"] is False for x in self.data["entries"]))
        groups={x["kind"] for x in self.data["entries"]}
        self.assertEqual(groups,{"native-watch","phone-bridge","unsupported"})
        self.assertFalse(self.data["policy"]["apk_runtime_available"])

    def test_no_run_or_remote_install_in_static_preview(self):
        html=render(self.data)
        self.assertIn("UgLy|OS · App Hub",html)
        self.assertIn("Installs locked",html)
        self.assertIn("connect-src 'none'",html)
        self.assertIn('role="group"',html)
        self.assertEqual(html.count('class="app"'),len(self.data["entries"]))
        for forbidden in ("opkg install ","adb install ","fastboot flash ",
                          "window.location=", "fetch(", "XMLHttpRequest", "eval("):
            self.assertNotIn(forbidden,html)

    def test_rejects_every_install_or_firmware_capability_override(self):
        for key in self.data["policy"]:
            with self.subTest(flag=key):
                data=deepcopy(self.data)
                data["policy"][key]=True
                with self.assertRaises(CatalogError):
                    validate(data)
        data=deepcopy(self.data)
        data["entries"][0]["installable"]=True
        with self.assertRaises(CatalogError):
            validate(data)

    def test_rejects_apks_labeled_as_native_or_phone_bridge(self):
        data=deepcopy(self.data)
        data["entries"][0]["platform"]="android-apk"
        with self.assertRaises(CatalogError):
            validate(data)
        data=deepcopy(self.data)
        data["entries"][5]["platform"]="asteroidos-opkg"
        with self.assertRaises(CatalogError):
            validate(data)
        data=deepcopy(self.data)
        data["entries"][-1]["state"]="source-built"
        with self.assertRaises(CatalogError):
            validate(data)

    def test_no_duplicate_records_or_untrusted_urls(self):
        for bad in ("http://github.com/project","https://evil.example/app",
                    "https://github.com.evil.example/project",
                    "https://github.com@evil.example/project",
                    "https://github.com/example/repo?token=secret"):
            with self.subTest(url=bad):
                data=deepcopy(self.data)
                data["entries"][0]["source"]=bad
                with self.assertRaises(CatalogError):
                    validate(data)
        data=deepcopy(self.data)
        data["entries"][1]["id"]=data["entries"][0]["id"]
        with self.assertRaises(CatalogError):
            validate(data)

    def test_blocks_xss_and_unicode_text_is_escaped(self):
        data=deepcopy(self.data)
        data["entries"][0]["name"]="<script>alert(1)</script>"
        page=render(data)
        self.assertIn("&lt;script&gt;",page)
        self.assertNotIn("<script>alert(1)</script>",page)
        data["entries"][0]["summary"]='" onmouseover="alert(1)"'
        page=render(data)
        self.assertIn("&quot; onmouseover=&quot;",page)

    def test_malformed_duplicate_json_and_symlinks_fail_closed(self):
        with tempfile.TemporaryDirectory() as folder:
            d=Path(folder);a=d/"catalog.json"
            a.write_text('{"schema_version":1,"schema_version":2}')
            with self.assertRaises(CatalogError):
                load(a)
            a.write_text("bad json")
            with self.assertRaises(CatalogError):
                load(a)
            link=d/"alias.json";link.symlink_to(self.path)
            with self.assertRaises(CatalogError):
                load(link)

    def test_generated_html_reproducible_byte_for_byte(self):
        page=render(self.data)
        self.assertEqual(page,render(load(self.path)))
        self.assertLess(len(page.encode()),100_000)
        self.assertNotIn("http://",page)
        self.assertIn('data-filter="phone-bridge"',page)


if __name__=="__main__":
    unittest.main()
