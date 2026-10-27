"""Network-free tests of public FOTA metadata-only reconnaissance."""
from __future__ import annotations

import json
from pathlib import Path
import socket
import sys
import tempfile
import unittest
from unittest.mock import patch
from urllib.error import HTTPError

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import watch3_r840x_public_fota_version_recon as recon


def xml(latest: str):
    return ('<?xml version="1.0"?><versioninfo><firmware><version><latest>'
            + latest + '</latest></version></firmware></versioninfo>').encode()


class FakeResponse:
    def __init__(self, data):
        self.data = data
    def __enter__(self): return self
    def __exit__(self, *args): return False
    def read(self, n):
        assert n == recon.MAX_XML_BYTES + 1
        return self.data[:n]


class FakeOpener:
    def __init__(self, responses):
        self.responses = list(responses)
        self.urls = []
    def open(self, request, timeout=None):
        self.urls.append(request.full_url)
        assert request.get_method() == "GET"
        assert request.full_url.startswith(recon.FOTA_BASE)
        assert timeout <= 7
        action = self.responses.pop(0)
        if isinstance(action, Exception):
            raise action
        return FakeResponse(action)


class PublicFotaTests(unittest.TestCase):
    def test_exact_model_version_is_metadata_not_signed_firmware(self):
        result = recon.parse_version_xml(xml("R840XXXU1AUA2"), "SM-R840X")
        self.assertEqual(result["state"], "R840X_BUILD_TOKEN_FOUND_IN_PUBLIC_FOTA_XML")
        self.assertEqual(result["r840x_build_tokens"], ["R840XXXU1AUA2"])
        self.assertEqual(result["retail_build_tokens"], [])
        rep = recon.report_for([result])
        self.assertEqual(rep["result"], "NO_GO")
        self.assertFalse(rep["exact_stock_recovery_archive_obtained"])
        self.assertFalse(rep["firmware_written"])
        self.assertFalse(rep["model_firmware_compatibility_proven"])

    def test_retail_mismatch_and_missing_build_not_success(self):
        retail = recon.parse_version_xml(xml("R840XXU1DWK2"), "SM-R840X")
        self.assertEqual(retail["state"], "RETAIL_BUILD_IN_X_LOOKUP_NOT_MODEL_ACCEPTANCE")
        actual_retail = recon.parse_version_xml(xml("R840XXU1DWK2"), "SM-R840")
        self.assertEqual(actual_retail["state"], "RETAIL_CONTROL_HAS_PUBLIC_FOTA_BUILD")
        empty = recon.parse_version_xml(xml(""), "SM-R840X")
        self.assertEqual(empty["state"], "VALID_XML_NO_MATCHING_WATCH3_BUILD_TOKEN")
        self.assertEqual(recon.parse_version_xml(b"<html/>", "SM-R840X")["state"],
                         "NOT_VERSIONINFO_XML")
        self.assertEqual(recon.parse_version_xml(b"NOT XML", "SM-R840X")["state"],
                         "NOT_VALID_VERSION_XML")

    def test_reject_dtd_entity_and_oversized_body(self):
        body = b'<!DOCTYPE versioninfo [<!ENTITY x SYSTEM "file:///etc/passwd">]><versioninfo>&x;</versioninfo>'
        self.assertEqual(recon.parse_version_xml(body, "SM-R840X")["state"],
                         "XML_DTD_OR_ENTITY_BLOCKED")
        self.assertEqual(recon.parse_version_xml(b"a" * (recon.MAX_XML_BYTES + 1), "SM-R840X")["state"],
                         "PUBLIC_METADATA_OVERSIZED")

    def test_exactly_three_fixed_public_gets_no_identity_data(self):
        fake = FakeOpener([
            xml("R840XXXU1AUA2"),
            HTTPError("https://irrelevant.invalid/", 404, "Not Found", None, None),
            xml("R840XXU1DWK2"),
        ])
        with patch.object(socket, "socket", side_effect=AssertionError("Do not use raw socket")):
            outputs = recon.public_probe(opener=fake)
        self.assertEqual(len(outputs), 3)
        self.assertEqual(fake.urls, [
            "https://fota-cloud-dn.ospserver.net/firmware/XAR/SM-R840X/version.xml",
            "https://fota-cloud-dn.ospserver.net/firmware/KOO/SM-R840X/version.xml",
            "https://fota-cloud-dn.ospserver.net/firmware/XAR/SM-R840/version.xml",
        ])
        self.assertEqual(outputs[0]["state"], "R840X_BUILD_TOKEN_FOUND_IN_PUBLIC_FOTA_XML")
        self.assertEqual(outputs[1]["state"], "HTTP_404")
        self.assertEqual(outputs[2]["state"], "RETAIL_CONTROL_HAS_PUBLIC_FOTA_BUILD")
        self.assertTrue(all(x["device_contacted"] is False for x in outputs))
        self.assertTrue(all(x["downloaded_firmware"] is False for x in outputs))
        self.assertEqual(recon.report_for(outputs)["result"], "NO_GO")

    def test_owner_pap_one_public_request_and_strict_no_go(self):
        # PAP was observed physically in the watch's exact Tizen active CSC file.
        self.assertEqual(recon.OBSERVED_ACTIVE_CSC, (
            ("SM-R840X", "PAP", "OWNER_SDB_ACTIVE_CSC_PAP_CONFIRMED_2026_10_27"),
        ))
        fake = FakeOpener([xml("R840XXXU1AUA2")])
        results = recon.public_probe(opener=fake, observed_csc_only=True)
        self.assertEqual(fake.urls, [
            "https://fota-cloud-dn.ospserver.net/firmware/PAP/SM-R840X/version.xml",
        ])
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["state"], "R840X_BUILD_TOKEN_FOUND_IN_PUBLIC_FOTA_XML")
        report = recon.report_for(results, observed_csc_only=True)
        self.assertFalse(report["probed_regions_are_unverified_for_owner_model"])
        self.assertEqual(report["physical_active_csc_observed"], "PAP")
        self.assertTrue(report["physical_csc_does_not_authenticate_stock_image"])
        for key in ("model_firmware_compatibility_proven", "exact_stock_recovery_archive_obtained",
                    "signed_stock_recovery_verified", "restoration_of_failed_boot_verified",
                    "odin_session_started", "pit_requested", "device_contacted",
                    "firmware_downloaded", "firmware_written", "custom_boot_verified",
                    "flash_allowed"):
            self.assertFalse(report[key], key)
        self.assertEqual(report["result"], "NO_GO")

    def test_owner_pap_403_is_not_negative_stock_firmware_proof(self):
        url = "https://fota-cloud-dn.ospserver.net/firmware/PAP/SM-R840X/version.xml"
        fake = FakeOpener([HTTPError(url, 403, "Forbidden", None, None)])
        results = recon.public_probe(opener=fake, observed_csc_only=True)
        self.assertEqual(fake.urls, [url])
        self.assertEqual(results[0]["state"], "HTTP_403")
        report = recon.report_for(results, observed_csc_only=True)
        self.assertEqual(report["physical_active_csc_observed"], "PAP")
        self.assertFalse(report["exact_stock_recovery_archive_obtained"])
        self.assertEqual(report["result"], "NO_GO")

    def test_owner_pap_cli_uses_only_new_optional_single_public_mode(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "pap.json"
            stub = [{"model": "SM-R840X", "region": "PAP", "state": "HTTP_403",
                     "device_contacted": False, "downloaded_firmware": False}]
            with patch.object(recon, "public_probe", return_value=stub) as called:
                self.assertEqual(
                    recon.main(["--probe-owner-active-csc", "--output", str(out)]), 0)
            called.assert_called_once_with(observed_csc_only=True, inspect_xml_shape=False)
            report = json.loads(out.read_text())
            self.assertEqual(report["physical_active_csc_observed"], "PAP")
            self.assertFalse(report["flash_allowed"])
            self.assertFalse(report["firmware_downloaded"])
            self.assertEqual(len(report["observations"]), 1)

    def test_owner_pap_version_xml_structure_only_never_reveals_urls(self):
        body = (
            b'<versioninfo><url>https://private-fake.example/firmware/</url>'
            b'<firmware><model>SM-R840X</model><cc>PAP</cc>'
            b'<version><latest>R840XXXU1AUA2/R840XXXU1AUA2/</latest>'
            b'<upgrade><value>R840XXXU1ATFA</value></upgrade>'
            b'</version></firmware></versioninfo>'
        )
        summary = recon.summarize_version_xml_shape(body)
        self.assertTrue(summary["structure_valid"])
        self.assertEqual(summary["state"], "STRUCTURE_OBSERVED_FROM_PUBLIC_VERSION_XML")
        self.assertEqual(summary["http_url_looking_text_count"], 1)
        self.assertEqual(summary["archive_url_suffix_looking_text_count"], 0)
        self.assertIn("versioninfo/firmware/version/latest",
                      summary["observed_element_paths"])
        self.assertIn("versioninfo/url", summary["observed_element_paths"])
        output = json.dumps(summary)
        self.assertNotIn("private-fake", output)
        self.assertNotIn("R840XXX", output)
        self.assertNotIn("https://", output)
        self.assertIs(summary["official_repair_archive_authenticated"], False)
        self.assertTrue(summary["absence_of_url_does_not_prove_archive_nonexistence"])

    def test_archive_looking_text_is_never_auto_firmware_authentication(self):
        body = (b"<versioninfo><url>https://unverified.example/fake.tar.md5</url>"
                b"<firmware><version><latest>R840XXXU1AUA2</latest>"
                b"</version></firmware></versioninfo>")
        summary = recon.summarize_version_xml_shape(body)
        self.assertEqual(summary["archive_url_suffix_looking_text_count"], 1)
        self.assertFalse(summary["official_repair_archive_authenticated"])
        self.assertNotIn("unverified.example", json.dumps(summary))

    def test_malformed_structure_fail_closed_and_no_xml_values_leaked(self):
        for raw, status in (
            (b"x" * (recon.MAX_XML_BYTES + 1), "PUBLIC_METADATA_OVERSIZED"),
            (b"<!DOCTYPE versioninfo><versioninfo/>", "XML_DTD_OR_ENTITY_BLOCKED"),
            (b"<html/>", "NOT_VERSIONINFO_XML"),
            (b"broken", "NOT_VALID_VERSION_XML"),
        ):
            with self.subTest(status=status):
                result = recon.summarize_version_xml_shape(raw)
                self.assertEqual(result["state"], status)
                self.assertFalse(result["structure_valid"])
        deep = b"<versioninfo>" + b"<a>" * 12 + b"abc" + b"</a>" * 12 + b"</versioninfo>"
        self.assertEqual(recon.summarize_version_xml_shape(deep)["state"],
                         "XML_STRUCTURE_COMPLEXITY_LIMIT")
        unusual = b'<versioninfo xmlns:private="urn:test"><private:secret/></versioninfo>'
        self.assertEqual(recon.summarize_version_xml_shape(unusual)["state"],
                         "XML_UNEXPECTED_TAG_NAME")

    def test_structure_mode_sends_only_owner_pap_request_and_no_raw_xml(self):
        body = (b"<versioninfo><url>https://test-secret.example/firmware/</url>"
                b"<firmware><version><latest>R840XXXU1AUA2</latest>"
                b"</version></firmware></versioninfo>")
        fake = FakeOpener([body])
        observations = recon.public_probe(opener=fake, observed_csc_only=True,
                                          inspect_xml_shape=True)
        self.assertEqual(fake.urls, [
            "https://fota-cloud-dn.ospserver.net/firmware/PAP/SM-R840X/version.xml"
        ])
        self.assertEqual(len(observations), 1)
        shape = observations[0]["xml_structure_redacted"]
        self.assertTrue(shape["structure_valid"])
        self.assertNotIn("test-secret.example", json.dumps(observations))
        self.assertEqual(recon.report_for(observations, observed_csc_only=True)["result"], "NO_GO")

    def test_owner_pap_structure_cli_preserves_no_go_and_one_get(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "shape.json"
            stub = [{
                "model": "SM-R840X", "region": "PAP",
                "state": "R840X_BUILD_TOKEN_FOUND_IN_PUBLIC_FOTA_XML",
                "r840x_build_tokens": ["R840XXXU1AUA2"],
                "device_contacted": False, "downloaded_firmware": False,
                "xml_structure_redacted": {"structure_valid": True},
            }]
            with patch.object(recon, "public_probe", return_value=stub) as mocked:
                self.assertEqual(recon.main([
                    "--inspect-owner-pap-xml-structure", "--output", str(out)
                ]), 0)
            mocked.assert_called_once_with(observed_csc_only=True, inspect_xml_shape=True)
            saved = json.loads(out.read_text())
            self.assertEqual(saved["result"], "NO_GO")
            self.assertFalse(saved["firmware_downloaded"])
            self.assertFalse(saved["flash_allowed"])
            self.assertEqual(saved["physical_active_csc_observed"], "PAP")

    def test_network_failure_cannot_claim_missing_watch_firmware(self):
        fake = FakeOpener([TimeoutError("timeout")] * len(recon.PROBES))
        outputs = recon.public_probe(opener=fake)
        self.assertTrue(all(x["state"] == "PUBLIC_ENDPOINT_UNREACHABLE_OR_BLOCKED" for x in outputs))
        self.assertTrue(all(x["model"] in ("SM-R840X", "SM-R840") for x in outputs))
        self.assertFalse(recon.report_for(outputs)["signed_stock_recovery_verified"])

    def test_offline_sample_runs_without_network_and_no_clobber(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "input.xml"
            p.write_bytes(xml("R840XXXU1AUA2"))
            out = Path(td) / "result.json"
            with patch("urllib.request.urlopen", side_effect=AssertionError("Network forbidden")), patch.object(
                    recon, "public_probe", side_effect=AssertionError("Public probe forbidden")):
                self.assertEqual(recon.main(["--offline-sample", str(p), "--output", str(out)]), 0)
                self.assertEqual(recon.main(["--offline-sample", str(p), "--output", str(out)]), 2)
            report = json.loads(out.read_text())
            self.assertFalse(report["device_contacted"])
            self.assertFalse(report["odin_session_started"])
            self.assertEqual(report["observations"][0]["state"], "R840X_BUILD_TOKEN_FOUND_IN_PUBLIC_FOTA_XML")

if __name__ == "__main__":
    unittest.main()
