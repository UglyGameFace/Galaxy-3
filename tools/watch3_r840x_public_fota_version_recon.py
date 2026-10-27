#!/usr/bin/env python3
"""One-shot, bounded PUBLIC Samsung FOTA version-XML reconnaissance.

Never contacts the watch, uses an IMEI/serial, downloads firmware or sends
Odin/SDB commands. Explicit legacy --probe-public-metadata opens only
three historical public HTTPS model-region URLs. The newer
--probe-owner-active-csc sends exactly one public SM-R840X/PAP request,
based on the owner's verified read-only SDB CSC observation; neither
mode uses redirects, cookies, personal identifiers or credentials.
Read-only network to Samsung endpoint, NOT a watch recovery method.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import socket
import ssl
import sys
from urllib.error import HTTPError, URLError
from urllib.request import HTTPSHandler, HTTPRedirectHandler, Request, build_opener
from xml.etree import ElementTree as ET

FOTA_HOST = "fota-cloud-dn.ospserver.net"
FOTA_BASE = "https://" + FOTA_HOST + "/firmware/"
MAX_XML_BYTES = 128 * 1024
PROBE_TIMEOUT = 7
MODEL_R840X = "SM-R840X"
MODEL_RETAIL = "SM-R840"
# Historical pre-CSC research tested unverified XAR/KOO hypotheses.
# On 2026-10-27 owner supplied sanitized result from the physically
# running SM-R840X exact SDB CSC file confirming active PAP.
# That does NOT establish original sales region, firmware acceptance,
# bootloader signing, or a freely downloadable recovery archive.
PROBES = (
    ("SM-R840X", "XAR", "XAR_IS_RETAIL_US_HYPOTHESIS_NOT_CONFIRMED_FOR_LDU"),
    ("SM-R840X", "KOO", "KOO_IS_RETAIL_KOREA_HYPOTHESIS_NOT_CONFIRMED_FOR_LDU"),
    ("SM-R840", "XAR", "RETAIL_CONTROL_DIFFERENT_MODEL_NOT_FLASHABLE_ON_R840X"),
)
OBSERVED_ACTIVE_CSC = (
    ("SM-R840X", "PAP", "OWNER_SDB_ACTIVE_CSC_PAP_CONFIRMED_2026_10_27"),
)
BUILD_X = re.compile(r"(?<![A-Z0-9])R840XXXU[0-9][A-Z0-9]{4}(?![A-Z0-9])")
BUILD_RETAIL = re.compile(r"(?<![A-Z0-9])R840XXU[0-9][A-Z0-9]{4}(?![A-Z0-9])")

class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

def parse_version_xml(data: bytes, model: str) -> dict:
    """Parse only firmware version tokens. Never include raw XML in reports."""
    if len(data) > MAX_XML_BYTES:
        return {"state": "PUBLIC_METADATA_OVERSIZED"}
    if not data:
        return {"state": "EMPTY_RESPONSE"}
    # ElementTree doesn't resolve external entities; additionally reject
    # doctypes and entities before parsing untrusted server text.
    if b"<!DOCTYPE" in data.upper() or b"<!ENTITY" in data.upper():
        return {"state": "XML_DTD_OR_ENTITY_BLOCKED"}
    try:
        root = ET.fromstring(data)
    except (ET.ParseError, ValueError):
        return {"state": "NOT_VALID_VERSION_XML"}
    if root.tag != "versioninfo":
        return {"state": "NOT_VERSIONINFO_XML"}
    # All parsed text stays local; only bounded, allowlisted build identifiers
    # are included in the JSON report.
    text = " ".join((el.text or "")[:4096] for el in root.iter())[:30000].upper()
    x = sorted(set(BUILD_X.findall(text)))[:16]
    retail = sorted(set(BUILD_RETAIL.findall(text)))[:16]
    if model == MODEL_R840X and x:
        state = "R840X_BUILD_TOKEN_FOUND_IN_PUBLIC_FOTA_XML"
    elif model == MODEL_R840X and retail:
        state = "RETAIL_BUILD_IN_X_LOOKUP_NOT_MODEL_ACCEPTANCE"
    elif model == MODEL_RETAIL and retail:
        state = "RETAIL_CONTROL_HAS_PUBLIC_FOTA_BUILD"
    else:
        state = "VALID_XML_NO_MATCHING_WATCH3_BUILD_TOKEN"
    return {
        "state": state,
        "r840x_build_tokens": x,
        "retail_build_tokens": retail,
    }

def summarize_version_xml_shape(data: bytes) -> dict:
    """Only structural tag names and link-type booleans, NEVER raw URLs/values.

    The observed Samsung PAP record may provide version history without
    a complete stock image. Neither an apparent link nor its absence can
    establish the availability or authenticity of an R840X repair archive.
    """
    basic = parse_version_xml(data, MODEL_R840X)
    if basic["state"] in (
        "PUBLIC_METADATA_OVERSIZED", "EMPTY_RESPONSE",
        "XML_DTD_OR_ENTITY_BLOCKED", "NOT_VALID_VERSION_XML",
        "NOT_VERSIONINFO_XML",
    ):
        return {"state": basic["state"], "structure_valid": False}
    try:
        root = ET.fromstring(data)
    except (ET.ParseError, ValueError):
        return {"state": "XML_STRUCTURE_PARSE_REFUSED", "structure_valid": False}
    if root.tag != "versioninfo":
        return {"state": "NOT_VERSIONINFO_XML", "structure_valid": False}

    # Fixed small allowlist for text-free schema metadata. Do NOT copy
    # arbitrary XML text, attribute values, hostnames or binary links.
    safe_tag = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,31}\Z")
    nodes = 0
    paths: set[str] = set()
    archive_url_like = 0
    generic_http_url_like = 0
    stack = [(root, tuple())]
    while stack:
        node, parent = stack.pop()
        nodes += 1
        if nodes > 2048 or len(parent) > 10:
            return {"state": "XML_STRUCTURE_COMPLEXITY_LIMIT", "structure_valid": False}
        # Never surface attacker-controlled raw tag names.
        tag = node.tag
        if not isinstance(tag, str) or not safe_tag.fullmatch(tag):
            return {"state": "XML_UNEXPECTED_TAG_NAME", "structure_valid": False}
        current = parent + (tag,)
        paths.add("/".join(current))
        if len(paths) > 128:
            return {"state": "XML_STRUCTURE_UNEXPECTED_FIELD_COUNT",
                    "structure_valid": False}
        if not list(node):
            value = (node.text or "").strip()
            if value.lower().startswith(("https://", "http://")):
                generic_http_url_like += 1
                if re.search(r"\.(?:zip|tar|md5|img|bin|enc4)(?:[?#].*)?\Z",
                             value, flags=re.I):
                    archive_url_like += 1
        for child in reversed(list(node)):
            stack.append((child, current))
    return {
        "state": "STRUCTURE_OBSERVED_FROM_PUBLIC_VERSION_XML",
        "structure_valid": True,
        "xml_byte_length": len(data),
        "observed_element_paths": sorted(paths),
        "number_of_unique_element_paths": len(paths),
        "http_url_looking_text_count": generic_http_url_like,
        "archive_url_suffix_looking_text_count": archive_url_like,
        "raw_xml_retained_or_reported": False,
        "download_url_values_reported": False,
        "official_repair_archive_authenticated": False,
        "absence_of_url_does_not_prove_archive_nonexistence": True,
    }


def public_probe(opener=None, *, observed_csc_only: bool = False,
                 inspect_xml_shape: bool = False) -> list[dict]:
    """Fixed host, 3 historical OR 1 PAP GET; optional redacted XML layout."""
    if opener is None:
        opener = build_opener(NoRedirect(),
                              HTTPSHandler(context=ssl.create_default_context()))
    out = []
    probes = OBSERVED_ACTIVE_CSC if observed_csc_only else PROBES
    for model, region, assumption in probes:
        url = FOTA_BASE + region + "/" + model + "/version.xml"
        result = {
            "model": model,
            "region": region,
            "region_assumption": assumption,
            "state": "NETWORK_NOT_ATTEMPTED",
            "downloaded_firmware": False,
            "device_contacted": False,
        }
        try:
            req = Request(url, headers={"User-Agent": "UgLyOS-R840X-Public-Metadata-Audit/1.0",
                                        "Accept": "application/xml, text/xml"},
                          method="GET")
            with opener.open(req, timeout=PROBE_TIMEOUT) as response:
                body = response.read(MAX_XML_BYTES + 1)
                result.update(parse_version_xml(body, model))
                if inspect_xml_shape:
                    result["xml_structure_redacted"] = summarize_version_xml_shape(body)
        except HTTPError as error:
            # 3xx when redirects disallowed, 403/404 when unavailable; never
            # trust a failed endpoint as proof of firmware nonexistence.
            result["state"] = ("HTTP_%d" % error.code) if 300 <= error.code <= 599 else "HTTP_ERROR"
        except (URLError, OSError, TimeoutError, ValueError, socket.timeout):
            result["state"] = "PUBLIC_ENDPOINT_UNREACHABLE_OR_BLOCKED"
        out.append(result)
    return out

def report_for(probes: list[dict], *, observed_csc_only: bool = False) -> dict:
    return {
        "schema": "uglyos-r840x-public-fota-version-recon-v1",
        "mode": "PUBLIC_SAMSUNG_VERSION_XML_ONLY",
        "device": MODEL_R840X,
        "installed_build": "R840XXXU1AUA2",
        "probed_regions_are_unverified_for_owner_model": not observed_csc_only,
        "physical_active_csc_observed": "PAP" if observed_csc_only else None,
        "physical_csc_evidence": (
            "OWNER_READ_ONLY_SDB_EXACT_ACTIVE_CUSTOMER_LOG"
            if observed_csc_only else "NOT_USED_HISTORICAL_REGION_HYPOTHESES"
        ),
        "physical_csc_does_not_authenticate_stock_image": True,
        "response_meaning": ("Public FOTA version metadata is not a full stock "
                             "firmware download, model-signed rescue image, "
                             "PIT, anti-rollback or authorized custom boot."),
        "observations": probes,
        "model_firmware_compatibility_proven": False,
        "exact_stock_recovery_archive_obtained": False,
        "signed_stock_recovery_verified": False,
        "restoration_of_failed_boot_verified": False,
        "odin_session_started": False,
        "pit_requested": False,
        "device_contacted": False,
        "firmware_downloaded": False,
        "firmware_written": False,
        "custom_boot_verified": False,
        "flash_allowed": False,
        "result": "NO_GO",
    }

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--probe-public-metadata", action="store_true",
                    help="Explicitly fetch 3 historical PUBLIC FOTA version.xml URLs")
    ap.add_argument("--probe-owner-active-csc", action="store_true",
                    help="Only one fixed PUBLIC SM-R840X/PAP version.xml metadata request")
    ap.add_argument("--inspect-owner-pap-xml-structure", action="store_true",
                    help="One PUBLIC PAP version.xml GET; report sanitized XML tag paths ONLY")
    ap.add_argument("--offline-sample", type=Path,
                    help="Parse only an existing local XML fixture; no network access")
    ap.add_argument("--output", type=Path,
                    help="Optional JSON report. Never contains raw XML, IMEI, serial or IP")
    args = ap.parse_args(argv)
    if sum(bool(x) for x in (args.probe_public_metadata,
                             args.probe_owner_active_csc,
                             args.inspect_owner_pap_xml_structure,
                             args.offline_sample)) != 1:
        ap.error("Choose exactly one of the historical, PAP, structural PAP, "
                 "or local XML sample modes")
    if args.offline_sample:
        try:
            if args.offline_sample.is_symlink() or args.offline_sample.stat().st_size > MAX_XML_BYTES:
                raise OSError()
            data = args.offline_sample.read_bytes()
        except OSError:
            print("FAIL: LOCAL_XML_UNREADABLE_OR_OVERSIZED", file=sys.stderr)
            return 2
        probes = [{"model": MODEL_R840X, "region": "LOCAL_FIXTURE",
                   "state": "OFFLINE_SAMPLE_ONLY", "device_contacted": False,
                   **parse_version_xml(data, MODEL_R840X)}]
    else:
        probes = public_probe(
            observed_csc_only=(args.probe_owner_active_csc or
                               args.inspect_owner_pap_xml_structure),
            inspect_xml_shape=args.inspect_owner_pap_xml_structure)
    report = (json.dumps(report_for(
        probes, observed_csc_only=(args.probe_owner_active_csc or
                                  args.inspect_owner_pap_xml_structure)),
                         indent=2) + "\n")
    if args.output:
        try:
            with args.output.open("x", encoding="utf-8") as file:
                file.write(report)
        except OSError:
            print("FAIL: CANNOT_CREATE_EXCLUSIVE_REPORT", file=sys.stderr)
            return 2
        print("Wrote metadata-only report: " + str(args.output))
    else:
        print(report, end="")
    print("NO_GO: no Watch3 connection, firmware download, Odin session or flash.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
