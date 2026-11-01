#!/usr/bin/env python3
"""Read bounded standard D-Bus policy evidence from an owned R840X.

Fixed SDB sync LIST/RECV only. Never activate a service, send a D-Bus
message, execute vendor code, request root, change security state, or write
to the watch. Reports are evidence, NOT an effective-permission decision.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import stat
import sys
import xml.etree.ElementTree as ET

from watch3_r08_android_sdb import (
    PORT, SdbError, ShellCloseError, Connection, DBUS_RUNTIME_PROBES,
    private_watch_ip,
)
from watch3_r08_fota_consumer_inventory import (
    DBUS_POLICY_DIRECTORIES, DBUS_FOTA_POLICY_NAME,
    InventoryError, list_one,
)
from watch3_r08_fota_handoff_pull import HandoffError, _receive_bounded_file

MAX_BYTES = 64 * 1024
MAX_POLICY_FILES = 8
MAX_RELEVANT_RULES = 128
# Only standard fixed configuration files, no directory walk or CLI paths.
CORE_FILES = (
    b"/usr/share/dbus-1/system.conf",
    b"/etc/dbus-1/system.conf",
    b"/etc/dbus-1/system-local.conf",
)
RULE_FIELDS = (
    "send_destination", "send_interface", "send_member", "send_type",
    "own", "receive_sender", "receive_type",
)
SAFE_FIELD = re.compile(r"[A-Za-z0-9_.:*+-]{1,128}\Z")
SAFE_POLICY = re.compile(r"[A-Za-z0-9_.+-]{1,64}\Z")


class PolicyError(ValueError):
    """Privacy-safe, categorical outcome."""


def allowed_path(path: bytes) -> bool:
    if path in CORE_FILES:
        return True
    return any(
        path.startswith(root + b"/") and
        DBUS_FOTA_POLICY_NAME.fullmatch(path[len(root) + 1:].decode("ascii", "strict"))
        for root in DBUS_POLICY_DIRECTORIES.values()
    )


def read_file(ip: str, key: Path, path: bytes, timeout: int = 10) -> bytes:
    # Never turn a filename or error returned by the watch into an arbitrary RECV.
    if type(path) is not bytes or not allowed_path(path):
        raise PolicyError("POLICY_PATH_NOT_ALLOWLISTED")
    try:
        with socket.create_connection((ip, PORT), timeout=timeout) as sock:
            sock.settimeout(timeout)
            return _receive_bounded_file(sock, key, path, MAX_BYTES)
    except HandoffError as exc:
        raise PolicyError("POLICY_RECV_" + str(exc)) from None
    except (OSError, SdbError, TimeoutError):
        raise PolicyError("POLICY_SDB_UNAVAILABLE") from None


def list_policy_dir(ip: str, key: Path, scope: str, timeout: int = 10) -> dict:
    if scope not in DBUS_POLICY_DIRECTORIES:
        raise PolicyError("POLICY_SCOPE_NOT_ALLOWLISTED")
    try:
        with socket.create_connection((ip, PORT), timeout=timeout) as sock:
            sock.settimeout(timeout)
            return list_one(sock, key, scope)
    except InventoryError as exc:
        return {"status": str(exc)}
    except (OSError, SdbError, TimeoutError):
        return {"status": "POLICY_SDB_UNAVAILABLE"}


def analyze_xml(raw: bytes) -> dict:
    """Extract only FOTA/structural policy evidence without declaring permission."""
    if not raw or len(raw) > MAX_BYTES:
        raise PolicyError("POLICY_XML_SIZE_INVALID")
    if b"<!ENTITY" in raw.upper() or b"<![" in raw.upper():
        raise PolicyError("POLICY_XML_ENTITY_OR_SECTION_REJECTED")
    try:
        root = ET.fromstring(raw)
    except (ET.ParseError, ValueError):
        raise PolicyError("POLICY_XML_MALFORMED") from None
    if root.tag != "busconfig":
        raise PolicyError("POLICY_XML_UNEXPECTED_ROOT")
    includes = 0
    includedirs = 0
    rules = []
    unmatched_policy_blocks = 0
    for child in root:
        if child.tag == "include":
            includes += 1
        elif child.tag == "includedir":
            includedirs += 1
        elif child.tag == "policy":
            if len(child) > 1024:
                raise PolicyError("POLICY_XML_RULE_COUNT_LIMIT")
            retained = 0
            for node in child:
                if node.tag not in ("allow", "deny"):
                    continue
                fields = {k: v for k, v in node.attrib.items() if k in RULE_FIELDS}
                if not fields or any(not SAFE_FIELD.fullmatch(v) for v in fields.values()):
                    continue
                relevant = (
                    any(fields.get(key) in ("fota.consumer", "*") for key in
                        ("send_destination", "own", "receive_sender")) or
                    fields.get("send_type") == "method_call" or
                    fields.get("send_type") == "*" or
                    fields.get("receive_type") == "method_call"
                )
                if not relevant:
                    continue
                scope = {k: v for k, v in child.attrib.items()
                         if k in ("user", "group", "context")
                         and isinstance(v, str) and SAFE_FIELD.fullmatch(v)}
                rules.append({"scope": scope, "action": node.tag, "fields": fields})
                retained += 1
                if len(rules) > MAX_RELEVANT_RULES:
                    raise PolicyError("POLICY_XML_RELEVANT_RULE_LIMIT")
            if not retained:
                unmatched_policy_blocks += 1
    return {
        "xml_valid": True,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "bytes": len(raw),
        "include_tags": includes,
        "includedir_tags": includedirs,
        "relevant_rules": rules,
        "other_policy_blocks": unmatched_policy_blocks,
        "actual_effective_policy_proven": False,
    }


def collect(ip: str, key: Path) -> dict:
    ip = private_watch_ip(ip)
    evidence = {}
    for path in CORE_FILES:
        label = path.decode("ascii")
        try:
            evidence[label] = analyze_xml(read_file(ip, key, path))
        except PolicyError as exc:
            evidence[label] = {"status": str(exc)}
    directory_results = {}
    for scope, base in DBUS_POLICY_DIRECTORIES.items():
        result = list_policy_dir(ip, key, scope)
        directory_results[scope] = result
        if result.get("status") != "LIST_COMPLETE" or result.get("matching_names_truncated"):
            continue
        candidates = result.get("matching_fota_policy_files", {})
        if type(candidates) is not dict or len(candidates) > MAX_POLICY_FILES:
            continue
        for name, facts in sorted(candidates.items()):
            if (not isinstance(name, str) or not DBUS_FOTA_POLICY_NAME.fullmatch(name)
                    or not isinstance(facts, dict)
                    or facts.get("kind") != "REGULAR_FILE"
                    or type(facts.get("bytes")) is not int
                    or not 0 < facts["bytes"] <= MAX_BYTES):
                continue
            path = base + b"/" + name.encode("ascii")
            label = path.decode("ascii")
            try:
                raw = read_file(ip, key, path)
                if len(raw) != facts["bytes"]:
                    raise PolicyError("POLICY_FILE_CHANGED_DURING_READ")
                evidence[label] = analyze_xml(raw)
            except PolicyError as exc:
                evidence[label] = {"status": str(exc)}
    return {
        "schema": "uglyos-r840x-dbus-policy-evidence-v1",
        "state": "PARTIAL_STANDARD_POLICY_EVIDENCE",
        "policy_files": evidence,
        "directory_results": directory_results,
        "bus_policy_complete": False,
        "user_shell_authorized_for_fota": "UNDETERMINED",
        "smack_cynara_authorization": "UNDETERMINED",
        "runtime_bus_identity_attested": False,
        "fota_method_called": False,
        "vendor_executable_executed": False,
        "watch_write_performed": False,
        "root_proven": False,
        "bootloader_unlocked": False,
        "stock_recovery_proven": False,
        "interpretation": (
            "This is a bounded subset of standard policy files, not the merged "
            "effective D-Bus policy. Dynamic/nonstandard includes, policy order, "
            "SMACK/Cynara, running daemon settings and caller credentials remain "
            "unverified. Rules shown must not be evaluated as user authorization."
        ),
    }




# Focused physical capture after the v1 report discarded matching attributes.
# Exactly three previously observed files; no unknown directory names or paths.
FOCUSED_FILES = (
    b"/usr/share/dbus-1/system.conf",
    b"/etc/dbus-1/system.conf",
    b"/etc/dbus-1/system.d/fota-consumer.conf",
)
EXPECTED_FOCUSED_SHA256 = {
    "/usr/share/dbus-1/system.conf":
        "df59ef6b3bd808b8b131fc5eef7c45dd98622d5a52473ab3dd1f4f542b0d7cb1",
    "/etc/dbus-1/system.conf":
        "a6f50dc70ef082a110dcdb164579cd2af221b90226c5e0aca237edcad98a1c26",
    "/etc/dbus-1/system.d/fota-consumer.conf":
        "499ae912f2397720c952f27143d2112427509b95335c91d5b0ec7749e6999fec",
}
MAX_FOCUSED_RULES = 96
SCOPE_ATTRIBUTES = frozenset(("context", "user", "group", "at_console"))
RULE_ATTRIBUTES = frozenset((
    "send_destination", "send_destination_prefix", "send_interface",
    "send_member", "send_path", "send_type", "send_error",
    "send_requested_reply", "send_broadcast", "receive_sender",
    "receive_interface", "receive_member", "receive_path", "receive_type",
    "receive_error", "receive_requested_reply", "own", "own_prefix",
    "eavesdrop", "user", "group", "min_fds", "max_fds",
))
INCLUDE_ATTRIBUTES = frozenset((
    "ignore_missing", "if_selinux_enabled", "selinux_root_relative",
))
# Configuration paths are system metadata, not arbitrary user-controlled paths.
SAFE_CONFIG_TOKEN = re.compile(r"[A-Za-z0-9_./:@*+-]{1,192}\Z")


def focused_policy_xml(raw: bytes) -> dict:
    """Extract ordered original XML rules, preserving matching constraints.

    No policy evaluation or include loading is performed. The generic v1
    projection silently omitted important D-Bus rule attributes, so this
    intentionally reports unknown attributes rather than losing them.
    """
    base = analyze_xml(raw)  # reuse strict size, entity and root checks
    root = ET.fromstring(raw)
    details = []
    unreported_nodes = 0
    for node in root:
        if len(details) >= MAX_FOCUSED_RULES:
            raise PolicyError("FOCUSED_XML_NODE_LIMIT")
        if node.tag in ("include", "includedir"):
            item = {
                "kind": node.tag,
                "path": node.text.strip() if node.text and
                    SAFE_CONFIG_TOKEN.fullmatch(node.text.strip()) else "UNREPORTED",
                "attributes": {k: v for k, v in node.attrib.items()
                               if k in INCLUDE_ATTRIBUTES and
                               SAFE_CONFIG_TOKEN.fullmatch(v)},
                "unrecognized_attribute_names": sorted(
                    k for k in node.attrib if k not in INCLUDE_ATTRIBUTES),
            }
            details.append(item)
        elif node.tag == "policy":
            if len(node) > MAX_FOCUSED_RULES:
                raise PolicyError("FOCUSED_XML_RULE_LIMIT")
            scope = {k: v for k, v in node.attrib.items()
                     if k in SCOPE_ATTRIBUTES and SAFE_CONFIG_TOKEN.fullmatch(v)}
            item = {
                "kind": "policy",
                "scope": scope,
                "unrecognized_scope_names": sorted(
                    k for k in node.attrib if k not in SCOPE_ATTRIBUTES),
                "rules": [],
                "other_nodes": 0,
            }
            for rule in node:
                if rule.tag not in ("allow", "deny"):
                    item["other_nodes"] += 1
                    continue
                safe = {k: v for k, v in rule.attrib.items()
                        if k in RULE_ATTRIBUTES and SAFE_CONFIG_TOKEN.fullmatch(v)}
                unsupported = sorted(
                    k for k, v in rule.attrib.items()
                    if k not in safe)
                item["rules"].append({
                    "action": rule.tag,
                    "attributes": safe,
                    "unreported_attribute_names": unsupported,
                })
                if len(item["rules"]) > MAX_FOCUSED_RULES:
                    raise PolicyError("FOCUSED_XML_RULE_LIMIT")
            details.append(item)
        else:
            unreported_nodes += 1
    return {
        "xml_valid": True,
        "sha256": base["sha256"],
        "bytes": len(raw),
        "ordered_config_nodes": details,
        "other_config_nodes": unreported_nodes,
        "effective_sender_permission": "UNDETERMINED",
    }


def collect_focused(ip: str, key: Path) -> dict:
    """Read only three exact observed files; no LIST, D-Bus or service action."""
    ip = private_watch_ip(ip)
    files = {}
    for path in FOCUSED_FILES:
        name = path.decode("ascii")
        try:
            result = focused_policy_xml(read_file(ip, key, path))
            result["matches_october_30_v1_sha256"] = (
                result["sha256"] == EXPECTED_FOCUSED_SHA256[name]
            )
            files[name] = result
        except PolicyError as exc:
            files[name] = {"status": str(exc)}
    return {
        "schema": "uglyos-r840x-dbus-focused-original-rules-v1",
        "state": "FOCUSED_FILES_ONLY",
        "source_paths": list(EXPECTED_FOCUSED_SHA256),
        "policy_files": files,
        "bus_config_load_order_verified": False,
        "other_103_directory_entries_inspected": False,
        "dbus_sender_shell_credential_verified": False,
        "smack_cynara_authorization": "UNDETERMINED",
        "effective_dbus_send_permission_for_shell": "UNDETERMINED",
        "fota_consumer_method_authorization": "UNDETERMINED",
        "fota_method_called": False, "watch_write_performed": False,
        "root_proven": False, "bootloader_unlocked": False,
        "stock_recovery_proven": False,
        "interpretation": (
            "Only the original ordered XML rules and include declarations of "
            "three fixed files have been read; attributes that could alter a "
            "match are retained or explicitly flagged. This is not the running "
            "daemon's merged configuration, sender authorization, signature "
            "acceptance, root or stock restoration."
        ),
    }



# The owner has already read the complete rule attributes of these three
# pinned original files. Audit their *subset* offline before any new probe.
# Never turn a locally simulated D-Bus decision into an on-watch grant.
FOCUSED_REVIEW_TARGET = {
    "send_destination": "fota.consumer",
    "send_interface": "fota.consumer",
    "send_member": "LaunchFota",
    "send_path": "/fota/consumer",
    "send_type": "method_call",
}
FOCUSED_SUPPORTED_SEND_MATCHES = frozenset((
    "send_destination", "send_interface", "send_member",
    "send_path", "send_type",
))
FOCUSED_REVIEW_MAX_NODES = 96


def _focused_default_send_matches(rule: dict) -> str:
    """Tri-state match against a hypothetical FOTA method call only.

    Decide a *definite mismatch* on known attributes before inspecting
    unsupported attributes. In particular, send_requested_reply on
    method_return/error rules must not create false uncertainty about
    an unrelated method_call. Unknown constraints on otherwise plausible
    send rules remain UNKNOWN, never MATCH.
    """
    if not isinstance(rule, dict) or rule.get("action") not in ("allow", "deny"):
        return "UNKNOWN"
    attributes = rule.get("attributes")
    unreported = rule.get("unreported_attribute_names")
    if not isinstance(attributes, dict) or not isinstance(unreported, list):
        return "UNKNOWN"

    known_send = [(key, value) for key, value in attributes.items()
                  if key in FOCUSED_SUPPORTED_SEND_MATCHES]
    # If *any* supported send filter excludes our method, no other
    # attribute can make that rule apply to the hypothetical message.
    if any(isinstance(value, str) and
           value not in ("*", FOCUSED_REVIEW_TARGET[key])
           for key, value in known_send):
        return "NO_MATCH"
    if any(type(value) is not str for _, value in known_send):
        return "UNKNOWN"

    unsupported_send = any(key.startswith("send_") and
                           key not in FOCUSED_SUPPORTED_SEND_MATCHES
                           for key in attributes)
    unknown_non_send = any(key.startswith("receive_") or
                           key in ("eavesdrop", "own", "own_prefix", "user", "group")
                           for key in attributes
                           if key not in FOCUSED_SUPPORTED_SEND_MATCHES)
    # Preserve uncertainty for unknown constraints on otherwise plausible
    # rules, but not for proven nonmatches such as send_type=method_return.
    if unreported or unsupported_send or (known_send and unknown_non_send):
        return "UNKNOWN"
    if not known_send:
        # Ordinary connection/receive/own rules do not regulate sending
        # this method call. Unknown future attributes are not ignored.
        if any(key not in RULE_ATTRIBUTES for key in attributes):
            return "UNKNOWN"
        return "NO_MATCH"
    return "MATCH"

def review_focused_report(source: object, *, source_sha256: str = "") -> dict:
    """Offline summary of known matching default rules; no access verdict."""
    if (not isinstance(source, dict) or
            source.get("schema") != "uglyos-r840x-dbus-focused-original-rules-v1" or
            source.get("state") != "FOCUSED_FILES_ONLY" or
            not isinstance(source.get("policy_files"), dict)):
        raise PolicyError("FOCUSED_REVIEW_EXPECTS_V1_REPORT")
    files = source["policy_files"]
    required = [p.decode("ascii") for p in FOCUSED_FILES]
    if set(files) != set(required):
        raise PolicyError("FOCUSED_REVIEW_FILES_INCOMPLETE_OR_EXTRA")
    details = {}
    observed_matches = []
    incomplete = False
    uncertainty_reasons = set()
    known_nonmatching_default_rules = 0
    for name in required:
        record = files[name]
        if not isinstance(record, dict) or not isinstance(
                record.get("ordered_config_nodes"), list):
            raise PolicyError("FOCUSED_REVIEW_FILE_NOT_OBSERVED")
        nodes = record["ordered_config_nodes"]
        if len(nodes) > FOCUSED_REVIEW_MAX_NODES:
            raise PolicyError("FOCUSED_REVIEW_NODE_LIMIT")
        pinned = (
            record.get("xml_valid") is True and
            record.get("sha256") == EXPECTED_FOCUSED_SHA256[name] and
            record.get("matches_october_30_v1_sha256") is True
        )
        details[name] = {
            "original_bytes_match_previous_capture": pinned,
            "ordered_node_count": len(nodes),
            "include_declarations": [],
            "default_send_rule_matches": [],
        }
        if not pinned:
            incomplete = True
            uncertainty_reasons.add("PINNED_SOURCE_CHANGED_OR_UNVERIFIED")
        for node in nodes:
            if not isinstance(node, dict):
                raise PolicyError("FOCUSED_REVIEW_INVALID_NODE")
            kind = node.get("kind")
            if kind in ("include", "includedir"):
                details[name]["include_declarations"].append({
                    "kind": kind, "path": node.get("path", "UNREPORTED"),
                })
                continue
            if kind != "policy":
                incomplete = True
                uncertainty_reasons.add("UNKNOWN_CONFIG_NODE")
                continue
            scope = node.get("scope")
            rules = node.get("rules")
            if (not isinstance(scope, dict) or not isinstance(rules, list) or
                    len(rules) > FOCUSED_REVIEW_MAX_NODES):
                raise PolicyError("FOCUSED_REVIEW_INVALID_POLICY_BLOCK")
            if scope.get("context") != "default":
                # Named-user or group policies are accounted for by the
                # global-effective-policy caveat, not default-rule matching.
                continue
            if node.get("unrecognized_scope_names"):
                incomplete = True
                uncertainty_reasons.add("UNKNOWN_DEFAULT_SCOPE_ATTRIBUTE")
            for rule in rules:
                state = _focused_default_send_matches(rule)
                if state == "UNKNOWN":
                    incomplete = True
                    uncertainty_reasons.add("UNKNOWN_POTENTIAL_SEND_CONSTRAINT")
                elif state == "NO_MATCH":
                    known_nonmatching_default_rules += 1
                if state == "MATCH":
                    hit = {
                        "action": rule["action"],
                        "attributes": rule["attributes"],
                    }
                    details[name]["default_send_rule_matches"].append(hit)
                    observed_matches.append({"file": name, "action": rule["action"]})
    targeted = [i["action"] for i in details[
        "/etc/dbus-1/system.d/fota-consumer.conf"]["default_send_rule_matches"]]
    core_deny = any(
        item["action"] == "deny" and
        item["attributes"].get("send_type") == "method_call"
        for item in details["/usr/share/dbus-1/system.conf"]["default_send_rule_matches"]
    )
    ordered_overlap = len(targeted) >= 2 and "deny" in targeted[:-1] and targeted[-1] == "allow"
    pinned_all = all(item["original_bytes_match_previous_capture"]
                     for item in details.values())
    return {
        "schema": "uglyos-r840x-dbus-focused-default-rule-audit-v1",
        "source_report_sha256": source_sha256,
        "exact_original_three_hashes_matched": pinned_all,
        "core_default_method_deny_observed": core_deny,
        "fota_default_rule_sequence_for_hypothetical_message": targeted,
        "fota_last_matching_default_rule": targeted[-1] if targeted else "NOT_OBSERVED",
        "fota_deny_then_allow_in_same_file": ordered_overlap,
        "matching_rule_subset_has_unknowns_or_drift": incomplete,
        "subset_uncertainty_reason_codes": sorted(uncertainty_reasons),
        "known_nonmatching_default_rules_ignored": known_nonmatching_default_rules,
        "individual_file_details": details,
        "observed_default_subset_result": (
            "LATER_FOTA_INTERFACE_ALLOW_MATCHES"
            if ordered_overlap and pinned_all and not incomplete else
            "INCONCLUSIVE"
        ),
        "running_daemon_load_order_verified": False,
        "other_policy_files_verified": False,
        "sender_bus_uid_verified": False,
        "smack_cynara_authorization": "UNDETERMINED",
        "effective_dbus_send_permission_for_shell": "UNDETERMINED",
        "consumer_method_authorization": "UNDETERMINED",
        "watch_contacted": False,
        "fota_method_called": False,
        "watch_write_performed": False,
        "root_proven": False,
        "bootloader_unlocked": False,
        "stock_recovery_proven": False,
        "interpretation": (
            "Only a hypothetical method call matching the pinned original "
            "fota.consumer interface is considered. A later default rule "
            "in the observed FOTA file matches the request, but other includes, "
            "user/group/mandatory policies, running daemon identity, MAC "
            "and receiver checks are not validated. No effective authorization "
            "or boot permission is concluded."
        ),
    }



MAX_PREVIOUS_REPORT = 256 * 1024
FOTA_POLICY = "/etc/dbus-1/system.d/fota-consumer.conf"
SYSTEM_POLICY = "/usr/share/dbus-1/system.conf"


def _send_candidate(rule: object) -> bool:
    """Possible method-call rule; v1 omits some filtering attributes."""
    if not isinstance(rule, dict) or rule.get("action") not in ("deny", "allow"):
        return False
    f = rule.get("fields")
    if not isinstance(f, dict) or not any(k.startswith("send_") for k in f):
        return False
    expected = {"send_destination": "fota.consumer", "send_interface": "fota.consumer",
                "send_member": "LaunchFota", "send_type": "method_call"}
    return all(value in ("*", expected[k]) for k, value in f.items() if k in expected)


def review_saved_report(report: object, source_sha256: str = "") -> dict:
    """Analyze captured v1 evidence without contacting a watch or granting access."""
    if (not isinstance(report, dict) or report.get("schema") !=
            "uglyos-r840x-dbus-policy-evidence-v1" or
            report.get("state") != "PARTIAL_STANDARD_POLICY_EVIDENCE" or
            not isinstance(report.get("policy_files"), dict)):
        raise PolicyError("POLICY_REVIEW_EXPECTS_V1_PARTIAL_REPORT")
    files = report["policy_files"]
    fota, system = files.get(FOTA_POLICY, {}), files.get(SYSTEM_POLICY, {})
    if not isinstance(fota, dict) or not isinstance(system, dict):
        raise PolicyError("POLICY_REVIEW_INVALID_SOURCE_FILES")
    for file in (fota, system):
        rules = file.get("relevant_rules", [])
        if (not isinstance(rules, list) or len(rules) > MAX_RELEVANT_RULES or
                any(not isinstance(r, dict) or not isinstance(r.get("fields"), dict)
                    or not isinstance(r.get("scope"), dict) for r in rules)):
            raise PolicyError("POLICY_REVIEW_INVALID_RULE_LIST")

    def default_candidate(r):
        return (r["scope"].get("context") == "default" and
                r["fields"].get("send_destination") == "fota.consumer" and
                _send_candidate(r))

    candidates = [r["action"] for r in fota.get("relevant_rules", []) if default_candidate(r)]
    users = sorted({
        r["scope"]["user"] for r in fota.get("relevant_rules", [])
        if r["scope"].get("user") in ("root", "fota", "system")
        and r.get("action") == "allow"
        and r["fields"].get("send_destination") == "fota.consumer"
        and _send_candidate(r)
    })
    global_deny = any(
        r["scope"].get("context") == "default" and r.get("action") == "deny"
        and r["fields"].get("send_type") == "method_call"
        for r in system.get("relevant_rules", [])
    )
    interface_allow = any(
        default_candidate(r) and r.get("action") == "allow"
        and r["fields"].get("send_interface") == "fota.consumer"
        for r in fota.get("relevant_rules", [])
    )
    dirs = report.get("directory_results", {})
    unseen = {}
    if isinstance(dirs, dict):
        for key in ("dbus_system_vendor_policy", "dbus_system_override_policy"):
            facts = dirs.get(key, {})
            if isinstance(facts, dict) and type(facts.get("other_or_unreported_entries")) is int:
                unseen[key] = facts["other_or_unreported_entries"]
    return {
        "schema": "uglyos-r840x-dbus-policy-static-review-v1",
        "source_report_sha256": source_sha256,
        "source_is_partial": True,
        "fota_policy_file_observed": fota.get("xml_valid") is True,
        "system_default_method_call_deny_observed": global_deny,
        "explicit_fota_sender_users_observed": users,
        "fota_default_send_rule_sequence_in_extracted_file": candidates,
        "last_extracted_fota_default_send_rule": candidates[-1] if candidates else "NOT_OBSERVED",
        "fota_interface_specific_allow_observed": interface_allow,
        "potential_default_allow_after_deny": (
            "deny" in candidates[:-1] and bool(candidates) and candidates[-1] == "allow"
        ),
        "unreported_entries_in_scanned_policy_directories": unseen,
        "effective_dbus_send_permission_for_shell": "UNDETERMINED",
        "fota_consumer_method_authorization": "UNDETERMINED",
        "smack_cynara_authorization": "UNDETERMINED",
        "watch_contacted": False, "fota_method_called": False,
        "watch_write_performed": False, "root_proven": False,
        "bootloader_unlocked": False, "stock_recovery_proven": False,
        "interpretation": (
            "A later default allow candidate may override an earlier default deny "
            "for matching interface traffic. Not a bus authorization verdict: "
            "v1 discarded other rules and match attributes; actual include/order "
            "and unseen policy files, bus sender UID, SMACK/Cynara and consumer "
            "checks remain unknown."
        ),
    }


def read_existing_report(path: Path) -> tuple[dict, str]:
    """Bounded local no-symlink regular-file read. Never opens a watch socket."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        raise PolicyError("POLICY_REVIEW_INPUT_UNREADABLE") from None
    with os.fdopen(descriptor, "rb") as stream:
        metadata = os.fstat(stream.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_PREVIOUS_REPORT:
            raise PolicyError("POLICY_REVIEW_INPUT_INVALID_TYPE_OR_SIZE")
        raw = stream.read(MAX_PREVIOUS_REPORT + 1)
    if not raw or len(raw) > MAX_PREVIOUS_REPORT:
        raise PolicyError("POLICY_REVIEW_INPUT_INVALID_SIZE")
    try:
        record = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeError):
        raise PolicyError("POLICY_REVIEW_INVALID_JSON") from None
    return record, hashlib.sha256(raw).hexdigest()



RUNTIME_ALLOWED_OPS = frozenset(("dbus_runtime_unit", "service_process_snapshot"))
RUNTIME_EXECUTABLES = {"dbus-daemon": "DBUS_DAEMON",
                       "dbus-broker-launch": "DBUS_BROKER_LAUNCH"}
RUNTIME_PROCESS_LIMIT = 4
RUNTIME_RAW_MAX = 64 * 1024


def runtime_bus_query(ip: str, key: Path, operation: str, timeout=8) -> str:
    """Existing SDB allowlist; no activation, FOTA or arbitrary shell input."""
    if operation not in RUNTIME_ALLOWED_OPS:
        raise PolicyError("RUNTIME_OPERATION_NOT_ALLOWLISTED")
    for style in ("standard", "tizen-command"):
        try:
            with socket.create_connection((ip, PORT), timeout=timeout) as sock:
                sock.settimeout(timeout)
                channel = Connection(sock, key)
                channel.handshake()
                return channel.shell(operation, style=style)
        except ShellCloseError:
            if style == "tizen-command":
                raise PolicyError("RUNTIME_SDB_SHELL_UNAVAILABLE") from None
        except (SdbError, OSError, TimeoutError):
            raise PolicyError("RUNTIME_SDB_CONNECTION_FAILED") from None
    raise PolicyError("RUNTIME_SDB_SHELL_UNAVAILABLE")


def _daemon_family(command: str) -> str | None:
    """Match only the argv0 basename, never a command mentioned as an arg."""
    if not isinstance(command, str) or len(command) > 4096:
        return None
    first = command.strip().split(None, 1)[0] if command.strip() else ""
    if not re.fullmatch(r"(/[A-Za-z0-9_+./-]{1,160}/)?[A-Za-z0-9_-]{1,60}", first):
        return None
    return RUNTIME_EXECUTABLES.get(first.rsplit("/", 1)[-1])


def _config_flag_class(command: str) -> str:
    """Redact argv and paths other than the already-captured three configs."""
    matches = re.findall(r"(?:^|\s)--config-file(?:=|\s+)([^\s;]+)", command)
    if not matches:
        return "NO_EXPLICIT_CONFIG_FLAG_SEEN"
    if len(matches) != 1:
        return "AMBIGUOUS_CONFIG_FLAG"
    return ("CAPTURED_CORE_SYSTEM_CONF" if matches[0] ==
            "/usr/share/dbus-1/system.conf" else
            "CAPTURED_ETC_SYSTEM_CONF" if matches[0] ==
            "/etc/dbus-1/system.conf" else
            "OTHER_EXPLICIT_CONFIG_REDACTED")


def parse_runtime_unit(raw: str) -> dict:
    """Only categorical fields from systemctl show; no full ExecStart stored."""
    if not isinstance(raw, str) or len(raw) > 8192:
        raise PolicyError("RUNTIME_UNIT_OUTPUT_INVALID")
    if any(part in raw.lower() for part in ("access denied", "permission denied")):
        raise PolicyError("RUNTIME_UNIT_ACCESS_DENIED")
    fields = {}
    for line in raw.splitlines():
        if "=" not in line:
            raise PolicyError("RUNTIME_UNIT_OUTPUT_INVALID")
        key, value = line.split("=", 1)
        if key not in ("Id", "LoadState", "ActiveState", "SubState",
                       "MainPID", "ExecStart") or key in fields or len(value) > 4096:
            raise PolicyError("RUNTIME_UNIT_OUTPUT_INVALID")
        fields[key] = value
    if set(fields) != {"Id", "LoadState", "ActiveState", "SubState",
                       "MainPID", "ExecStart"}:
        raise PolicyError("RUNTIME_UNIT_OUTPUT_INVALID")
    if fields["Id"] not in ("dbus.service", "dbus-daemon.service", "dbus-broker.service"):
        raise PolicyError("RUNTIME_UNIT_UNEXPECTED_ID")
    if any(not re.fullmatch(r"[a-z][a-z0-9-]{0,40}", fields[k])
           for k in ("LoadState", "ActiveState", "SubState")):
        raise PolicyError("RUNTIME_UNIT_OUTPUT_INVALID")
    if not re.fullmatch(r"(0|[1-9][0-9]{0,7})", fields["MainPID"]):
        raise PolicyError("RUNTIME_UNIT_OUTPUT_INVALID")
    m = re.search(r"(?:^|\{\s*)path=([^\s;]+)\s*;", fields["ExecStart"])
    family = _daemon_family(m.group(1)) if m else None
    return {
        "unit_id_class": fields["Id"],
        "unit_loaded": fields["LoadState"] == "loaded",
        "unit_active": fields["ActiveState"] == "active",
        "unit_substate": fields["SubState"],
        "main_pid_present": int(fields["MainPID"]) > 0,
        "configured_daemon_family": family or "UNRECOGNIZED_OR_NOT_OBSERVED",
        "configured_explicit_config_class": _config_flag_class(fields["ExecStart"]),
        "unit_is_runtime_process_attestation": False,
    }


def parse_runtime_ps(raw: str) -> dict:
    """Inspect one passive bounded ps output, discarding all unrelated argv."""
    if not isinstance(raw, str) or not 1 <= len(raw) <= RUNTIME_RAW_MAX:
        raise PolicyError("RUNTIME_PROCESS_OUTPUT_INVALID")
    lines = raw.splitlines()
    if len(lines) > 2000 or len(lines) < 1:
        raise PolicyError("RUNTIME_PROCESS_OUTPUT_INVALID")
    header = lines[0].split()
    # The previously observed BusyBox ps format is PID USER VSZ STAT COMMAND.
    # Different layouts must not be misinterpreted as runtime confirmation.
    if header[:5] != ["PID", "USER", "VSZ", "STAT", "COMMAND"]:
        return {"status": "PS_LAYOUT_UNSUPPORTED", "candidate_processes": [],
                "truncated": False}
    observed = []
    all_count = 0
    for line in lines[1:]:
        chunks = line.strip().split(None, 4)
        if len(chunks) != 5 or not chunks[0].isdigit():
            continue
        family = _daemon_family(chunks[4])
        if not family:
            continue
        all_count += 1
        if len(observed) < RUNTIME_PROCESS_LIMIT:
            observed.append({
                "daemon_family": family,
                "explicit_config_class": _config_flag_class(chunks[4]),
                "system_flag_observed": bool(re.search(r"(?:^|\s)--system(?:\s|$)", chunks[4])),
                "process_is_system_bus_attested": False,
            })
    return {
        "status": "PS_SNAPSHOT_PARSED",
        "candidate_processes": observed,
        "truncated": all_count > RUNTIME_PROCESS_LIMIT,
    }


def collect_runtime_bus(ip: str, key: Path) -> dict:
    """Two bounded preexisting system commands; no mutation or daemon RPC."""
    ip = private_watch_ip(ip)
    sources = {}
    for operation, decoder in (("dbus_runtime_unit", parse_runtime_unit),
                               ("service_process_snapshot", parse_runtime_ps)):
        try:
            sources[operation] = decoder(runtime_bus_query(ip, key, operation))
        except PolicyError as exc:
            sources[operation] = {"status": str(exc)}
    return {
        "schema": "uglyos-r840x-running-dbus-provenance-v1",
        "state": "PARTIAL_READONLY_RUNTIME_PROVENANCE",
        "sources": sources,
        "runtime_daemon_config_loaded_verified": False,
        "running_daemon_arguments_independently_attested": False,
        "complete_effective_dbus_policy_verified": False,
        "sender_bus_uid_verified": False,
        "smack_cynara_authorization": "UNDETERMINED",
        "effective_dbus_send_permission_for_shell": "UNDETERMINED",
        "fota_consumer_method_authorization": "UNDETERMINED",
        "fota_method_called": False, "watch_write_performed": False,
        "root_proven": False, "bootloader_unlocked": False,
        "stock_recovery_proven": False,
        "interpretation": (
            "Only a bounded snapshot of the configured dbus.service and "
            "candidate process names/flags. Unit properties, even when active, "
            "do not attest the actual executable arguments or fully merged "
            "D-Bus policy. No sender authorization, privileged service method, "
            "security bypass or firmware write was tested."
        ),
    }


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument("--watch-ip", help="Authenticated read-only physical policy capture")
    mode.add_argument("--offline-report", type=Path, help="Local saved v1 report; NO WATCH")
    mode.add_argument("--focused-detail-ip", help="Read only three fixed original D-Bus policy XML files")
    mode.add_argument("--offline-focused-report", type=Path, help="Review exact original three-file JSON without watch access")
    mode.add_argument("--runtime-ip", help="Two read-only metadata queries on existing system bus process/unit")
    p.add_argument("--key-path", type=Path, default=Path.home()/".config/galaxy3/watch3-sdbkey")
    p.add_argument("--report", type=Path, default=None)
    args = p.parse_args(argv)
    output_path = args.report or Path.home() / ("watch3-r840x-dbus-policy-static-review.json"
        if args.offline_report else "watch3-r840x-dbus-focused-default-rule-audit.json"
        if args.offline_focused_report else "watch3-r840x-dbus-runtime-provenance.json"
        if args.runtime_ip else "watch3-r840x-dbus-focused-original-rules.json"
        if args.focused_detail_ip else "watch3-r840x-dbus-policy-evidence.json")
    try:
        if output_path.exists() or output_path.is_symlink():
            raise PolicyError("POLICY_REPORT_ALREADY_EXISTS")
        if not output_path.parent.is_dir():
            raise PolicyError("POLICY_REPORT_PARENT_MISSING")
        if args.offline_report:
            source, digest = read_existing_report(args.offline_report)
            result = review_saved_report(source, source_sha256=digest)
        elif args.offline_focused_report:
            source, digest = read_existing_report(args.offline_focused_report)
            result = review_focused_report(source, source_sha256=digest)
        elif args.focused_detail_ip:
            result = collect_focused(args.focused_detail_ip, args.key_path)
        elif args.runtime_ip:
            result = collect_runtime_bus(args.runtime_ip, args.key_path)
        else:
            result = collect(args.watch_ip, args.key_path)
        payload = (json.dumps(result, indent=2)+"\n").encode("utf-8")
        fd = os.open(output_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "wb") as output:
                output.write(payload)
                output.flush()
                os.fsync(output.fileno())
        except BaseException:
            output_path.unlink(missing_ok=True)
            raise
    except (PolicyError, OSError, ValueError) as exc:
        print("POLICY_EVIDENCE_ERROR: " + (str(exc) if isinstance(exc, PolicyError)
            else "LOCAL_OR_SDB_ERROR"), file=sys.stderr)
        return 1
    print(("OFFLINE_DBUS_POLICY_STATIC_REVIEW: " if args.offline_report else
           "OFFLINE_DBUS_FOCUSED_RULE_AUDIT: " if args.offline_focused_report else
           "READ_ONLY_DBUS_RUNTIME_PROVENANCE: " if args.runtime_ip else
           "READ_ONLY_DBUS_FOCUSED_ORIGINAL_RULES: " if args.focused_detail_ip else
           "READ_ONLY_DBUS_POLICY_EVIDENCE: ")+str(output_path))
    print("Partial config evidence only; no service call, execution or watch write.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
