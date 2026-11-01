"""NO WATCH fixture tests for bounded FOTA D-Bus policy reads."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import watch3_r840x_dbus_policy_readonly as policy
from watch3_r08_fota_consumer_inventory import (
    DBUS_POLICY_DIRECTORIES, DirectoryDecoder, InventoryError,
)
import struct


XML = b"""<?xml version="1.0"?>
<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN" "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
<includedir>system.d</includedir>
<policy context="default"><deny send_type="method_call"/><allow send_destination="fota.consumer"/></policy>
<policy user="fota"><allow own="fota.consumer"/></policy>
<policy user="another"><allow send_destination="something.other"/></policy>
</busconfig>
"""


def dent(name, mode=0o100644, size=1024):
    n = name.encode("ascii")
    return struct.pack("<4sIIII",b"DENT",mode,size,0,len(n))+n


def done():
    return struct.pack("<4sIIII",b"DONE",0,0,0,0)


class PolicyTests(unittest.TestCase):
    def test_standard_paths_fixed_and_private(self):
        self.assertEqual(DBUS_POLICY_DIRECTORIES, {
            "dbus_system_vendor_policy": b"/usr/share/dbus-1/system.d",
            "dbus_system_override_policy": b"/etc/dbus-1/system.d",
        })
        self.assertTrue(policy.allowed_path(b"/usr/share/dbus-1/system.conf"))
        self.assertTrue(policy.allowed_path(b"/etc/dbus-1/system.d/fota.consumer.conf"))
        self.assertFalse(policy.allowed_path(b"/etc/passwd"))
        self.assertFalse(policy.allowed_path(b"/etc/dbus-1/system.d/../secret.conf"))
        self.assertFalse(policy.allowed_path(b"/etc/dbus-1/system.d/not-fota.conf.bak"))

    def test_policy_xml_extracts_rules_but_not_permission_claim(self):
        report = policy.analyze_xml(XML)
        self.assertTrue(report["xml_valid"])
        self.assertEqual(report["sha256"],hashlib.sha256(XML).hexdigest())
        self.assertEqual(report["includedir_tags"],1)
        self.assertEqual(len(report["relevant_rules"]),3)
        self.assertFalse(report["actual_effective_policy_proven"])
        self.assertEqual(report["other_policy_blocks"],1)

    def test_reject_entity_and_internal_section(self):
        for raw in (b'<busconfig><!ENTITY xx "oops"></busconfig>',
                    b'<busconfig><![CDATA[foo]]></busconfig>'):
            with self.assertRaisesRegex(policy.PolicyError,"POLICY_XML_ENTITY_OR_SECTION_REJECTED"):
                policy.analyze_xml(raw)

    def test_malformed_and_size_limits(self):
        with self.assertRaisesRegex(policy.PolicyError,"POLICY_XML_UNEXPECTED_ROOT"):
            policy.analyze_xml(b"<foo/>")
        with self.assertRaisesRegex(policy.PolicyError,"POLICY_XML_MALFORMED"):
            policy.analyze_xml(b"<busconfig><policy>")
        with self.assertRaisesRegex(policy.PolicyError,"POLICY_XML_SIZE_INVALID"):
            policy.analyze_xml(b"x"*(policy.MAX_BYTES+1))

    def test_inventory_lists_only_fota_conf(self):
        dec=DirectoryDecoder()
        dec.feed(dent("other.conf") + dent("fota.consumer.conf") +
                 dent("update-manager.conf")+done(), "dbus_system_vendor_policy")
        result=dec.report("dbus_system_vendor_policy")
        self.assertEqual(result["status"],"LIST_COMPLETE")
        self.assertEqual(set(result["matching_fota_policy_files"]),
                         {"fota.consumer.conf","update-manager.conf"})
        self.assertEqual(result["other_or_unreported_entries"],1)

    def test_collect_uses_only_observed_regular_file(self):
        calls=[]
        def fake_read(ip,key,path):
            calls.append(path)
            return XML
        def fake_list(ip,key,scope):
            return {"status":"LIST_COMPLETE","matching_names_truncated":False,
                    "matching_fota_policy_files":{
                        "fota.consumer.conf":{"kind":"REGULAR_FILE","bytes":len(XML)},
                        "update-link.conf":{"kind":"SYMLINK","bytes":len(XML)},
                        "other.conf":{"kind":"REGULAR_FILE","bytes":len(XML)},
                    }}
        with patch.object(policy,"read_file",side_effect=fake_read), patch.object(
                policy,"list_policy_dir",side_effect=fake_list):
            result=policy.collect("10.115.12.131", Path("/unused"))
        self.assertEqual(len(calls),5)
        self.assertEqual(sum(x.endswith(b"/fota.consumer.conf") for x in calls),2)
        self.assertFalse(any(x.endswith(b"/other.conf") for x in calls))
        self.assertFalse(any(x.endswith(b"/update-link.conf") for x in calls))
        self.assertFalse(result["bus_policy_complete"])
        self.assertEqual(result["user_shell_authorized_for_fota"],"UNDETERMINED")
        self.assertFalse(result["fota_method_called"])
        self.assertFalse(result["watch_write_performed"])

    def test_denied_files_and_empty_lists_keep_partial_state(self):
        def denied(ip,key,path):
            raise policy.PolicyError("POLICY_RECV_DENIED")
        with patch.object(policy,"read_file",side_effect=denied) as reads, patch.object(
                policy,"list_policy_dir",return_value={"status":"EMPTY_OR_INACCESSIBLE"}):
            result=policy.collect("10.115.12.131",Path("/unused"))
        self.assertEqual(reads.call_count,3)
        self.assertTrue(all(row["status"]=="POLICY_RECV_DENIED"
                            for row in result["policy_files"].values()))
        self.assertEqual(result["state"],"PARTIAL_STANDARD_POLICY_EVIDENCE")

    def test_excessive_names_fail_closed(self):
        with patch.object(policy,"read_file",return_value=XML) as reads, patch.object(
                policy,"list_policy_dir",return_value={
                    "status":"LIST_COMPLETE","matching_names_truncated":True,
                    "matching_fota_policy_files":{
                        "fota.consumer.conf":{"kind":"REGULAR_FILE","bytes":len(XML)},
                    }}):
            result=policy.collect("10.115.12.131",Path("/unused"))
        self.assertEqual(reads.call_count,3)
        self.assertEqual(len(result["policy_files"]),3)

    def test_invalid_remote_path_before_network(self):
        with patch.object(policy.socket,"create_connection",side_effect=AssertionError("NO NETWORK")):
            with self.assertRaisesRegex(policy.PolicyError,"POLICY_PATH_NOT_ALLOWLISTED"):
                policy.read_file("10.0.0.4",Path("/unused"),b"/etc/shadow")

    def test_main_refuses_existing_report_without_watch(self):
        with tempfile.TemporaryDirectory() as td:
            out=Path(td)/"policy.json"
            out.write_text("KEEP")
            with patch.object(policy,"collect",side_effect=AssertionError("MUST NOT COLLECT")):
                rc=policy.main(["--watch-ip","10.115.12.131","--report",str(out)])
            self.assertEqual(rc,1)
            self.assertEqual(out.read_text(),"KEEP")

    def test_main_private_report_and_no_clobber(self):
        with tempfile.TemporaryDirectory() as td:
            out=Path(td)/"policy.json"
            report={"state":"PARTIAL_STANDARD_POLICY_EVIDENCE","watch_write_performed":False}
            with patch.object(policy,"collect",return_value=report):
                rc=policy.main(["--watch-ip","10.115.12.131","--report",str(out)])
            self.assertEqual(rc,0)
            self.assertEqual(out.stat().st_mode & 0o077,0)
            self.assertFalse(json.loads(out.read_text())["watch_write_performed"])



def captured_v1_fixture(allow_after_deny=True):
    rules = [
        {"scope":{"user":"root"},"action":"allow","fields":{"send_destination":"fota.consumer"}},
        {"scope":{"user":"fota"},"action":"allow","fields":{"own":"fota.consumer"}},
        {"scope":{"user":"fota"},"action":"allow","fields":{"send_destination":"fota.consumer"}},
        {"scope":{"user":"system"},"action":"allow","fields":{"send_destination":"fota.consumer"}},
        {"scope":{"context":"default"},"action":"deny","fields":{"own":"fota.consumer"}},
        {"scope":{"context":"default"},"action":"deny","fields":{
            "send_destination":"fota.consumer","send_type":"method_call"}},
        {"scope":{"context":"default"},"action":"allow","fields":{
            "send_destination":"fota.consumer","send_interface":"fota.consumer"}},
    ]
    if not allow_after_deny:
        rules[-2],rules[-1] = rules[-1],rules[-2]
    return {
        "schema":"uglyos-r840x-dbus-policy-evidence-v1",
        "state":"PARTIAL_STANDARD_POLICY_EVIDENCE",
        "policy_files":{
            "/usr/share/dbus-1/system.conf":{
                "xml_valid":True,
                "relevant_rules":[{"scope":{"context":"default"},"action":"deny",
                                   "fields":{"send_type":"method_call"}}],
            },
            "/etc/dbus-1/system.d/fota-consumer.conf":{
                "xml_valid":True,"relevant_rules":rules,
            },
        },
        "directory_results":{
            "dbus_system_override_policy":{"status":"LIST_COMPLETE",
                                           "other_or_unreported_entries":103},
        },
        "bus_policy_complete":False,
        "user_shell_authorized_for_fota":"UNDETERMINED",
    }


class OfflinePolicyReviewTests(unittest.TestCase):
    def test_actual_observed_rule_sequence_flags_ambiguity_not_access(self):
        r=policy.review_saved_report(captured_v1_fixture(),source_sha256="test")
        self.assertEqual(r["explicit_fota_sender_users_observed"],["fota","root","system"])
        self.assertEqual(r["fota_default_send_rule_sequence_in_extracted_file"],["deny","allow"])
        self.assertTrue(r["fota_interface_specific_allow_observed"])
        self.assertTrue(r["system_default_method_call_deny_observed"])
        self.assertTrue(r["potential_default_allow_after_deny"])
        self.assertEqual(r["effective_dbus_send_permission_for_shell"],"UNDETERMINED")
        self.assertFalse(r["watch_contacted"])
        self.assertFalse(r["fota_method_called"])

    def test_last_deny_does_not_flag_possible_later_exception(self):
        r=policy.review_saved_report(captured_v1_fixture(False))
        self.assertEqual(r["last_extracted_fota_default_send_rule"],"deny")
        self.assertFalse(r["potential_default_allow_after_deny"])

    def test_different_interface_does_not_count_as_matching_allow(self):
        v=captured_v1_fixture()
        v["policy_files"]["/etc/dbus-1/system.d/fota-consumer.conf"]["relevant_rules"][-1]["fields"]["send_interface"]="different.interface"
        r=policy.review_saved_report(v)
        self.assertEqual(r["fota_default_send_rule_sequence_in_extracted_file"],["deny"])
        self.assertFalse(r["fota_interface_specific_allow_observed"])

    def test_own_rule_not_send_rule(self):
        v=captured_v1_fixture()
        v["policy_files"]["/etc/dbus-1/system.d/fota-consumer.conf"]["relevant_rules"][-1]["fields"]={"own":"fota.consumer"}
        r=policy.review_saved_report(v)
        self.assertEqual(r["fota_default_send_rule_sequence_in_extracted_file"],["deny"])

    def test_absent_fota_xml_remains_unknown(self):
        v=captured_v1_fixture()
        v["policy_files"].pop("/etc/dbus-1/system.d/fota-consumer.conf")
        r=policy.review_saved_report(v)
        self.assertFalse(r["fota_policy_file_observed"])
        self.assertEqual(r["last_extracted_fota_default_send_rule"],"NOT_OBSERVED")
        self.assertEqual(r["effective_dbus_send_permission_for_shell"],"UNDETERMINED")

    def test_reject_wrong_schema_and_malformed_rule(self):
        v=captured_v1_fixture()
        v["schema"]="some-other-schema"
        with self.assertRaisesRegex(policy.PolicyError,"POLICY_REVIEW_EXPECTS_V1_PARTIAL_REPORT"):
            policy.review_saved_report(v)
        v=captured_v1_fixture()
        v["policy_files"]["/etc/dbus-1/system.d/fota-consumer.conf"]["relevant_rules"]=[None]
        with self.assertRaisesRegex(policy.PolicyError,"POLICY_REVIEW_INVALID_RULE_LIST"):
            policy.review_saved_report(v)

    def test_offline_cli_does_not_connect_watch(self):
        with tempfile.TemporaryDirectory() as td:
            src, dest=Path(td)/"source.json",Path(td)/"review.json"
            src.write_text(json.dumps(captured_v1_fixture()))
            with patch.object(policy.socket,"create_connection",side_effect=AssertionError("NO WATCH")):
                rc=policy.main(["--offline-report",str(src),"--report",str(dest)])
            self.assertEqual(rc,0)
            result=json.loads(dest.read_text())
            self.assertTrue(result["potential_default_allow_after_deny"])
            self.assertEqual(result["source_report_sha256"],hashlib.sha256(src.read_bytes()).hexdigest())
            self.assertEqual(dest.stat().st_mode & 0o077,0)
            self.assertEqual(policy.main(["--offline-report",str(src),"--report",str(dest)]),1)
            self.assertEqual(json.loads(dest.read_text()),result)

    def test_reject_symlink_input_before_read(self):
        with tempfile.TemporaryDirectory() as td:
            original=Path(td)/"original.json"
            original.write_text(json.dumps(captured_v1_fixture()))
            link=Path(td)/"link.json"
            link.symlink_to(original)
            with self.assertRaisesRegex(policy.PolicyError,"POLICY_REVIEW_INPUT_UNREADABLE"):
                policy.read_existing_report(link)

    def test_oversize_and_bad_json_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            source=Path(td)/"source.json"
            source.write_bytes(b"{"* (policy.MAX_PREVIOUS_REPORT + 1))
            with self.assertRaisesRegex(policy.PolicyError,"POLICY_REVIEW_INPUT_INVALID_TYPE_OR_SIZE"):
                policy.read_existing_report(source)
            source.write_text("{")
            with self.assertRaisesRegex(policy.PolicyError,"POLICY_REVIEW_INVALID_JSON"):
                policy.read_existing_report(source)

    def test_old_watch_cli_entrypoint_remains_supported(self):
        with tempfile.TemporaryDirectory() as td:
            dest=Path(td)/"evidence.json"
            record={"state":"PARTIAL_STANDARD_POLICY_EVIDENCE"}
            with patch.object(policy,"collect",return_value=record) as collect:
                rc=policy.main(["--watch-ip","10.115.12.131","--report",str(dest)])
            self.assertEqual(rc,0)
            collect.assert_called_once()
            self.assertEqual(json.loads(dest.read_text()),record)


ORIGINAL_FOCUSED_XML = b"""<?xml version="1.0"?>
<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN" "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
 <includedir>system.d</includedir>
 <include ignore_missing="yes">system-local.conf</include>
 <policy context="default">
  <deny send_destination="fota.consumer" send_type="method_call"/>
  <allow send_destination="fota.consumer" send_interface="fota.consumer"
         send_path="/fota/consumer" send_member="LaunchFota"
         send_requested_reply="true" custom_match="must-not-lose"/>
 </policy>
 <policy user="fota"><allow own="fota.consumer"/></policy>
</busconfig>
"""


class FocusedOriginalPolicyTests(unittest.TestCase):
    def test_retains_original_rule_order_and_full_matching_attributes(self):
        doc=policy.focused_policy_xml(ORIGINAL_FOCUSED_XML)
        self.assertEqual(doc["ordered_config_nodes"][0]["kind"],"includedir")
        self.assertEqual(doc["ordered_config_nodes"][0]["path"],"system.d")
        self.assertEqual(doc["ordered_config_nodes"][1]["path"],"system-local.conf")
        rules=doc["ordered_config_nodes"][2]["rules"]
        self.assertEqual([r["action"] for r in rules],["deny","allow"])
        allow=rules[1]
        self.assertEqual(allow["attributes"]["send_path"],"/fota/consumer")
        self.assertEqual(allow["attributes"]["send_member"],"LaunchFota")
        self.assertEqual(allow["attributes"]["send_requested_reply"],"true")
        self.assertEqual(allow["unreported_attribute_names"],["custom_match"])
        self.assertEqual(doc["effective_sender_permission"],"UNDETERMINED")

    def test_preserves_user_scope_and_sanitizes_include_text(self):
        doc=policy.focused_policy_xml(ORIGINAL_FOCUSED_XML)
        self.assertEqual(doc["ordered_config_nodes"][3]["scope"],{"user":"fota"})
        xml=b'<busconfig><include>../../secret?foo=bar</include></busconfig>'
        self.assertEqual(policy.focused_policy_xml(xml)["ordered_config_nodes"][0]["path"],"UNREPORTED")

    def test_rejects_entity_and_size_and_malformed_xml(self):
        for raw in (b'<busconfig><!ENTITY secret "bad"/></busconfig>',
                    b"x"*(policy.MAX_BYTES+1),
                    b"<busconfig><policy>"):
            with self.assertRaises(policy.PolicyError):
                policy.focused_policy_xml(raw)

    def test_focused_sources_fixed_and_hashes_known_from_capture(self):
        self.assertEqual(policy.FOCUSED_FILES,(
            b"/usr/share/dbus-1/system.conf",b"/etc/dbus-1/system.conf",
            b"/etc/dbus-1/system.d/fota-consumer.conf",
        ))
        self.assertEqual(policy.EXPECTED_FOCUSED_SHA256[
            "/etc/dbus-1/system.d/fota-consumer.conf"],
            "499ae912f2397720c952f27143d2112427509b95335c91d5b0ec7749e6999fec")

    def test_focused_collect_uses_exactly_three_originals_and_no_lists(self):
        observed=[]
        def read(ip,key,path):
            observed.append(path)
            return ORIGINAL_FOCUSED_XML
        with patch.object(policy,"read_file",side_effect=read),patch.object(
                policy,"list_policy_dir",side_effect=AssertionError("NO DIRECTORY SCAN")):
            result=policy.collect_focused("10.115.12.131",Path("/unused"))
        self.assertEqual(observed,list(policy.FOCUSED_FILES))
        self.assertEqual(result["state"],"FOCUSED_FILES_ONLY")
        self.assertFalse(result["bus_config_load_order_verified"])
        self.assertFalse(result["other_103_directory_entries_inspected"])
        self.assertFalse(result["fota_method_called"])
        self.assertFalse(result["watch_write_performed"])
        self.assertFalse(result["policy_files"][
            "/etc/dbus-1/system.d/fota-consumer.conf"]["matches_october_30_v1_sha256"])

    def test_denied_target_produces_categorical_outcome_not_permission(self):
        with patch.object(policy,"read_file",
                          side_effect=policy.PolicyError("POLICY_RECV_DENIED")):
            result=policy.collect_focused("10.115.12.131",Path("/unused"))
        self.assertEqual(len(result["policy_files"]),3)
        self.assertTrue(all(item["status"]=="POLICY_RECV_DENIED"
                            for item in result["policy_files"].values()))
        self.assertEqual(result["effective_dbus_send_permission_for_shell"],"UNDETERMINED")

    def test_cli_rejects_overlapping_capture_modes(self):
        with self.assertRaises(SystemExit):
            policy.main(["--watch-ip","10.115.12.131","--focused-detail-ip","10.115.12.131"])

    def test_focused_cli_private_report_no_clobber_and_no_sdb_in_test(self):
        with tempfile.TemporaryDirectory() as td:
            dest=Path(td)/"focused.json"
            record={"schema":"uglyos-r840x-dbus-focused-original-rules-v1",
                    "watch_write_performed":False}
            with patch.object(policy,"collect_focused",return_value=record),patch.object(
                    policy.socket,"create_connection",side_effect=AssertionError("NO NETWORK")):
                rc=policy.main(["--focused-detail-ip","10.115.12.131","--report",str(dest)])
                again=policy.main(["--focused-detail-ip","10.115.12.131","--report",str(dest)])
            self.assertEqual(rc,0)
            self.assertEqual(again,1)
            self.assertEqual(dest.stat().st_mode & 0o077,0)
            self.assertEqual(json.loads(dest.read_text()),record)

    def test_original_offline_cli_remains_unmodified(self):
        with tempfile.TemporaryDirectory() as td:
            src,dest=Path(td)/"prior.json",Path(td)/"review.json"
            src.write_text(json.dumps(captured_v1_fixture()))
            with patch.object(policy.socket,"create_connection",side_effect=AssertionError("NO NETWORK")):
                rc=policy.main(["--offline-report",str(src),"--report",str(dest)])
            self.assertEqual(rc,0)
            self.assertTrue(json.loads(dest.read_text())["potential_default_allow_after_deny"])

    def test_focused_allows_only_fixed_files(self):
        self.assertTrue(policy.allowed_path(policy.FOCUSED_FILES[-1]))
        self.assertFalse(policy.allowed_path(b"/etc/dbus-1/system.d/../shadow"))
        self.assertFalse(policy.allowed_path(b"/etc/dbus-1/system.d/other.conf"))



def full_original_subset_fixture():
    """Synthetic projection of observed original policy rule shape; no vendor bytes."""
    def rule(action, **attrs):
        return {"action": action, "attributes": attrs, "unreported_attribute_names": []}
    def policy_node(scope, rules):
        return {"kind": "policy", "scope": scope,
                "unrecognized_scope_names": [], "rules": rules, "other_nodes": 0}
    fota_nodes = [
        policy_node({"user": "root"}, [
            rule("allow", send_destination="fota.consumer"),
        ]),
        policy_node({"user": "fota"}, [
            rule("allow", own="fota.consumer"),
            rule("allow", send_destination="fota.consumer"),
        ]),
        policy_node({"user": "system"}, [
            rule("allow", send_destination="fota.consumer"),
        ]),
        policy_node({"context": "default"}, [
            rule("deny", own="fota.consumer"),
            rule("deny", send_destination="fota.consumer", send_type="method_call"),
            rule("allow", send_destination="fota.consumer", send_interface="fota.consumer"),
        ]),
    ]
    general_nodes = [
        policy_node({"context": "default"}, [
            rule("allow", user="*"),
            rule("deny", own="*"),
            rule("deny", send_type="method_call"),
            rule("allow", send_destination="org.freedesktop.DBus",
                 send_interface="org.freedesktop.DBus"),
        ]),
        {"kind": "include", "path": "/etc/dbus-1/system.conf", "attributes": {}},
        {"kind": "includedir", "path": "system.d", "attributes": {}},
        {"kind": "includedir", "path": "/etc/dbus-1/system.d", "attributes": {}},
        {"kind": "include", "path": "/etc/dbus-1/system-local.conf",
         "attributes": {"ignore_missing": "yes"}},
    ]
    original = {
        "/usr/share/dbus-1/system.conf": general_nodes,
        "/etc/dbus-1/system.conf": [],
        "/etc/dbus-1/system.d/fota-consumer.conf": fota_nodes,
    }
    return {
        "schema": "uglyos-r840x-dbus-focused-original-rules-v1",
        "state": "FOCUSED_FILES_ONLY",
        "policy_files": {
            name: {
                "xml_valid": True, "ordered_config_nodes": nodes,
                "sha256": policy.EXPECTED_FOCUSED_SHA256[name],
                "matches_october_30_v1_sha256": True,
            } for name, nodes in original.items()
        },
        "bus_config_load_order_verified": False,
        "effective_dbus_send_permission_for_shell": "UNDETERMINED",
    }


class FocusedDefaultAuditTests(unittest.TestCase):
    @staticmethod
    def review(fixture=None):
        return policy.review_focused_report(
            fixture if fixture is not None else full_original_subset_fixture(),
            source_sha256="test")

    def test_owner_observed_exact_default_sequence_exposes_later_allow(self):
        actual = self.review()
        self.assertTrue(actual["exact_original_three_hashes_matched"])
        self.assertTrue(actual["core_default_method_deny_observed"])
        self.assertEqual(actual["fota_default_rule_sequence_for_hypothetical_message"],
                         ["deny", "allow"])
        self.assertEqual(actual["observed_default_subset_result"],
                         "LATER_FOTA_INTERFACE_ALLOW_MATCHES")
        self.assertFalse(actual["matching_rule_subset_has_unknowns_or_drift"])
        self.assertEqual(actual["effective_dbus_send_permission_for_shell"],
                         "UNDETERMINED")
        self.assertFalse(actual["watch_contacted"])
        self.assertFalse(actual["fota_method_called"])
        self.assertFalse(actual["root_proven"])

    def test_missing_interface_attribute_cannot_match_unrelated_interface(self):
        value = full_original_subset_fixture()
        fota = value["policy_files"]["/etc/dbus-1/system.d/fota-consumer.conf"]
        fota["ordered_config_nodes"][-1]["rules"][-1]["attributes"]["send_interface"] = "other.interface"
        result = self.review(value)
        self.assertEqual(result["fota_default_rule_sequence_for_hypothetical_message"], ["deny"])
        self.assertEqual(result["observed_default_subset_result"], "INCONCLUSIVE")

    def test_later_specific_deny_changes_observed_subset_conclusion(self):
        value = full_original_subset_fixture()
        rules = value["policy_files"]["/etc/dbus-1/system.d/fota-consumer.conf"]["ordered_config_nodes"][-1]["rules"]
        rules.append({"action": "deny", "attributes": {
            "send_destination": "fota.consumer", "send_member": "LaunchFota",
        }, "unreported_attribute_names": []})
        result = self.review(value)
        self.assertEqual(result["fota_last_matching_default_rule"], "deny")
        self.assertEqual(result["observed_default_subset_result"], "INCONCLUSIVE")

    def test_unknown_send_constraint_does_not_claim_local_allow(self):
        value = full_original_subset_fixture()
        allow = value["policy_files"]["/etc/dbus-1/system.d/fota-consumer.conf"]["ordered_config_nodes"][-1]["rules"][-1]
        allow["attributes"]["send_destination_prefix"] = "unknown"
        result = self.review(value)
        self.assertTrue(result["matching_rule_subset_has_unknowns_or_drift"])
        self.assertEqual(result["observed_default_subset_result"], "INCONCLUSIVE")

    def test_unreported_original_attribute_makes_result_inconclusive(self):
        value = full_original_subset_fixture()
        allow = value["policy_files"]["/etc/dbus-1/system.d/fota-consumer.conf"]["ordered_config_nodes"][-1]["rules"][-1]
        allow["unreported_attribute_names"] = ["future-rule-option"]
        result = self.review(value)
        self.assertTrue(result["matching_rule_subset_has_unknowns_or_drift"])

    def test_source_hash_drift_is_not_trusted(self):
        value = full_original_subset_fixture()
        value["policy_files"]["/etc/dbus-1/system.d/fota-consumer.conf"]["sha256"] = "0"*64
        result = self.review(value)
        self.assertFalse(result["exact_original_three_hashes_matched"])
        self.assertEqual(result["observed_default_subset_result"], "INCONCLUSIVE")

    def test_error_if_focused_files_missing_or_extra(self):
        value = full_original_subset_fixture()
        value["policy_files"].pop("/etc/dbus-1/system.conf")
        with self.assertRaisesRegex(policy.PolicyError, "FOCUSED_REVIEW_FILES_INCOMPLETE_OR_EXTRA"):
            self.review(value)
        value = full_original_subset_fixture()
        value["policy_files"]["/etc/shadow"] = {}
        with self.assertRaisesRegex(policy.PolicyError, "FOCUSED_REVIEW_FILES_INCOMPLETE_OR_EXTRA"):
            self.review(value)

    def test_invalid_schema_and_rule_blocks_rejected(self):
        value = full_original_subset_fixture()
        value["schema"] = "invalid"
        with self.assertRaisesRegex(policy.PolicyError, "FOCUSED_REVIEW_EXPECTS_V1_REPORT"):
            self.review(value)
        value = full_original_subset_fixture()
        value["policy_files"]["/usr/share/dbus-1/system.conf"]["ordered_config_nodes"][0]["rules"] = None
        with self.assertRaisesRegex(policy.PolicyError, "FOCUSED_REVIEW_INVALID_POLICY_BLOCK"):
            self.review(value)

    def test_host_only_cli_does_not_open_any_network_connection(self):
        with tempfile.TemporaryDirectory() as td:
            source, target = Path(td)/"source.json", Path(td)/"audit.json"
            source.write_text(json.dumps(full_original_subset_fixture()))
            with patch.object(policy.socket, "create_connection", side_effect=AssertionError("NO WATCH")):
                rc = policy.main(["--offline-focused-report", str(source), "--report", str(target)])
            self.assertEqual(rc, 0)
            obj = json.loads(target.read_text())
            self.assertEqual(obj["observed_default_subset_result"],
                             "LATER_FOTA_INTERFACE_ALLOW_MATCHES")
            self.assertEqual(obj["effective_dbus_send_permission_for_shell"],
                             "UNDETERMINED")
            self.assertEqual(target.stat().st_mode & 0o077, 0)
            with patch.object(policy.socket, "create_connection", side_effect=AssertionError("NO WATCH")):
                self.assertEqual(policy.main(
                    ["--offline-focused-report", str(source), "--report", str(target)]), 1)

    def test_watch_and_original_offline_modes_mutually_exclusive(self):
        with self.assertRaises(SystemExit):
            policy.main(["--watch-ip", "10.115.12.131",
                         "--offline-focused-report", "/tmp/data.json"])




class OriginalWatchPolicyRuleClassificationTests(unittest.TestCase):
    """Regression for reply-only rules found in original system.conf."""

    @staticmethod
    def physical_shape():
        obj=full_original_subset_fixture()
        general=obj["policy_files"]["/usr/share/dbus-1/system.conf"]["ordered_config_nodes"][0]["rules"]
        general.extend([
            {"action":"allow","attributes":{"send_type":"signal"},"unreported_attribute_names":[]},
            {"action":"allow","attributes":{"send_type":"method_return",
                                          "send_requested_reply":"true"},"unreported_attribute_names":[]},
            {"action":"allow","attributes":{"send_type":"error",
                                          "send_requested_reply":"true"},"unreported_attribute_names":[]},
            {"action":"allow","attributes":{"receive_type":"method_call"},"unreported_attribute_names":[]},
            {"action":"deny","attributes":{"send_destination":"org.freedesktop.DBus",
                            "send_interface":"org.freedesktop.DBus.Debug.Stats"},
             "unreported_attribute_names":[]},
        ])
        return obj

    def test_original_reply_only_rules_do_not_poison_method_call_subset(self):
        out=policy.review_focused_report(self.physical_shape())
        self.assertTrue(out["exact_original_three_hashes_matched"])
        self.assertEqual(out["fota_default_rule_sequence_for_hypothetical_message"],["deny","allow"])
        self.assertEqual(out["observed_default_subset_result"],"LATER_FOTA_INTERFACE_ALLOW_MATCHES")
        self.assertFalse(out["matching_rule_subset_has_unknowns_or_drift"])
        self.assertEqual(out["subset_uncertainty_reason_codes"],[])
        self.assertGreater(out["known_nonmatching_default_rules_ignored"],4)
        self.assertEqual(out["effective_dbus_send_permission_for_shell"],"UNDETERMINED")

    def test_known_mismatch_precedes_unknown_reply_constraints(self):
        rule={"action":"allow","attributes":{
            "send_type":"method_return","send_requested_reply":"true",
            "send_destination_prefix":"new-constraint"},"unreported_attribute_names":["future_field"]}
        self.assertEqual(policy._focused_default_send_matches(rule),"NO_MATCH")
        rule["attributes"]["send_type"]="method_call"
        self.assertEqual(policy._focused_default_send_matches(rule),"UNKNOWN")

    def test_known_different_destination_precedes_unknown(self):
        rule={"action":"deny","attributes":{
            "send_destination":"org.freedesktop.DBus",
            "send_requested_reply":"true"},"unreported_attribute_names":[]}
        self.assertEqual(policy._focused_default_send_matches(rule),"NO_MATCH")
        rule["attributes"]["send_destination"]="fota.consumer"
        self.assertEqual(policy._focused_default_send_matches(rule),"UNKNOWN")

    def test_unknown_on_matching_fota_allow_stays_inconclusive(self):
        obj=self.physical_shape()
        fota=obj["policy_files"]["/etc/dbus-1/system.d/fota-consumer.conf"]["ordered_config_nodes"][-1]
        fota["rules"][-1]["attributes"]["send_requested_reply"]="true"
        out=policy.review_focused_report(obj)
        self.assertTrue(out["matching_rule_subset_has_unknowns_or_drift"])
        self.assertIn("UNKNOWN_POTENTIAL_SEND_CONSTRAINT",out["subset_uncertainty_reason_codes"])
        self.assertEqual(out["observed_default_subset_result"],"INCONCLUSIVE")

    def test_changed_original_sha_is_a_distinct_inconclusive_reason(self):
        obj=self.physical_shape()
        obj["policy_files"]["/etc/dbus-1/system.d/fota-consumer.conf"]["sha256"]="0"*64
        out=policy.review_focused_report(obj)
        self.assertEqual(out["subset_uncertainty_reason_codes"],["PINNED_SOURCE_CHANGED_OR_UNVERIFIED"])
        self.assertEqual(out["observed_default_subset_result"],"INCONCLUSIVE")

    def test_unrelated_user_policy_scope_does_not_poison_default_subset(self):
        obj=self.physical_shape()
        fota=obj["policy_files"]["/etc/dbus-1/system.d/fota-consumer.conf"]["ordered_config_nodes"][0]
        fota["unrecognized_scope_names"]=["future_user_attribute"]
        out=policy.review_focused_report(obj)
        self.assertEqual(out["observed_default_subset_result"],"LATER_FOTA_INTERFACE_ALLOW_MATCHES")
        self.assertEqual(out["effective_dbus_send_permission_for_shell"],"UNDETERMINED")

    def test_unknown_default_scope_stays_inconclusive(self):
        obj=self.physical_shape()
        fota=obj["policy_files"]["/etc/dbus-1/system.d/fota-consumer.conf"]["ordered_config_nodes"][-1]
        fota["unrecognized_scope_names"]=["future_default_attribute"]
        out=policy.review_focused_report(obj)
        self.assertEqual(out["observed_default_subset_result"],"INCONCLUSIVE")
        self.assertIn("UNKNOWN_DEFAULT_SCOPE_ATTRIBUTE",out["subset_uncertainty_reason_codes"])

    def test_owner_shaped_json_offline_no_watch_and_private_output(self):
        with tempfile.TemporaryDirectory() as td:
            inp,out=Path(td)/"focused.json",Path(td)/"audit.json"
            inp.write_text(json.dumps(self.physical_shape()))
            with patch.object(policy.socket,"create_connection",side_effect=AssertionError("NO WATCH")):
                self.assertEqual(policy.main(["--offline-focused-report",str(inp),
                                              "--report",str(out)]),0)
            result=json.loads(out.read_text())
            self.assertEqual(result["observed_default_subset_result"],"LATER_FOTA_INTERFACE_ALLOW_MATCHES")
            self.assertFalse(result["matching_rule_subset_has_unknowns_or_drift"])
            self.assertFalse(result["watch_contacted"])
            self.assertEqual(out.stat().st_mode & 0o077,0)


RUNTIME_UNIT_SAMPLE = """Id=dbus.service
LoadState=loaded
ActiveState=active
SubState=running
MainPID=247
ExecStart={ path=/usr/bin/dbus-daemon ; argv[]=/usr/bin/dbus-daemon --system --nofork --config-file=/usr/share/dbus-1/system.conf ; ignore_errors=no ; start_time=[unknown] ; stop_time=[unknown] ; pid=247 ; code=(null) ; status=0/0 }
"""
RUNTIME_PS_SAMPLE = """PID USER VSZ STAT COMMAND
1 root 12345 S /usr/lib/systemd/systemd
247 messagebus 3456 S /usr/bin/dbus-daemon --system --nofork --config-file=/usr/share/dbus-1/system.conf
298 sh 500 S /bin/sh -c dbus-daemon --system --test
309 fota 500 S /usr/bin/fota-consumer
"""


class RunningBusProvenanceTests(unittest.TestCase):
    def test_runtime_operations_are_only_fixed_literals(self):
        from watch3_r08_android_sdb import ALLOWED_PROBES, DBUS_RUNTIME_PROBES
        self.assertEqual(policy.RUNTIME_ALLOWED_OPS,
                         frozenset(("dbus_runtime_unit","service_process_snapshot")))
        self.assertEqual(set(DBUS_RUNTIME_PROBES),{"dbus_runtime_unit"})
        self.assertIn("dbus.service",ALLOWED_PROBES["dbus_runtime_unit"])
        self.assertEqual(ALLOWED_PROBES["service_process_snapshot"],"ps")
        self.assertNotIn("restart",ALLOWED_PROBES["dbus_runtime_unit"])
        self.assertNotIn("LaunchFota",ALLOWED_PROBES["dbus_runtime_unit"])

    def test_read_only_unit_parse_redacts_command_and_pid(self):
        result=policy.parse_runtime_unit(RUNTIME_UNIT_SAMPLE)
        self.assertTrue(result["unit_active"])
        self.assertTrue(result["main_pid_present"])
        self.assertEqual(result["configured_daemon_family"],"DBUS_DAEMON")
        self.assertEqual(result["configured_explicit_config_class"],
                         "CAPTURED_CORE_SYSTEM_CONF")
        self.assertFalse(result["unit_is_runtime_process_attestation"])
        self.assertNotIn("247",json.dumps(result))
        self.assertNotIn("argv",json.dumps(result))

    def test_unit_inactive_or_other_config_is_not_runtime_proof(self):
        raw=RUNTIME_UNIT_SAMPLE.replace("ActiveState=active","ActiveState=inactive").replace(
            "MainPID=247","MainPID=0").replace(
            "/usr/share/dbus-1/system.conf","/custom/sensitive/location.conf")
        result=policy.parse_runtime_unit(raw)
        self.assertFalse(result["unit_active"])
        self.assertFalse(result["main_pid_present"])
        self.assertEqual(result["configured_explicit_config_class"],
                         "OTHER_EXPLICIT_CONFIG_REDACTED")
        self.assertNotIn("sensitive",json.dumps(result))

    def test_unit_alias_and_malformed_duplicate_property_rejected(self):
        raw=RUNTIME_UNIT_SAMPLE.replace("Id=dbus.service","Id=dbus-broker.service")
        self.assertEqual(policy.parse_runtime_unit(raw)["unit_id_class"],
                         "dbus-broker.service")
        with self.assertRaisesRegex(policy.PolicyError,"RUNTIME_UNIT_UNEXPECTED_ID"):
            policy.parse_runtime_unit(RUNTIME_UNIT_SAMPLE.replace(
                "Id=dbus.service","Id=secret.service"))
        with self.assertRaisesRegex(policy.PolicyError,"RUNTIME_UNIT_OUTPUT_INVALID"):
            policy.parse_runtime_unit(RUNTIME_UNIT_SAMPLE+"MainPID=999\n")

    def test_ps_uses_only_real_argv0_not_sh_arguments(self):
        result=policy.parse_runtime_ps(RUNTIME_PS_SAMPLE)
        self.assertEqual(result["status"],"PS_SNAPSHOT_PARSED")
        self.assertEqual(len(result["candidate_processes"]),1)
        self.assertEqual(result["candidate_processes"][0]["daemon_family"],"DBUS_DAEMON")
        self.assertTrue(result["candidate_processes"][0]["system_flag_observed"])
        self.assertEqual(result["candidate_processes"][0]["explicit_config_class"],
                         "CAPTURED_CORE_SYSTEM_CONF")
        self.assertNotIn("247",json.dumps(result))
        self.assertFalse(result["candidate_processes"][0]["process_is_system_bus_attested"])

    def test_unsupported_ps_layout_cannot_claim_active_bus(self):
        result=policy.parse_runtime_ps("USER PID PPID VSZ COMMAND\nroot 247 1 100 dbus-daemon\n")
        self.assertEqual(result["status"],"PS_LAYOUT_UNSUPPORTED")
        self.assertEqual(result["candidate_processes"],[])

    def test_processes_bounded_and_unrelated_args_not_saved(self):
        lines=["PID USER VSZ STAT COMMAND"]
        for i in range(10):
            lines.append(f"{200+i} root 1024 S dbus-daemon --system --private-flag=SECRET{i}")
        result=policy.parse_runtime_ps("\n".join(lines)+"\n")
        self.assertEqual(len(result["candidate_processes"]),4)
        self.assertTrue(result["truncated"])
        self.assertNotIn("SECRET",json.dumps(result))

    def test_unknown_or_missing_bus_never_claims_policy(self):
        with patch.object(policy,"runtime_bus_query",side_effect=policy.PolicyError(
                "RUNTIME_SDB_SHELL_UNAVAILABLE")):
            result=policy.collect_runtime_bus("10.115.12.131",Path("/unused"))
        self.assertFalse(result["complete_effective_dbus_policy_verified"])
        self.assertEqual(result["effective_dbus_send_permission_for_shell"],
                         "UNDETERMINED")
        self.assertFalse(result["fota_method_called"])
        self.assertFalse(result["watch_write_performed"])
        self.assertEqual(result["sources"]["dbus_runtime_unit"]["status"],
                         "RUNTIME_SDB_SHELL_UNAVAILABLE")

    def test_collector_queries_exactly_two_known_ops(self):
        observed=[]
        def query(ip,key,op):
            observed.append(op)
            return RUNTIME_UNIT_SAMPLE if op=="dbus_runtime_unit" else RUNTIME_PS_SAMPLE
        with patch.object(policy,"runtime_bus_query",side_effect=query):
            result=policy.collect_runtime_bus("10.115.12.131",Path("/unused"))
        self.assertEqual(observed,["dbus_runtime_unit","service_process_snapshot"])
        self.assertEqual(result["state"],"PARTIAL_READONLY_RUNTIME_PROVENANCE")
        self.assertFalse(result["running_daemon_arguments_independently_attested"])
        self.assertFalse(result["root_proven"])

    def test_reject_arbitrary_shell_operation_before_connecting(self):
        with patch.object(policy.socket,"create_connection",side_effect=AssertionError("NO NETWORK")):
            with self.assertRaisesRegex(policy.PolicyError,"RUNTIME_OPERATION_NOT_ALLOWLISTED"):
                policy.runtime_bus_query("10.115.12.131",Path("/unused"),"arbitrary_shell")

    def test_runtime_cli_creates_private_json_and_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/"runtime.json"
            with patch.object(policy,"collect_runtime_bus",return_value={
                    "state":"PARTIAL_READONLY_RUNTIME_PROVENANCE",
                    "watch_write_performed":False}),patch.object(
                    policy.socket,"create_connection",side_effect=AssertionError("NO NETWORK")):
                self.assertEqual(policy.main(["--runtime-ip","10.115.12.131",
                                               "--report",str(path)]),0)
                self.assertEqual(policy.main(["--runtime-ip","10.115.12.131",
                                               "--report",str(path)]),1)
            self.assertEqual(path.stat().st_mode & 0o077,0)
            self.assertEqual(json.loads(path.read_text())["watch_write_performed"],False)

    def test_runtime_and_offline_modes_exclusive(self):
        with self.assertRaises(SystemExit):
            policy.main(["--runtime-ip","10.115.12.131",
                         "--offline-focused-report","/unused/report.json"])

if __name__=="__main__":
    unittest.main()
