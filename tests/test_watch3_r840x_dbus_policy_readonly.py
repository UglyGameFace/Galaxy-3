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

if __name__=="__main__":
    unittest.main()
