#!/usr/bin/env python3
"""Review exact owned R840X /bin/bapd D-Bus call instructions OFFLINE.

No network, SDB, Samsung executable execution, service call or watch write.
Only this exact original ELF (pinned SHA-256/size) inherits the conclusions.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import sys

PIN = "429d9611c47b2cebc8918294f076ce013c1947f74441b374b306e29d300b67ea"
SIZE = 103356


class ReviewError(ValueError):
    pass


def u32(data, offset):
    if not 0 <= offset <= len(data) - 4:
        raise ReviewError("INVALID_READ_OFFSET")
    return struct.unpack_from("<I", data, offset)[0]


def u16(data, offset):
    if not 0 <= offset <= len(data) - 2:
        raise ReviewError("INVALID_READ_OFFSET")
    return struct.unpack_from("<H", data, offset)[0]


def arm_imm(value):
    shift = ((value >> 8) & 15) * 2
    byte = value & 255
    return ((byte >> shift) | (byte << ((32 - shift) & 31))) & 0xffffffff


def thumb_blx(data, addr):
    first, second = u16(data, addr), u16(data, addr + 2)
    if first & 0xf800 != 0xf000 or second & 0xd001 != 0xc000:
        raise ReviewError("NOT_THUMB_BLX_IMMEDIATE")
    sign = (first >> 10) & 1
    i1 = 1 ^ (((second >> 13) & 1) ^ sign)
    i2 = 1 ^ (((second >> 11) & 1) ^ sign)
    disp = ((sign << 24) | (i1 << 23) | (i2 << 22) |
            ((first & 0x3ff) << 12) | ((second & 0x7ff) << 1))
    if disp & (1 << 24):
        disp -= 1 << 25
    return (((addr + 4) & ~3) + disp) & 0xffffffff


def elf_sections(data):
    if data[:7] != b"\x7fELF\x01\x01\x01" or u32(data, 20) != 1 or u16(data, 18) != 40:
        raise ReviewError("INVALID_ARM_ELF32")
    offset, entry, count, names_i = u32(data, 32), u16(data, 46), u16(data, 48), u16(data, 50)
    if entry != 40 or not 5 <= count <= 100 or names_i >= count or offset + count * 40 > len(data):
        raise ReviewError("INVALID_SECTION_TABLE")
    records = [struct.unpack_from("<10I", data, offset + 40*i) for i in range(count)]
    names_rec = records[names_i]
    if names_rec[4] + names_rec[5] > len(data):
        raise ReviewError("INVALID_SECTION_NAMES")
    names = data[names_rec[4]:names_rec[4]+names_rec[5]]
    sections = {}
    for rec in records:
        if rec[0] >= len(names):
            raise ReviewError("INVALID_SECTION_NAME")
        end = names.find(b"\0", rec[0])
        if end < 0:
            raise ReviewError("INVALID_SECTION_NAME")
        name = names[rec[0]:end].decode("ascii")
        if name in sections or rec[1] != 8 and rec[4] + rec[5] > len(data):
            raise ReviewError("INVALID_SECTION_BOUNDS")
        sections[name] = (rec[3], rec[4], rec[5], rec[9])
    if not all(name in sections for name in (".plt", ".text", ".rodata", ".dynsym", ".dynstr", ".rel.plt")):
        raise ReviewError("REQUIRED_ELF_SECTION_MISSING")
    return sections


def offset(sections, addr, length):
    for name in (".plt", ".text", ".rodata", ".dynsym", ".dynstr", ".rel.plt"):
        if name not in sections:
            continue
        base, file_off, size, _ = sections[name]
        if base <= addr <= base+size and length <= base+size-addr:
            return file_off+addr-base
    raise ReviewError("ADDRESS_OUTSIDE_REVIEWED_SECTIONS")


def plt_import(data, sections, addr):
    start = offset(sections, addr, 12)
    a, b, c = (u32(data, start+i) for i in (0, 4, 8))
    if a & 0xfffff000 != 0xe28fc000 or b & 0xfffff000 != 0xe28cc000 or c & 0xfffff000 != 0xe5bcf000:
        raise ReviewError("UNRECOGNIZED_ARM_PLT")
    got = (addr+8+arm_imm(a)+arm_imm(b)+(c & 4095)) & 0xffffffff
    _, sym_start, sym_size, sym_ent = sections[".dynsym"]
    _, str_start, str_size, _ = sections[".dynstr"]
    _, rel_start, rel_size, rel_ent = sections[".rel.plt"]
    if sym_ent != 16 or rel_ent != 8:
        raise ReviewError("INVALID_DYNAMIC_ENTRY_SIZE")
    for i in range(0, rel_size, 8):
        slot, info = struct.unpack_from("<II", data, rel_start+i)
        if slot != got:
            continue
        if info & 255 != 22 or info >> 8 >= sym_size // 16:
            raise ReviewError("INVALID_ARM_JUMP_SLOT")
        name_offset = u32(data, sym_start+(info >> 8)*16)
        if name_offset >= str_size:
            raise ReviewError("INVALID_IMPORT_NAME")
        end = data.find(b"\0", str_start+name_offset, str_start+str_size)
        if end < 0:
            raise ReviewError("INVALID_IMPORT_NAME")
        return data[str_start+name_offset:end].decode("ascii"), got
    raise ReviewError("UNRESOLVED_PLT_IMPORT")


def literal(data, sections, load, add, pool, dest, string):
    insn = u16(data, offset(sections, load, 2))
    reg = (insn >> 8) & 7
    if insn & 0xf800 != 0x4800 or u16(data, offset(sections, add, 2)) != (0x4478 | reg):
        raise ReviewError("LITERAL_INSTRUCTION_INVALID")
    if ((load+4) & ~3) + (insn & 255)*4 != pool:
        raise ReviewError("LITERAL_POOL_INVALID")
    if (u32(data, offset(sections, pool, 4))+add+4) & 0xffffffff != dest:
        raise ReviewError("LITERAL_ADDRESS_INVALID")
    raw = string.encode("ascii")+b"\0"
    start = offset(sections, dest, len(raw))
    if data[start:start+len(raw)] != raw:
        raise ReviewError("LITERAL_TEXT_INVALID")
    return {"load": hex(load), "string_address": hex(dest), "text": string}



def callback_registration(data, sections):
    """Prove original event->handler pointer and conditional FOTA call site.

    This is a static registration/control-flow edge, not a bus policy grant
    or evidence that this event is reachable from an untrusted SDB shell.
    """
    def read(addr, length):
        start = offset(sections, addr, length)
        return data[start:start + length]

    if (read(0xac6c, 2) != bytes.fromhex("08b5") or
            read(0xac72, 10) != bytes.fromhex("0023034a04497a447944")):
        raise ReviewError("EVENT_REGISTRATION_INSTRUCTIONS_INVALID")
    # Direct Thumb BL to the exported bo_add_callback function.
    first, second = u16(data, offset(sections, 0xac7c, 4)), u16(data, offset(sections, 0xac7e, 2))
    if first & 0xf800 != 0xf000 or second & 0xd000 != 0xd000:
        raise ReviewError("EVENT_REGISTRATION_CALL_INVALID")
    sign = (first >> 10) & 1
    i1 = 1 ^ (((second >> 13) & 1) ^ sign)
    i2 = 1 ^ (((second >> 11) & 1) ^ sign)
    displacement = ((sign << 24) | (i1 << 23) | (i2 << 22) |
                    ((first & 0x3ff) << 12) | ((second & 0x7ff) << 1))
    if displacement & (1 << 24):
        displacement -= 1 << 25
    target = (0xac7c + 4 + displacement) & 0xffffffff
    if target != 0x4e10 or read(target, 2) != bytes.fromhex("2de9"):
        raise ReviewError("EVENT_CALLBACK_REGISTRY_TARGET_INVALID")

    handler = (u32(data, offset(sections, 0xac84, 4)) + 0xac78 + 4) & 0xffffffff
    event = (u32(data, offset(sections, 0xac88, 4)) + 0xac7a + 4) & 0xffffffff
    if handler != 0xaad1 or event != 0x12134:
        raise ReviewError("EVENT_HANDLER_OR_NAME_POINTER_INVALID")
    if read(event, len(b"dbus-connected\0")) != b"dbus-connected\0":
        raise ReviewError("EVENT_NAME_MISMATCH")
    if read(0xaad0, 4) != bytes.fromhex("2de9f041"):
        raise ReviewError("EVENT_CALLBACK_ENTRY_INVALID")

    # LDR global flag, CMP r4,#0, BNE returns before constructing FOTA request.
    if (read(0xaafc, 2) != bytes.fromhex("1c68") or
            read(0xaafe, 4) != bytes.fromhex("002c38d1") or
            read(0xab74, 8) != bytes.fromhex("012008b0bde8f081")):
        raise ReviewError("EVENT_CALLBACK_GUARD_INVALID")
    branch = u16(data, offset(sections, 0xab00, 2))
    distance = branch & 0xff
    if distance & 0x80:
        distance -= 0x100
    if (branch & 0xff00) != 0xd100 or 0xab00 + 4 + distance*2 != 0xab74:
        raise ReviewError("EVENT_CALLBACK_GUARD_TARGET_INVALID")
    # Exact original FOTA request was already proven at 0xab58; it falls
    # between the conditional branch and the skip-to-return target.
    if not (0xab00 < 0xab58 < 0xab74):
        raise ReviewError("EVENT_CALLBACK_CALL_OUTSIDE_GUARD")
    return {
        "registered_event": "dbus-connected",
        "registration_site": "0xac7c",
        "registration_function": "bo_add_callback",
        "callback_thumb_pointer": hex(handler),
        "callback_code_entry": "0xaad0",
        "request_callsite": "0xab58",
        "conditional_skip": "nonzero local state skips request",
        "guard_branch_site": "0xab00",
        "guard_return_target": "0xab74",
        "runtime_event_reachability_proven": False,
        "dbus_sender_authorization_proven": False,
        "consumer_authorization_proven": False
    }


def analyze(data):
    if len(data) != SIZE or hashlib.sha256(data).hexdigest() != PIN:
        raise ReviewError("PINNED_ORIGINAL_REQUIRED")
    sections = elf_sections(data)
    def call(site, symbol):
        kind = thumb_blx(data, offset(sections, site, 4))
        import_name, got = plt_import(data, sections, kind)
        if import_name != symbol:
            raise ReviewError("CALL_RELOCATION_MISMATCH")
        return {"site":hex(site), "plt":hex(kind), "got":hex(got), "symbol":symbol}
    refs = [
        literal(data, sections, 0xab26, 0xab28, 0xab94, 0x14538, "(is)"),
        literal(data, sections, 0xab0a, 0xab18, 0xab8c, 0x14540, "fota.consumer"),
        literal(data, sections, 0xab16, 0xab1a, 0xab90, 0x14550, "/fota/consumer"),
    ]
    # Thumb-2 LDR.W r12,[pc,#0x68], ADD r12,pc, then store as stack arg.
    if (data[offset(sections,0xab30,4):offset(sections,0xab30,4)+4] != bytes.fromhex("dff868c0")
            or u16(data,offset(sections,0xab3a,2)) != 0x44fc
            or (u32(data,offset(sections,0xab9c,4))+0xab3a+4) & 0xffffffff != 0x14560
            or data[offset(sections,0x14560,11):offset(sections,0x14560,11)+11] != b"LaunchFota\0"):
        raise ReviewError("METHOD_LITERAL_INVALID")
    for addr, instructions in ((0xab34,"2b46"), (0xab40,"2946"),
                               (0xab48,"3a46"),(0xab4a,"cdf800c0")):
        raw = bytes.fromhex(instructions)
        if data[offset(sections,addr,len(raw)):offset(sections,addr,len(raw))+len(raw)] != raw:
            raise ReviewError("DBUS_ARGUMENT_REGISTERS_INVALID")
    refs.append({"load":"0xab30","string_address":"0x14560","text":"LaunchFota"})
    return {
        "status":"PINNED_OFFLINE_BAPD_CALLSITE_VERIFIED",
        "original_sha256": PIN,
        "calls": [call(0xab2a, "g_variant_new"),
                  call(0xab58, "g_dbus_connection_call")],
        "arguments":refs,
        "callback_registration": callback_registration(data, sections),
        "service":"fota.consumer", "object_path":"/fota/consumer",
        "interface":"fota.consumer", "method":"LaunchFota", "variant_format":"(is)",
        "device_connected":False, "vendor_binary_executed":False,
        "caller_authorized":False, "fota_invoked":False, "root_proven":False,
        "signature_bypass_proven":False,"bootloader_unlocked":False,"stock_restore_proven":False,
        "scope_note":"One original FOTA callsite, callback registration and guard; neither event reachability nor authorization policy is proven"
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input",type=Path,required=True)
    parser.add_argument("--report",type=Path,required=True)
    args=parser.parse_args(argv)
    try:
        if args.input.stat().st_size != SIZE:
            raise ReviewError("PINNED_ORIGINAL_REQUIRED")
        result=analyze(args.input.read_bytes())
        report=args.report.expanduser()
        if not report.parent.is_dir():
            raise ReviewError("REPORT_PARENT_MISSING")
        fd=os.open(report,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        try:
            with os.fdopen(fd,"w") as f:
                json.dump(result,f,indent=2)
                f.write("\n")
                f.flush()
                os.fsync(f.fileno())
        except BaseException:
            report.unlink(missing_ok=True)
            raise
    except (ReviewError,OSError,ValueError,UnicodeError) as e:
        print("OFFLINE_BAPD_ERROR: "+(str(e) if isinstance(e,ReviewError) else "INVALID_PRIVATE_INPUT"),file=sys.stderr)
        return 1
    print("PINNED_OFFLINE_BAPD_CALLSITE_VERIFIED")
    print("No Samsung executable, D-Bus action, watch connection or firmware write.")
    return 0


if __name__=="__main__":
    raise SystemExit(main())
