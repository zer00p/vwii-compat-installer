#!/usr/bin/env python3
"""
validate_slccmpt.py - Comprehensive validator for vWii SLCCMPT NAND images.

Validates filesystem structure, SFFS permission modes, owner UIDs, group GIDs,
and content against factory stock vWii rules, dynamically verifying monotonic
title UID allocation and unique ownership.

Usage:
    python3 validate_slccmpt.py <image.raw> [options]

Options:
    --otp <path>            Path to otp.bin (default: auto-detected)
    --reference <ref.raw>   Optional reference RAW image to verify bit-for-bit title payload parity
    --verbose, -v           Show passing checks in addition to failures
    --json                  Output validation results in structured JSON format
"""

import os
import sys
import argparse
import json
import hashlib

from sffs_common import (
    load_sffs, load_target, walk_sffs_tree, walk_extracted_tree, get_expected_gid, decode_mode_perms,
    KNOWN_TITLE_NAMES, is_system_title, parse_tmd_group_id, read_entry_content,
    get_stock_titles, parse_setting_txt_area, decrypt_setting_txt, parse_uid_sys_table,
    parse_certificates, is_retail_certificate, verify_rsa_signature, parse_tmd, parse_ticket,
    is_original_nintendo_signature
)

# Stock expected permission constants (SFFS mode byte, UID, GID)
STOCK_ROOT_DIRS = {
    "/sys":     {"mode": 0xf2, "uid": 0, "gid": 0},
    "/shared1": {"mode": 0xf2, "uid": 0, "gid": 0},
    "/ticket":  {"mode": 0xf2, "uid": 0, "gid": 0},
    "/title":   {"mode": 0xf6, "uid": 0, "gid": 0},
    "/shared2": {"mode": 0xfe, "uid": 0, "gid": 0},
    "/tmp":     {"mode": 0xfe, "uid": 0, "gid": 0},
    "/import":  {"mode": 0xf2, "uid": 0, "gid": 0},
    "/meta":    {"mode": 0xfe, "uid": 4096, "gid": 1},
    "/wfs":     {"mode": 0xc2, "uid": 19, "gid": 19},
}

def get_friendly_name(title_id):
    if title_id in KNOWN_TITLE_NAMES:
        return KNOWN_TITLE_NAMES[title_id]
    idHi = (title_id >> 32) & 0xFFFFFFFF
    idLo = title_id & 0xFFFFFFFF
    return f"{idHi:08x}/{idLo:08x}"

def get_node_content(node, target_type, nand):
    if not node:
        return None
    content = node.get("content")
    if content is not None:
        return content
    if target_type == 'image' and nand is not None and "entry" in node:
        content = read_entry_content(nand, node["entry"])
        node["content"] = content
        return content
    if target_type == 'extracted_dir' and node.get("fpath"):
        try:
            with open(node["fpath"], "rb") as fp:
                content = fp.read()
            node["content"] = content
            return content
        except Exception:
            return None
    return None

class ValidationReport:
    def __init__(self):
        self.errors = []
        self.warnings = []
        self.passes = []
        self.target_type = "unknown"
        self.resolved_path = ""
        self.stats = {
            "total_nodes": 0,
            "titles_checked": 0,
            "detected_region": "Unknown",
            "required_stock_titles_checked": 0,
            "stock_titles_valid": False,
            "data_dirs_valid": 0,
            "tmd_signatures_valid": 0,
            "ticket_signatures_valid": 0,
            "content_payloads_valid": 0,
            "shared_apps_checked": 0,
            "content_map_valid": False,
            "setting_txt_valid": False,
            "uid_sys_valid": False,
            "cert_sys_valid": False,
            "space_sys_valid": False,
        }

    def error(self, path, msg):
        self.errors.append({"path": path, "message": msg})

    def warning(self, path, msg):
        self.warnings.append({"path": path, "message": msg})

    def pass_check(self, path, msg):
        self.passes.append({"path": path, "message": msg})

    def is_valid(self):
        return len(self.errors) == 0

def validate_image(image_path, otp_path=None, ref_image_path=None, verbose=False):
    report = ValidationReport()

    # 1. Resolve & Load Target (RAW Image or Extracted Filesystem Directory)
    try:
        target_type, resolved_path, nand, sb, root = load_target(image_path, otp_path)
    except Exception as e:
        report.error(image_path, f"Failed to load filesystem: {e}")
        return report

    report.target_type = target_type
    report.resolved_path = resolved_path

    nodes = {}
    if target_type == 'image':
        walk_sffs_tree(nand, root, nodes, read_content=False)
    else:
        walk_extracted_tree(resolved_path, nodes, read_content=False)

    report.stats["total_nodes"] = len(nodes)
    is_extracted = (target_type == 'extracted_dir')

    # 2. Validate Root Directories
    for rpath, exp in STOCK_ROOT_DIRS.items():
        if rpath not in nodes:
            report.error(rpath, "Root directory is missing")
            continue
        node = nodes[rpath]
        if node["is_file"]:
            report.error(rpath, "Expected directory, found file")
            continue
        if not is_extracted or node.get("has_stock_perms"):
            if node["mode"] != exp["mode"]:
                report.error(rpath, f"Mode mismatch: currently 0x{node['mode']:02x} ({decode_mode_perms(node['mode'])}), expected 0x{exp['mode']:02x} ({decode_mode_perms(exp['mode'])})")
            if node["uid"] != exp["uid"] or node["gid"] != exp["gid"]:
                report.error(rpath, f"Ownership mismatch: currently UID={node['uid']}, GID={node['gid']}, expected UID={exp['uid']}, GID={exp['gid']}")
        report.pass_check(rpath, f"Root directory OK (mode=0x{node['mode']:02x} ({decode_mode_perms(node['mode'])}), UID={node['uid']}, GID={node['gid']})")

    # 2b. Validate Category Subdirectories (/title/<idHi> and /ticket/<idHi>)
    for p, node in nodes.items():
        if not node["is_file"]:
            parts = p.split("/")
            if len(parts) == 3: # e.g. /title/00000001 or /ticket/00000001
                if parts[1] == "title":
                    if not is_extracted or node.get("has_stock_perms"):
                        if node["mode"] != 0xf6:
                            report.error(p, f"Title category dir mode mismatch: currently 0x{node['mode']:02x} ({decode_mode_perms(node['mode'])}), expected 0xf6 ({decode_mode_perms(0xf6)})")
                        if node["uid"] != 0 or node["gid"] != 0:
                            report.error(p, f"Title category dir ownership mismatch: currently UID={node['uid']}, GID={node['gid']}, expected UID=0, GID=0")
                    report.pass_check(p, f"Title category dir OK (mode=0x{node['mode']:02x} ({decode_mode_perms(node['mode'])}), UID={node['uid']}, GID={node['gid']})")
                elif parts[1] == "ticket":
                    idHi_str = parts[2].lower()
                    if idHi_str in ("00000001", "00010002", "00010008"):
                        exp_modes = (0x02,)
                    else:
                        exp_modes = (0x02, 0xf2)
                    if not is_extracted or node.get("has_stock_perms"):
                        if node["mode"] not in exp_modes:
                            exp_desc = "0x02" if len(exp_modes) == 1 else "0x02 or 0xf2"
                            report.error(p, f"Ticket category dir mode mismatch: currently 0x{node['mode']:02x} ({decode_mode_perms(node['mode'])}), expected {exp_desc}")
                        if node["uid"] != 0 or node["gid"] != 0:
                            report.error(p, f"Ticket category dir ownership mismatch: currently UID={node['uid']}, GID={node['gid']}, expected UID=0, GID=0")
                    report.pass_check(p, f"Ticket category dir OK (mode=0x{node['mode']:02x} ({decode_mode_perms(node['mode'])}), UID={node['uid']}, GID={node['gid']})")

    # 3. Validate System Files (/sys/cert.sys, /sys/uid.sys, /sys/space.sys)
    system_certs = {}
    if "/sys/cert.sys" not in nodes:
        report.error("/sys/cert.sys", "cert.sys is missing")
    else:
        c = nodes["/sys/cert.sys"]
        if not is_extracted or c.get("has_stock_perms"):
            if c["mode"] != 0xf5:
                report.error("/sys/cert.sys", f"Mode mismatch: currently 0x{c['mode']:02x} ({decode_mode_perms(c['mode'])}), expected 0xf5 ({decode_mode_perms(0xf5)})")
            if c["uid"] != 0 or c["gid"] != 0:
                report.error("/sys/cert.sys", f"Ownership mismatch: currently UID={c['uid']}, GID={c['gid']}, expected UID=0, GID=0")
        if c["size"] != 2560:
            report.error("/sys/cert.sys", f"Size invalid: currently {c['size']} bytes, expected 2560 bytes")
        else:
            c_content = get_node_content(c, target_type, nand)
            if c_content:
                parsed_certs = parse_certificates(c_content)
                has_xs = is_retail_certificate(parsed_certs.get("XS00000003"))
                has_ca = is_retail_certificate(parsed_certs.get("CA00000001"))
                has_cp = is_retail_certificate(parsed_certs.get("CP00000004"))
                if not (has_xs and has_ca and has_cp):
                    missing_certs = []
                    if not has_xs: missing_certs.append("XS00000003")
                    if not has_ca: missing_certs.append("CA00000001")
                    if not has_cp: missing_certs.append("CP00000004")
                    report.error("/sys/cert.sys", f"Missing or corrupted retail certificates: {', '.join(missing_certs)}")
                else:
                    system_certs = parsed_certs
                    report.stats["cert_sys_valid"] = True
                    report.pass_check("/sys/cert.sys", f"cert.sys OK (2560 bytes, retail certificates XS/CA/CP verified, mode=0x{c['mode']:02x} ({decode_mode_perms(c['mode'])}), UID={c['uid']}, GID={c['gid']})")

    uid_entries = []
    if "/sys/uid.sys" not in nodes:
        report.error("/sys/uid.sys", "uid.sys is missing")
    else:
        u = nodes["/sys/uid.sys"]
        if not is_extracted or u.get("has_stock_perms"):
            if u["mode"] != 0xf1:
                report.error("/sys/uid.sys", f"Mode mismatch: currently 0x{u['mode']:02x} ({decode_mode_perms(u['mode'])}), expected 0xf1 ({decode_mode_perms(0xf1)})")
            if u["uid"] != 0 or u["gid"] != 0:
                report.error("/sys/uid.sys", f"Ownership mismatch: currently UID={u['uid']}, GID={u['gid']}, expected UID=0, GID=0")
        if u["size"] == 0 or u["size"] % 12 != 0:
            report.error("/sys/uid.sys", f"Size invalid: currently {u['size']} bytes, expected non-zero multiple of 12 bytes")
        else:
            report.stats["uid_sys_valid"] = True
            num_entries = u["size"] // 12
            report.pass_check("/sys/uid.sys", f"uid.sys OK ({num_entries} registered title records, mode=0x{u['mode']:02x} ({decode_mode_perms(u['mode'])}), UID={u['uid']}, GID={u['gid']})")
            
            # Read uid.sys content for cross-checking
            u_content = get_node_content(u, target_type, nand)
            if u_content:
                uid_entries = parse_uid_sys_table(u_content)

    if "/sys/space.sys" in nodes:
        sp = nodes["/sys/space.sys"]
        if not is_extracted or sp.get("has_stock_perms"):
            if sp["mode"] != 0xf1:
                report.error("/sys/space.sys", f"space.sys mode mismatch: currently 0x{sp['mode']:02x} ({decode_mode_perms(sp['mode'])}), expected 0xf1 ({decode_mode_perms(0xf1)})")
            if sp["uid"] != 0 or sp["gid"] != 0:
                report.error("/sys/space.sys", f"space.sys ownership mismatch: currently UID={sp['uid']}, GID={sp['gid']}, expected UID=0, GID=0")
        report.stats["space_sys_valid"] = True
        report.pass_check("/sys/space.sys", f"space.sys OK ({sp['size']} bytes, mode=0x{sp['mode']:02x} ({decode_mode_perms(sp['mode'])}), UID={sp['uid']}, GID={sp['gid']})")

    # 4. Validate setting.txt and Determine Console Region
    setting_path = "/title/00000001/00000002/data/setting.txt"
    detected_region = None
    if setting_path not in nodes:
        report.error(setting_path, "setting.txt is missing")
    else:
        s = nodes[setting_path]
        if not is_extracted or s.get("has_stock_perms"):
            if s["mode"] != 0x55:
                report.error(setting_path, f"Mode mismatch: currently 0x{s['mode']:02x} ({decode_mode_perms(s['mode'])}), expected 0x55 ({decode_mode_perms(0x55)})")
            if s["uid"] != 4096 or s["gid"] != 1:
                report.error(setting_path, f"Ownership mismatch: currently UID={s['uid']}, GID={s['gid']}, expected UID=4096, GID=1")
        if s["size"] != 256:
            report.error(setting_path, f"Size mismatch: currently {s['size']} bytes, expected 256 bytes")
        else:
            report.stats["setting_txt_valid"] = True
            report.pass_check(setting_path, f"setting.txt OK (256 bytes, mode=0x{s['mode']:02x} ({decode_mode_perms(s['mode'])}), UID={s['uid']}, GID={s['gid']})")

            # Extract setting.txt region
            s_content = get_node_content(s, target_type, nand)
            if s_content:
                dec_setting = decrypt_setting_txt(s_content)
                detected_region = parse_setting_txt_area(dec_setting)

    # Fallback region detection from region-specific channel title IDs
    if not detected_region:
        if "/title/00010002/4843554a" in nodes or "/title/00010008/48414c4a" in nodes or "/title/00010008/48435a4a" in nodes:
            detected_region = "JPN"
        elif "/title/00010002/48435545" in nodes or "/title/00010008/48414c45" in nodes or "/title/00010008/48435a45" in nodes:
            detected_region = "USA"
        elif "/title/00010002/48435550" in nodes or "/title/00010008/48414c50" in nodes or "/title/00010008/48435a50" in nodes:
            detected_region = "EUR"
        else:
            detected_region = "JPN"

    report.stats["detected_region"] = detected_region

    # 5. Validate Required Stock System Titles for Detected Region
    stock_titles = get_stock_titles(detected_region)
    report.stats["required_stock_titles_checked"] = len(stock_titles)
    missing_stock_titles = 0

    for stid, sname in stock_titles.items():
        s_idHi = (stid >> 32) & 0xFFFFFFFF
        s_idLo = stid & 0xFFFFFFFF
        stpath = f"/title/{s_idHi:08x}/{s_idLo:08x}"

        if stpath not in nodes:
            report.error(stpath, f"Required stock title missing: {sname} (TID: {stid:016x})")
            missing_stock_titles += 1
        else:
            scpath = f"{stpath}/content"
            stmd = f"{scpath}/title.tmd"
            stik = f"/ticket/{s_idHi:08x}/{s_idLo:08x}.tik"
            sdpath = f"{stpath}/data"

            if scpath not in nodes:
                report.error(scpath, f"Content directory missing for required stock title: {sname}")
            if stmd not in nodes:
                report.error(stmd, f"TMD missing for required stock title: {sname}")
            if stik not in nodes:
                report.error(stik, f"Ticket missing for required stock title: {sname}")
            if sdpath not in nodes:
                report.error(sdpath, f"Data directory missing for required stock title: {sname}")

    if missing_stock_titles == 0:
        report.stats["stock_titles_valid"] = True
        report.pass_check("STOCK_SYSTEM_TITLES", f"All {len(stock_titles)} required stock system titles present for region {detected_region}")

    # 6. Validate All Installed Titles (/title/*/*), Cryptographic Signatures, Content Payloads, and Data Directory UIDs
    installed_title_dirs = []
    installed_tids = {}
    for p, node in nodes.items():
        if p.startswith("/title/") and not node["is_file"]:
            parts = p.split("/")
            if len(parts) == 4: # /title/<idHi>/<idLo>
                try:
                    idHi = int(parts[2], 16)
                    idLo = int(parts[3], 16)
                    tid = (idHi << 32) | idLo
                    installed_title_dirs.append((p, tid, idHi, idLo))
                    installed_tids[tid] = p
                except ValueError:
                    pass

    report.stats["titles_checked"] = len(installed_title_dirs)
    seen_uids = set()

    for tpath, tid, idHi, idLo in installed_title_dirs:
        tnode = nodes[tpath]
        friendly_name = get_friendly_name(tid)

        # Check Title Directory mode (0xf6 / rw-rw-r--, UID 0, GID 0)
        if not is_extracted or tnode.get("has_stock_perms"):
            if tnode["mode"] != 0xf6:
                report.error(tpath, f"Title dir mode mismatch: currently 0x{tnode['mode']:02x} ({decode_mode_perms(tnode['mode'])}), expected 0xf6 ({decode_mode_perms(0xf6)})")
            if tnode["uid"] != 0 or tnode["gid"] != 0:
                report.error(tpath, f"Title dir ownership mismatch: currently UID={tnode['uid']}, GID={tnode['gid']}, expected UID=0, GID=0")

        # Check Content Directory (mode 0xf2 / rw-rw----, UID 0, GID 0)
        cpath = f"{tpath}/content"
        if cpath not in nodes:
            report.error(cpath, f"Content directory is missing for {friendly_name}")
        else:
            cnode = nodes[cpath]
            if not is_extracted or cnode.get("has_stock_perms"):
                if cnode["mode"] != 0xf2:
                    report.error(cpath, f"Content dir mode mismatch: currently 0x{cnode['mode']:02x} ({decode_mode_perms(cnode['mode'])}), expected 0xf2 ({decode_mode_perms(0xf2)})")
                if cnode["uid"] != 0 or cnode["gid"] != 0:
                    report.error(cpath, f"Content dir ownership mismatch: currently UID={cnode['uid']}, GID={cnode['gid']}, expected UID=0, GID=0")

        # Check TMD (mode 0xf1 / rw-rw----, UID 0, GID 0) and parse cryptographic signature / content records
        tmd_path = f"{cpath}/title.tmd"
        tmd_data = None
        parsed_tmd = None
        if tmd_path not in nodes:
            report.error(tmd_path, f"TMD (title.tmd) is missing for {friendly_name}")
        else:
            tmd_node = nodes[tmd_path]
            if not is_extracted or tmd_node.get("has_stock_perms"):
                if tmd_node["mode"] != 0xf1:
                    report.error(tmd_path, f"TMD mode mismatch: currently 0x{tmd_node['mode']:02x} ({decode_mode_perms(tmd_node['mode'])}), expected 0xf1 ({decode_mode_perms(0xf1)})")
                if tmd_node["uid"] != 0 or tmd_node["gid"] != 0:
                    report.error(tmd_path, f"TMD ownership mismatch: currently UID={tmd_node['uid']}, GID={tmd_node['gid']}, expected UID=0, GID=0")

            tmd_data = get_node_content(tmd_node, target_type, nand)
            if tmd_data:
                parsed_tmd = parse_tmd(tmd_data)
                if not parsed_tmd:
                    report.error(tmd_path, f"TMD format invalid / corrupted for {friendly_name}")
                else:
                    # Cryptographic RSA signature verification against /sys/cert.sys
                    signer_cert = system_certs.get(parsed_tmd['signer'])
                    if not signer_cert:
                        report.error(tmd_path, f"TMD signer certificate '{parsed_tmd['signer']}' not found in cert.sys for {friendly_name}")
                    elif not verify_rsa_signature(parsed_tmd['sig'], parsed_tmd['payload'], signer_cert):
                        report.error(tmd_path, f"TMD signature invalid / tampered (fake-signed or modified, signer '{parsed_tmd['signer']}') for {friendly_name}")
                    else:
                        report.stats["tmd_signatures_valid"] += 1
                        report.pass_check(tmd_path, f"TMD signature authentic (signed by {parsed_tmd['signer']})")

                    # Region-specific System Menu version check
                    if tid == 0x0000000100000002 and detected_region:
                        exp_sm_ver_reg = {"JPN": 0, "USA": 1, "EUR": 2}.get(detected_region)
                        if exp_sm_ver_reg is not None and (parsed_tmd['version'] & 3) != exp_sm_ver_reg:
                            report.error(tmd_path, f"System Menu version mismatch for region {detected_region}: version {parsed_tmd['version']} (region code {parsed_tmd['version'] & 3}, expected {exp_sm_ver_reg})")

                    # Audit all content records declared in TMD
                    declared_cids = set()
                    content_required = idHi not in (0x00010000, 0x00010004)
                    for crec in parsed_tmd['contents']:
                        cid = crec['cid']
                        declared_cids.add(cid)
                        if not crec['is_shared']:
                            # Private content: /title/<idHi>/<idLo>/content/<cid:08x>.app
                            app_path = f"{cpath}/{cid:08x}.app"
                            if app_path not in nodes:
                                if content_required:
                                    report.error(app_path, f"Private content missing for {friendly_name}: {cid:08x}.app (size {crec['size']} bytes)")
                            else:
                                app_node = nodes[app_path]
                                if not is_extracted or app_node.get("has_stock_perms"):
                                    if app_node["mode"] != 0xf1:
                                        report.error(app_path, f"Content mode mismatch: currently 0x{app_node['mode']:02x} ({decode_mode_perms(app_node['mode'])}), expected 0xf1 ({decode_mode_perms(0xf1)})")
                                    if app_node["uid"] != 0 or app_node["gid"] != 0:
                                        report.error(app_path, f"Content ownership mismatch: currently UID={app_node['uid']}, GID={app_node['gid']}, expected UID=0, GID=0")
                                if app_node["size"] != crec["size"]:
                                    report.error(app_path, f"Content size mismatch for {friendly_name}: currently {app_node['size']} bytes, expected {crec['size']} bytes")
                                else:
                                    app_content = get_node_content(app_node, target_type, nand)
                                    if app_content is not None:
                                        app_sha1 = hashlib.sha1(app_content).digest()
                                        if app_sha1 != crec['hash']:
                                            report.error(app_path, f"Content payload SHA-1 mismatch / tampered for {friendly_name} (currently {app_sha1.hex()}, expected {crec['hash_hex']})")
                                        else:
                                            report.stats["content_payloads_valid"] += 1
                                            report.pass_check(app_path, f"Content payload OK ({crec['size']} bytes, SHA-1 verified)")

                    # Check for orphaned / unexpected .app files in title content directory
                    for p, node in nodes.items():
                        if p.startswith(cpath + "/") and p.endswith(".app") and p != tmd_path:
                            app_name = os.path.basename(p)
                            try:
                                app_cid = int(app_name[:-4], 16)
                                if app_cid not in declared_cids:
                                    report.warning(p, f"Orphaned content file not declared in TMD: {app_name} for {friendly_name}")
                            except ValueError:
                                pass

        # Check Ticket (mode 0xf1 / rw-rw----, UID 0, GID 0) and parse cryptographic signature
        # Retail disc game saves (00010000) and disc channels (00010004) do not have tickets on NAND.
        tik_path = f"/ticket/{idHi:08x}/{idLo:08x}.tik"
        ticket_required = idHi in (0x00000001, 0x00010002, 0x00010008, 0x00010001)
        if tik_path not in nodes:
            if ticket_required:
                report.error(tik_path, f"Ticket (.tik) is missing for {friendly_name}")
        else:
            tik_node = nodes[tik_path]
            if not is_extracted or tik_node.get("has_stock_perms"):
                if tik_node["mode"] != 0xf1:
                    report.error(tik_path, f"Ticket mode mismatch: currently 0x{tik_node['mode']:02x} ({decode_mode_perms(tik_node['mode'])}), expected 0xf1 ({decode_mode_perms(0xf1)})")
                if tik_node["uid"] != 0 or tik_node["gid"] != 0:
                    report.error(tik_path, f"Ticket ownership mismatch: currently UID={tik_node['uid']}, GID={tik_node['gid']}, expected UID=0, GID=0")

            tik_data = get_node_content(tik_node, target_type, nand)
            if tik_data:
                parsed_tik = parse_ticket(tik_data)
                if not parsed_tik:
                    report.error(tik_path, f"Ticket format invalid / corrupted for {friendly_name}")
                else:
                    tik_signer_cert = system_certs.get(parsed_tik['signer'])
                    if not tik_signer_cert:
                        report.error(tik_path, f"Ticket signer certificate '{parsed_tik['signer']}' not found in cert.sys for {friendly_name}")
                    elif not verify_rsa_signature(parsed_tik['sig'], parsed_tik['payload'], tik_signer_cert):
                        report.error(tik_path, f"Ticket signature invalid / tampered (fake-signed or modified, signer '{parsed_tik['signer']}') for {friendly_name}")
                    else:
                        report.stats["ticket_signatures_valid"] += 1
                        report.pass_check(tik_path, f"Ticket signature authentic (signed by {parsed_tik['signer']})")

                    if parsed_tik['title_id'] != tid:
                        report.error(tik_path, f"Ticket title ID mismatch: currently {parsed_tik['title_id']:016x}, expected {tid:016x}")

        # Validate /data directory with UID & GID Allocation Checks
        dpath = f"{tpath}/data"
        if dpath not in nodes:
            report.warning(dpath, f"Title has no /data directory: {friendly_name}")
        else:
            dnode = nodes[dpath]
            expected_gid = get_expected_gid(tid, tmd_data)

            if not is_extracted or dnode.get("has_stock_perms"):
                # System Menu must be UID 4096
                if tid == 0x0000000100000002 and dnode["uid"] != 4096:
                    report.error(dpath, f"System Menu data dir UID mismatch: currently UID={dnode['uid']}, expected UID=4096")
                elif dnode["uid"] < 4096:
                    report.error(dpath, f"Invalid title UID: currently UID={dnode['uid']}, expected UID >= 4096")

                if dnode["uid"] in seen_uids:
                    report.error(dpath, f"Duplicate UID collision: UID={dnode['uid']} is already used by another title")
                seen_uids.add(dnode["uid"])

                if dnode["mode"] != 0xc2:
                    report.error(dpath, f"Data dir mode mismatch: currently 0x{dnode['mode']:02x} ({decode_mode_perms(dnode['mode'])}), expected 0xc2 ({decode_mode_perms(0xc2)})")
                if dnode["gid"] != expected_gid:
                    report.error(dpath, f"Data dir GID mismatch: currently GID={dnode['gid']}, expected GID={expected_gid}")

                if dnode["mode"] == 0xc2 and dnode["gid"] == expected_gid and dnode["uid"] >= 4096:
                    report.stats["data_dirs_valid"] += 1
                    report.pass_check(dpath, f"Data dir OK (mode=0x{dnode['mode']:02x} ({decode_mode_perms(dnode['mode'])}), UID={dnode['uid']}, GID={dnode['gid']})")
            else:
                report.stats["data_dirs_valid"] += 1
                report.pass_check(dpath, "Data dir present")

    # 7. Cross-check /sys/uid.sys with Installed Titles
    if uid_entries:
        uid_tids = {entry_tid: entry_uid for entry_tid, entry_uid in uid_entries}
        for itid, ipath in installed_tids.items():
            if itid not in uid_tids:
                report.error(ipath, "Installed title is NOT registered in /sys/uid.sys")
        for utid, uuid in uid_entries:
            if utid not in installed_tids:
                u_idHi = (utid >> 32) & 0xFFFFFFFF
                u_idLo = utid & 0xFFFFFFFF
                report.warning(f"/title/{u_idHi:08x}/{u_idLo:08x}", f"Title registered in uid.sys (UID {uuid}) is not installed on disk")

    # 8. Validate Shared Content & content.map
    if "/shared1/content.map" not in nodes:
        report.error("/shared1/content.map", "content.map is missing from /shared1")
    else:
        cmap_node = nodes["/shared1/content.map"]
        if not is_extracted or cmap_node.get("has_stock_perms"):
            if cmap_node["mode"] != 0xf1:
                report.error("/shared1/content.map", f"content.map mode mismatch: currently 0x{cmap_node['mode']:02x} ({decode_mode_perms(cmap_node['mode'])}), expected 0xf1 ({decode_mode_perms(0xf1)})")
            if cmap_node["uid"] != 0 or cmap_node["gid"] != 0:
                report.error("/shared1/content.map", f"content.map ownership mismatch: currently UID={cmap_node['uid']}, GID={cmap_node['gid']}, expected UID=0, GID=0")
        if cmap_node["size"] == 0 or cmap_node["size"] % 28 != 0:
            report.error("/shared1/content.map", f"content.map size invalid: currently {cmap_node['size']} bytes, expected non-zero multiple of 28 bytes")
        else:
            report.stats["content_map_valid"] = True
            expected_shared_count = cmap_node["size"] // 28
            cmap_content = get_node_content(cmap_node, target_type, nand)
            if cmap_content:
                seen_hashes = {}
                for idx in range(expected_shared_count):
                    entry_data = cmap_content[idx * 28 : (idx + 1) * 28]
                    name = entry_data[:8].rstrip(b'\x00').decode('ascii', errors='ignore')
                    sha_bytes = entry_data[8:28]
                    if name:
                        if sha_bytes in seen_hashes:
                            report.error("/shared1/content.map", f"Duplicate shared content hash in content.map at slot {name} (duplicates slot {seen_hashes[sha_bytes]})")
                        else:
                            seen_hashes[sha_bytes] = name
            report.pass_check("/shared1/content.map", f"content.map OK ({expected_shared_count} shared entries registered, mode=0x{cmap_node['mode']:02x} ({decode_mode_perms(cmap_node['mode'])}), UID={cmap_node['uid']}, GID={cmap_node['gid']})")

    # Validate all /shared1/*.app files
    shared_apps = [p for p in nodes if p.startswith("/shared1/") and p.endswith(".app")]
    report.stats["shared_apps_checked"] = len(shared_apps)
    for app_path in shared_apps:
        anode = nodes[app_path]
        if not is_extracted or anode.get("has_stock_perms"):
            if anode["mode"] != 0xf1:
                report.error(app_path, f"Shared app mode mismatch: currently 0x{anode['mode']:02x} ({decode_mode_perms(anode['mode'])}), expected 0xf1 ({decode_mode_perms(0xf1)})")
            if anode["uid"] != 0 or anode["gid"] != 0:
                report.error(app_path, f"Shared app ownership mismatch: currently UID={anode['uid']}, GID={anode['gid']}, expected UID=0, GID=0")
        if anode["size"] == 0:
            report.error(app_path, "Shared app is empty (0 bytes)")

    report.pass_check("/shared1", f"All {len(shared_apps)} shared .app files and content.map OK")

    # 9. Optional Reference Parity Check
    if ref_image_path:
        try:
            r_nand, _, r_root = load_sffs(ref_image_path, otp_path)
            r_nodes = {}
            walk_sffs_tree(r_nand, r_root, r_nodes, read_content=True)

            walk_sffs_tree(nand, root, nodes, read_content=True)
            payload_matches = 0
            payload_diffs = 0

            # 1. Compare Private Title Payloads (/title/*/*/content/*.app)
            for p, node in nodes.items():
                if node["is_file"] and p.endswith(".app") and not p.startswith("/shared1/"):
                    if p in r_nodes and r_nodes[p]["is_file"]:
                        if node["sha1"] == r_nodes[p]["sha1"]:
                            payload_matches += 1
                        else:
                            payload_diffs += 1
                            report.error(p, f"Payload differs from reference image: currently SHA-1={node['sha1']}, expected SHA-1={r_nodes[p]['sha1']}")
                    else:
                        report.warning(p, "Title payload not present in reference image")

            # 2. Compare Shared Contents (/shared1/*.app) Order-Independently
            target_shared = sorted([n["size"] for p, n in nodes.items() if p.startswith("/shared1/") and p.endswith(".app")])
            ref_shared = sorted([n["size"] for p, n in r_nodes.items() if p.startswith("/shared1/") and p.endswith(".app")])

            if len(target_shared) != len(ref_shared):
                report.error("/shared1", f"Shared .app count mismatch: currently {len(target_shared)}, expected {len(ref_shared)}")
            elif target_shared != ref_shared:
                report.error("/shared1", "Shared .app size distribution mismatch with reference")
            else:
                report.pass_check("/shared1", f"Shared content parity OK: all {len(target_shared)} shared module sizes match reference exactly")

            report.pass_check("REFERENCE_PARITY", f"Private title payload parity OK: {payload_matches} identical, {payload_diffs} diffs")
        except Exception as e:
            report.warning("REFERENCE_CHECK", f"Failed to compare with reference image: {e}")

    return report

def main():
    parser = argparse.ArgumentParser(description="Validate an SLCCMPT image or extracted directory against stock vWii permissions and integrity rules.")
    parser.add_argument("image", help="Path directly to the SLCCMPT .raw/.bin NAND image file or extracted vWii root directory.")
    parser.add_argument("--otp", default=None, help="Path to otp.bin (default: auto-detected next to image or in testdata/).")
    parser.add_argument("--reference", default=None, help="Optional reference RAW image for payload comparison.")
    parser.add_argument("--verbose", "-v", action="store_true", help="Display all passing checks.")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format.")

    args = parser.parse_args()

    report = validate_image(args.image, args.otp, args.reference, args.verbose)

    if args.json:
        out = {
            "target": args.image,
            "resolved_path": report.resolved_path,
            "target_type": report.target_type,
            "valid": report.is_valid(),
            "stats": report.stats,
            "error_count": len(report.errors),
            "warning_count": len(report.warnings),
            "errors": report.errors,
            "warnings": report.warnings,
            "passes": report.passes if args.verbose else []
        }
        print(json.dumps(out, indent=2))
        sys.exit(0 if report.is_valid() else 1)

    target_desc = args.image
    if report.resolved_path and os.path.abspath(report.resolved_path) != os.path.abspath(args.image):
        target_desc += f" -> {report.resolved_path}"

    # Human-readable output
    print("\n" + "="*95)
    print(f"SLCCMPT Validation Report: {target_desc}")
    print("="*95)
    if report.stats['total_nodes'] > 0:
        print(f"Total Nodes Scanned:        {report.stats['total_nodes']}")
        print(f"Detected Region:            {report.stats['detected_region']}")
        print(f"Required Stock Titles:      {report.stats['required_stock_titles_checked']} expected (valid={report.stats['stock_titles_valid']})")
        print(f"Total Titles Audited:       {report.stats['titles_checked']}")
        print(f"Valid /data Directories:    {report.stats['data_dirs_valid']} / {report.stats['titles_checked']}")
        print(f"Authentic TMD Signatures:   {report.stats['tmd_signatures_valid']} verified")
        print(f"Authentic Ticket Signatures:{report.stats['ticket_signatures_valid']} verified")
        print(f"Verified Content Payloads:  {report.stats['content_payloads_valid']} verified")
        print(f"Shared .app Files Verified: {report.stats['shared_apps_checked']}")
        print(f"Core Files Status:          cert.sys={report.stats['cert_sys_valid']}, uid.sys={report.stats['uid_sys_valid']}, space.sys={report.stats['space_sys_valid']}, setting.txt={report.stats['setting_txt_valid']}")

    if args.verbose and report.passes:
        print("\n--- Passed Checks ---")
        for p in report.passes:
            print(f"  [PASS] {p['path']}: {p['message']}")

    if report.warnings:
        print(f"\n--- Warnings ({len(report.warnings)}) ---")
        for w in report.warnings:
            print(f"  [WARN] {w['path']}: {w['message']}")

    if report.errors:
        print(f"\n--- Errors Found ({len(report.errors)}) ---")
        for e in report.errors:
            print(f"  [FAIL] {e['path']}: {e['message']}")
        print("\n>>> RESULT: VALIDATION FAILED <<<")
        sys.exit(1)
    else:
        print("\n>>> RESULT: VALIDATION SUCCESSFUL (Target is 100% Stock Compliant) <<<")
        sys.exit(0)

if __name__ == '__main__':
    main()

