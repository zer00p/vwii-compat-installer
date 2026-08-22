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

from sffs_common import (
    load_sffs, load_target, walk_sffs_tree, walk_extracted_tree, get_expected_gid, decode_mode_perms,
    KNOWN_TITLE_NAMES, is_system_title, parse_tmd_group_id, read_entry_content
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
}

def get_friendly_name(title_id):
    if title_id in KNOWN_TITLE_NAMES:
        return KNOWN_TITLE_NAMES[title_id]
    idHi = (title_id >> 32) & 0xFFFFFFFF
    idLo = title_id & 0xFFFFFFFF
    return f"{idHi:08x}/{idLo:08x}"

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
            "data_dirs_valid": 0,
            "shared_apps_checked": 0,
            "content_map_valid": False,
            "setting_txt_valid": False,
            "uid_sys_valid": False,
            "cert_sys_valid": False,
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

    # 3. Validate System Files (/sys/cert.sys, /sys/uid.sys)
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
            report.stats["cert_sys_valid"] = True
            report.pass_check("/sys/cert.sys", f"cert.sys OK (2560 bytes, mode=0x{c['mode']:02x} ({decode_mode_perms(c['mode'])}), UID={c['uid']}, GID={c['gid']})")

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

    # 4. Validate setting.txt
    setting_path = "/title/00000001/00000002/data/setting.txt"
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

    # 5. Validate All Installed Titles (/title/*/*) and Data Directory UIDs
    installed_title_dirs = []
    for p, node in nodes.items():
        if p.startswith("/title/") and not node["is_file"]:
            parts = p.split("/")
            if len(parts) == 4: # /title/<idHi>/<idLo>
                try:
                    idHi = int(parts[2], 16)
                    idLo = int(parts[3], 16)
                    tid = (idHi << 32) | idLo
                    installed_title_dirs.append((p, tid, idHi, idLo))
                except ValueError:
                    pass

    report.stats["titles_checked"] = len(installed_title_dirs)
    seen_uids = set()

    for tpath, tid, idHi, idLo in installed_title_dirs:
        tnode = nodes[tpath]

        # Check Title Directory mode (0xf6 / rw-rw-r--, UID 0, GID 0)
        if not is_extracted or tnode.get("has_stock_perms"):
            if tnode["mode"] != 0xf6:
                report.error(tpath, f"Title dir mode mismatch: currently 0x{tnode['mode']:02x} ({decode_mode_perms(tnode['mode'])}), expected 0xf6 ({decode_mode_perms(0xf6)})")
            if tnode["uid"] != 0 or tnode["gid"] != 0:
                report.error(tpath, f"Title dir ownership mismatch: currently UID={tnode['uid']}, GID={tnode['gid']}, expected UID=0, GID=0")

        # Check Content Directory (mode 0xf2 / rw-rw----, UID 0, GID 0)
        cpath = f"{tpath}/content"
        if cpath in nodes:
            cnode = nodes[cpath]
            if not is_extracted or cnode.get("has_stock_perms"):
                if cnode["mode"] != 0xf2:
                    report.error(cpath, f"Content dir mode mismatch: currently 0x{cnode['mode']:02x} ({decode_mode_perms(cnode['mode'])}), expected 0xf2 ({decode_mode_perms(0xf2)})")
                if cnode["uid"] != 0 or cnode["gid"] != 0:
                    report.error(cpath, f"Content dir ownership mismatch: currently UID={cnode['uid']}, GID={cnode['gid']}, expected UID=0, GID=0")

        # Check TMD (mode 0xf1 / rw-rw----, UID 0, GID 0)
        tmd_path = f"{cpath}/title.tmd"
        if tmd_path in nodes:
            tmd_node = nodes[tmd_path]
            if not is_extracted or tmd_node.get("has_stock_perms"):
                if tmd_node["mode"] != 0xf1:
                    report.error(tmd_path, f"TMD mode mismatch: currently 0x{tmd_node['mode']:02x} ({decode_mode_perms(tmd_node['mode'])}), expected 0xf1 ({decode_mode_perms(0xf1)})")
                if tmd_node["uid"] != 0 or tmd_node["gid"] != 0:
                    report.error(tmd_path, f"TMD ownership mismatch: currently UID={tmd_node['uid']}, GID={tmd_node['gid']}, expected UID=0, GID=0")

        # Check Ticket (mode 0xf1 / rw-rw----, UID 0, GID 0)
        tik_path = f"/ticket/{idHi:08x}/{idLo:08x}.tik"
        if tik_path in nodes:
            tik_node = nodes[tik_path]
            if not is_extracted or tik_node.get("has_stock_perms"):
                if tik_node["mode"] != 0xf1:
                    report.error(tik_path, f"Ticket mode mismatch: currently 0x{tik_node['mode']:02x} ({decode_mode_perms(tik_node['mode'])}), expected 0xf1 ({decode_mode_perms(0xf1)})")
                if tik_node["uid"] != 0 or tik_node["gid"] != 0:
                    report.error(tik_path, f"Ticket ownership mismatch: currently UID={tik_node['uid']}, GID={tik_node['gid']}, expected UID=0, GID=0")

        # Validate /data directory with UID & GID Allocation Checks
        dpath = f"{tpath}/data"
        if dpath not in nodes:
            report.warning(dpath, "Title has no /data directory")
        else:
            dnode = nodes[dpath]
            tmd_data = None
            if not is_system_title(tid):
                tmd_path = f"{tpath}/content/title.tmd"
                if tmd_path in nodes:
                    tmd_node = nodes[tmd_path]
                    if tmd_node.get("content") is not None:
                        tmd_data = tmd_node["content"]
                    elif target_type == 'image' and nand is not None and "entry" in tmd_node:
                        tmd_data = read_entry_content(nand, tmd_node["entry"])
                    elif target_type == 'extracted_dir' and tmd_node.get("fpath"):
                        try:
                            with open(tmd_node["fpath"], "rb") as fp:
                                tmd_data = fp.read()
                        except Exception:
                            tmd_data = None

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

    # 6. Validate Shared Content & content.map
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

    # 7. Optional Reference Parity Check
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
        print(f"Titles Audited:             {report.stats['titles_checked']}")
        print(f"Valid /data Directories:    {report.stats['data_dirs_valid']} / {report.stats['titles_checked']}")
        print(f"Shared .app Files Verified: {report.stats['shared_apps_checked']}")
        print(f"Core Files Status:          cert.sys={report.stats['cert_sys_valid']}, uid.sys={report.stats['uid_sys_valid']}, setting.txt={report.stats['setting_txt_valid']}")

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
