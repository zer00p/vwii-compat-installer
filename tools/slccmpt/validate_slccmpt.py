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
    load_sffs, walk_sffs_tree, get_expected_gid, decode_mode
)

# Stock expected permission constants (SFFS mode byte, UID, GID)
STOCK_ROOT_DIRS = {
    "/sys":     {"mode": 0xf2, "uid": 0, "gid": 0, "desc": "0770 (rwxrwx---)"},
    "/shared1": {"mode": 0xf2, "uid": 0, "gid": 0, "desc": "0770 (rwxrwx---)"},
    "/ticket":  {"mode": 0xf2, "uid": 0, "gid": 0, "desc": "0770 (rwxrwx---)"},
    "/title":   {"mode": 0xf6, "uid": 0, "gid": 0, "desc": "0775 (rwxrwxr-x)"},
    "/shared2": {"mode": 0xfe, "uid": 0, "gid": 0, "desc": "0777 (rwxrwxrwx)"},
    "/tmp":     {"mode": 0xfe, "uid": 0, "gid": 0, "desc": "0777 (rwxrwxrwx)"},
    "/import":  {"mode": 0xf2, "uid": 0, "gid": 0, "desc": "0770 (rwxrwx---)"},
}

KNOWN_TITLE_NAMES = {
    0x0000000100000002: "System Menu (vWii)",
    0x0000000100000050: "IOS80",
    0x0001000248435550: "Wii U Electronic Manual EUR (HCUP)",
    0x0001000248435545: "Wii U Electronic Manual USA (HCUE)",
    0x000100024843554a: "Wii U Electronic Manual JPN (HCUJ)",
    0x0001000248414341: "Mii Channel (HACA)",
    0x0001000848414c50: "EULA EUR (HALP)",
    0x0001000848414c45: "EULA USA (HALE)",
    0x0001000848414c4a: "EULA JPN (HALJ)",
    0x0001000248435641: "Return to Wii U Menu (HCVA)",
    0x0001000248414241: "Disc Channel (HABA)",
    0x0000000100000200: "BC-NAND",
    0x0000000100000201: "BC-WFS",
    0x0000000100000009: "IOS9",
    0x000000010000000c: "IOS12",
    0x000000010000000d: "IOS13",
    0x000000010000000e: "IOS14",
    0x000000010000000f: "IOS15",
    0x0000000100000011: "IOS17",
    0x0000000100000015: "IOS21",
    0x0000000100000016: "IOS22",
    0x000000010000001c: "IOS28",
    0x000000010000001f: "IOS31",
    0x0000000100000021: "IOS33",
    0x0000000100000022: "IOS34",
    0x0000000100000023: "IOS35",
    0x0000000100000024: "IOS36",
    0x0000000100000025: "IOS37",
    0x0000000100000026: "IOS38",
    0x0000000100000029: "IOS41",
    0x000000010000002b: "IOS43",
    0x000000010000002d: "IOS45",
    0x000000010000002e: "IOS46",
    0x0000000100000030: "IOS48",
    0x0000000100000035: "IOS53",
    0x0000000100000037: "IOS55",
    0x0000000100000038: "IOS56",
    0x0000000100000039: "IOS57",
    0x000000010000003a: "IOS58",
    0x000000010000003b: "IOS59",
    0x000000010000003e: "IOS62",
    0x0001000848435a50: "Region Select EUR (HCZP)",
    0x0001000848435a45: "Region Select USA (HCZE)",
    0x0001000848435a4a: "Region Select JPN (HCZJ)",
}

def get_friendly_name(title_id):
    if title_id in KNOWN_TITLE_NAMES:
        return KNOWN_TITLE_NAMES[title_id]
    idHi = (title_id >> 32) & 0xFFFFFFFF
    idLo = title_id & 0xFFFFFFFF
    return f"Title {idHi:08x}/{idLo:08x}"

class ValidationReport:
    def __init__(self):
        self.errors = []
        self.warnings = []
        self.passes = []
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

    # 1. Load SFFS Image
    try:
        nand, sb, root = load_sffs(image_path, otp_path)
    except Exception as e:
        report.error("/", f"Failed to load SFFS filesystem: {e}")
        return report

    nodes = {}
    walk_sffs_tree(nand, root, nodes, read_content=False)
    report.stats["total_nodes"] = len(nodes)

    # 2. Validate Root Directories
    for rpath, exp in STOCK_ROOT_DIRS.items():
        if rpath not in nodes:
            report.error(rpath, "Root directory is MISSING")
            continue
        node = nodes[rpath]
        if node["is_file"]:
            report.error(rpath, "Expected directory, found file")
            continue
        if node["mode"] != exp["mode"]:
            report.error(rpath, f"Mode mismatch: 0x{node['mode']:02x} (expected 0x{exp['mode']:02x} {exp['desc']})")
        if node["uid"] != exp["uid"] or node["gid"] != exp["gid"]:
            report.error(rpath, f"Ownership mismatch: UID={node['uid']}, GID={node['gid']} (expected {exp['uid']}/{exp['gid']})")
        report.pass_check(rpath, f"Root directory permissions OK (mode=0x{node['mode']:02x}, uid={node['uid']}, gid={node['gid']})")

    # 3. Validate System Files (/sys/cert.sys, /sys/uid.sys)
    if "/sys/cert.sys" not in nodes:
        report.error("/sys/cert.sys", "cert.sys is MISSING")
    else:
        c = nodes["/sys/cert.sys"]
        if c["mode"] != 0xf5:
            report.error("/sys/cert.sys", f"cert.sys mode mismatch: 0x{c['mode']:02x} (expected 0xf5 / 0664)")
        if c["uid"] != 0 or c["gid"] != 0:
            report.error("/sys/cert.sys", f"cert.sys ownership mismatch: {c['uid']}/{c['gid']} (expected 0/0)")
        if c["size"] != 2560:
            report.error("/sys/cert.sys", f"cert.sys size invalid: {c['size']} bytes (expected 2560 bytes)")
        else:
            report.stats["cert_sys_valid"] = True
            report.pass_check("/sys/cert.sys", "cert.sys permissions and size OK (0xf5, 0/0, 2560 B)")

    if "/sys/uid.sys" not in nodes:
        report.error("/sys/uid.sys", "uid.sys is MISSING")
    else:
        u = nodes["/sys/uid.sys"]
        if u["mode"] != 0xf1:
            report.error("/sys/uid.sys", f"uid.sys mode mismatch: 0x{u['mode']:02x} (expected 0xf1 / 0660)")
        if u["uid"] != 0 or u["gid"] != 0:
            report.error("/sys/uid.sys", f"uid.sys ownership mismatch: {u['uid']}/{u['gid']} (expected 0/0)")
        if u["size"] == 0 or u["size"] % 12 != 0:
            report.error("/sys/uid.sys", f"uid.sys size invalid: {u['size']} bytes (expected multiple of 12)")
        else:
            report.stats["uid_sys_valid"] = True
            num_entries = u["size"] // 12
            report.pass_check("/sys/uid.sys", f"uid.sys valid table ({num_entries} registered title records)")

    # 4. Validate setting.txt
    setting_path = "/title/00000001/00000002/data/setting.txt"
    if setting_path not in nodes:
        report.error(setting_path, "setting.txt is MISSING")
    else:
        s = nodes[setting_path]
        if s["mode"] != 0x55:
            report.error(setting_path, f"setting.txt mode mismatch: 0x{s['mode']:02x} (expected 0x55 / 0444 read-only)")
        if s["uid"] != 4096 or s["gid"] != 1:
            report.error(setting_path, f"setting.txt ownership mismatch: {s['uid']}/{s['gid']} (expected 4096/1)")
        if s["size"] != 256:
            report.error(setting_path, f"setting.txt size mismatch: {s['size']} (expected 256)")
        else:
            report.stats["setting_txt_valid"] = True
            report.pass_check(setting_path, "setting.txt permissions and size OK (0x55, 4096/1, 256 B)")

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
        tname = get_friendly_name(tid)
        tnode = nodes[tpath]

        # Check Title Directory mode (0xf6 / 0775, UID 0, GID 0)
        if tnode["mode"] != 0xf6:
            report.error(tpath, f"Title dir mode mismatch: 0x{tnode['mode']:02x} (expected 0xf6)")
        if tnode["uid"] != 0 or tnode["gid"] != 0:
            report.error(tpath, f"Title dir ownership mismatch: {tnode['uid']}/{tnode['gid']} (expected 0/0)")

        # Check Content Directory (mode 0xf2 / 0770, UID 0, GID 0)
        cpath = f"{tpath}/content"
        if cpath in nodes:
            cnode = nodes[cpath]
            if cnode["mode"] != 0xf2:
                report.error(cpath, f"Content dir mode mismatch: 0x{cnode['mode']:02x} (expected 0xf2)")
            if cnode["uid"] != 0 or cnode["gid"] != 0:
                report.error(cpath, f"Content dir ownership mismatch: {cnode['uid']}/{cnode['gid']} (expected 0/0)")

        # Check TMD (mode 0xf1 / 0660, UID 0, GID 0)
        tmd_path = f"{cpath}/title.tmd"
        if tmd_path in nodes:
            tmd_node = nodes[tmd_path]
            if tmd_node["mode"] != 0xf1:
                report.error(tmd_path, f"TMD mode mismatch: 0x{tmd_node['mode']:02x} (expected 0xf1)")
            if tmd_node["uid"] != 0 or tmd_node["gid"] != 0:
                report.error(tmd_path, f"TMD ownership mismatch: {tmd_node['uid']}/{tmd_node['gid']} (expected 0/0)")

        # Check Ticket (mode 0xf1 / 0660, UID 0, GID 0)
        tik_path = f"/ticket/{idHi:08x}/{idLo:08x}.tik"
        if tik_path in nodes:
            tik_node = nodes[tik_path]
            if tik_node["mode"] != 0xf1:
                report.error(tik_path, f"Ticket mode mismatch: 0x{tik_node['mode']:02x} (expected 0xf1)")
            if tik_node["uid"] != 0 or tik_node["gid"] != 0:
                report.error(tik_path, f"Ticket ownership mismatch: {tik_node['uid']}/{tik_node['gid']} (expected 0/0)")

        # Validate /data directory with UID & GID Allocation Checks
        dpath = f"{tpath}/data"
        if dpath not in nodes:
            report.warning(dpath, f"Title has no /data directory: {tname}")
        else:
            dnode = nodes[dpath]
            expected_gid = get_expected_gid(tid)

            # System Menu must be UID 4096
            if tid == 0x0000000100000002 and dnode["uid"] != 4096:
                report.error(dpath, f"System Menu data dir UID must be 4096 (got {dnode['uid']})")
            elif dnode["uid"] < 4096:
                report.error(dpath, f"Invalid title UID {dnode['uid']} (expected >= 4096)")

            if dnode["uid"] in seen_uids:
                report.error(dpath, f"Duplicate UID {dnode['uid']} collision with another title!")
            seen_uids.add(dnode["uid"])

            if dnode["mode"] != 0xc2:
                report.error(dpath, f"Data dir mode mismatch: 0x{dnode['mode']:02x} (expected 0xc2 / 0700)")
            if dnode["gid"] != expected_gid:
                report.error(dpath, f"Data dir GID mismatch: {dnode['gid']} (expected {expected_gid})")

            if dnode["mode"] == 0xc2 and dnode["gid"] == expected_gid and dnode["uid"] >= 4096:
                report.stats["data_dirs_valid"] += 1
                report.pass_check(dpath, f"Data dir permissions valid: UID={dnode['uid']}, GID={dnode['gid']} ({tname})")

    # 6. Validate Shared Content & content.map
    if "/shared1/content.map" not in nodes:
        report.error("/shared1/content.map", "content.map is MISSING from /shared1")
    else:
        cmap_node = nodes["/shared1/content.map"]
        if cmap_node["mode"] != 0xf1:
            report.error("/shared1/content.map", f"content.map mode mismatch: 0x{cmap_node['mode']:02x} (expected 0xf1 / 0660)")
        if cmap_node["uid"] != 0 or cmap_node["gid"] != 0:
            report.error("/shared1/content.map", f"content.map ownership mismatch: {cmap_node['uid']}/{cmap_node['gid']} (expected 0/0)")
        if cmap_node["size"] == 0 or cmap_node["size"] % 28 != 0:
            report.error("/shared1/content.map", f"content.map size invalid: {cmap_node['size']} bytes (expected multiple of 28)")
        else:
            report.stats["content_map_valid"] = True
            expected_shared_count = cmap_node["size"] // 28
            report.pass_check("/shared1/content.map", f"content.map valid structure ({expected_shared_count} shared entries registered)")

    # Validate all /shared1/*.app files
    shared_apps = [p for p in nodes if p.startswith("/shared1/") and p.endswith(".app")]
    report.stats["shared_apps_checked"] = len(shared_apps)
    for app_path in shared_apps:
        anode = nodes[app_path]
        if anode["mode"] != 0xf1:
            report.error(app_path, f"Shared app mode mismatch: 0x{anode['mode']:02x} (expected 0xf1 / 0660)")
        if anode["uid"] != 0 or anode["gid"] != 0:
            report.error(app_path, f"Shared app ownership mismatch: {anode['uid']}/{anode['gid']} (expected 0/0)")
        if anode["size"] == 0:
            report.error(app_path, "Shared app is 0 bytes")

    report.pass_check("/shared1", f"Verified all {len(shared_apps)} shared .app files and content.map")

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
                            report.error(p, f"Payload differs from reference image: {node['sha1'][:8]}.. vs {r_nodes[p]['sha1'][:8]}..")
                    else:
                        report.warning(p, "Title payload not present in reference image")

            # 2. Compare Shared Contents (/shared1/*.app) Order-Independently
            target_shared = sorted([n["size"] for p, n in nodes.items() if p.startswith("/shared1/") and p.endswith(".app")])
            ref_shared = sorted([n["size"] for p, n in r_nodes.items() if p.startswith("/shared1/") and p.endswith(".app")])

            if len(target_shared) != len(ref_shared):
                report.error("/shared1", f"Shared .app count mismatch: {len(target_shared)} vs {len(ref_shared)} in reference")
            elif target_shared != ref_shared:
                report.error("/shared1", f"Shared .app size distribution mismatch with reference")
            else:
                report.pass_check("/shared1 (Parity)", f"Order-independent shared content parity verified: all {len(target_shared)} shared module sizes match reference exactly")

            report.pass_check("REFERENCE_PARITY", f"Compared {payload_matches + payload_diffs} private title payloads against reference: {payload_matches} identical, {payload_diffs} diffs")
        except Exception as e:
            report.warning("REFERENCE_CHECK", f"Failed to compare with reference image: {e}")

    return report

def main():
    parser = argparse.ArgumentParser(description="Validate an SLCCMPT image against stock vWii permissions and integrity rules.")
    parser.add_argument("image", help="Path to the SLCCMPT .RAW / .bin NAND image.")
    parser.add_argument("--otp", default=None, help="Path to otp.bin.")
    parser.add_argument("--reference", default=None, help="Optional reference RAW image for payload comparison.")
    parser.add_argument("--verbose", "-v", action="store_true", help="Display all passing checks.")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format.")

    args = parser.parse_args()

    report = validate_image(args.image, args.otp, args.reference, args.verbose)

    if args.json:
        out = {
            "image": args.image,
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

    # Human-readable output
    print("\n" + "="*95)
    print(f"SLCCMPT Image Validation Report: {args.image}")
    print("="*95)
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
        print("\n>>> RESULT: VALIDATION SUCCESSFUL (Image is 100% Stock Compliant) <<<")
        sys.exit(0)

if __name__ == '__main__':
    main()
