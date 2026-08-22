#!/usr/bin/env python3
"""
inspect_permissions.py - Inspect SFFS permissions, UID, and GID of all nodes in an SLCCMPT NAND image.

Usage:
    python3 inspect_permissions.py <image.raw> [options]

Options:
    --otp <path>        Path to otp.bin (default: auto-detected from testdata/ or local dir)
    --filter <str>      Filter paths containing the given substring (e.g. '/data', '/sys', '/title')
    --format <fmt>      Output format: 'table' (default), 'json', 'csv'
    --sort <key>        Sort by: 'path' (default), 'uid', 'gid', 'mode', 'size'
    --files-only        Display only files
    --dirs-only         Display only directories
"""

import os
import sys
import argparse
import json
import csv

from sffs_common import load_target, walk_sffs_tree, walk_extracted_tree, decode_mode_perms

def main():
    parser = argparse.ArgumentParser(description="Inspect SFFS permissions and ownership in an SLCCMPT image or extracted directory.")
    parser.add_argument("image", help="Path directly to the SLCCMPT .raw/.bin NAND image file or extracted vWii root directory.")
    parser.add_argument("--otp", default=None, help="Path to otp.bin (default: auto-detected next to image or in testdata/).")
    parser.add_argument("--filter", default=None, help="Filter paths by substring.")
    parser.add_argument("--format", choices=["table", "json", "csv"], default="table", help="Output format.")
    parser.add_argument("--sort", choices=["path", "uid", "gid", "mode", "size"], default="path", help="Sort key.")
    parser.add_argument("--files-only", action="store_true", help="Display only files.")
    parser.add_argument("--dirs-only", action="store_true", help="Display only directories.")

    args = parser.parse_args()

    try:
        target_type, resolved_path, nand, sb, root = load_target(args.image, args.otp)
    except Exception as e:
        print(f"Error loading image or directory '{args.image}': {e}", file=sys.stderr)
        sys.exit(1)

    nodes = {}
    if target_type == 'image':
        walk_sffs_tree(nand, root, nodes, read_content=False)
    else:
        walk_extracted_tree(resolved_path, nodes, read_content=False)

    # Filter
    filtered = []
    for path, info in nodes.items():
        if args.filter and args.filter not in path:
            continue
        if args.files_only and not info["is_file"]:
            continue
        if args.dirs_only and info["is_file"]:
            continue
        filtered.append(info)

    # Sort
    filtered.sort(key=lambda x: x[args.sort])

    if args.format == "json":
        out_list = []
        for item in filtered:
            out_list.append({
                "path": item["path"],
                "type": "file" if item["is_file"] else "dir",
                "mode": f"0x{item['mode']:02x}",
                "permissions": decode_mode_perms(item["mode"]),
                "uid": item["uid"],
                "gid": item["gid"],
                "size": item["size"]
            })
        print(json.dumps(out_list, indent=2))

    elif args.format == "csv":
        writer = csv.writer(sys.stdout)
        writer.writerow(["Path", "Type", "Mode", "Permissions", "UID", "GID", "SizeBytes"])
        for item in filtered:
            writer.writerow([
                item["path"],
                "file" if item["is_file"] else "dir",
                f"0x{item['mode']:02x}",
                decode_mode_perms(item["mode"]),
                item["uid"],
                item["gid"],
                item["size"]
            ])

    else:
        # Table format
        print(f"\n==========================================================================================")
        print(f"SFFS Permissions & Ownership: {args.image} ({len(filtered)} nodes matching)")
        print(f"==========================================================================================")
        print(f"{'Type':<5s} | {'Mode':<6s} | {'Permissions':<11s} | {'UID':<10s} | {'GID':<6s} | {'Size (B)':<10s} | Path")
        print("-" * 105)
        for item in filtered:
            t_str = "FILE" if item["is_file"] else "DIR"
            mode_hex = f"0x{item['mode']:02x}"
            perms_str = decode_mode_perms(item["mode"])
            size_str = str(item["size"]) if item["is_file"] else "-"
            print(f"{t_str:<5s} | {mode_hex:<6s} | {perms_str:<11s} | {item['uid']:<10d} | {item['gid']:<6d} | {size_str:<10s} | {item['path']}")

if __name__ == '__main__':
    main()
