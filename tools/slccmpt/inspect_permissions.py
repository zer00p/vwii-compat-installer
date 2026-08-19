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

from sffs_common import load_sffs, walk_sffs_tree, decode_mode

def main():
    parser = argparse.ArgumentParser(description="Inspect SFFS permissions and ownership in an SLCCMPT image.")
    parser.add_argument("image", help="Path to the SLCCMPT .RAW / .bin NAND image.")
    parser.add_argument("--otp", default=None, help="Path to otp.bin.")
    parser.add_argument("--filter", default=None, help="Filter paths by substring.")
    parser.add_argument("--format", choices=["table", "json", "csv"], default="table", help="Output format.")
    parser.add_argument("--sort", choices=["path", "uid", "gid", "mode", "size"], default="path", help="Sort key.")
    parser.add_argument("--files-only", action="store_true", help="Display only files.")
    parser.add_argument("--dirs-only", action="store_true", help="Display only directories.")

    args = parser.parse_args()

    try:
        nand, sb, root = load_sffs(args.image, args.otp)
    except Exception as e:
        print(f"Error loading image: {e}", file=sys.stderr)
        sys.exit(1)

    nodes = {}
    walk_sffs_tree(nand, root, nodes, read_content=False)

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
                "mode_hex": f"0x{item['mode']:02x}",
                "mode_desc": decode_mode(item["mode"]),
                "uid": item["uid"],
                "gid": item["gid"],
                "size": item["size"]
            })
        print(json.dumps(out_list, indent=2))

    elif args.format == "csv":
        writer = csv.writer(sys.stdout)
        writer.writerow(["Path", "Type", "ModeHex", "ModeDescription", "UID", "GID", "SizeBytes"])
        for item in filtered:
            writer.writerow([
                item["path"],
                "file" if item["is_file"] else "dir",
                f"0x{item['mode']:02x}",
                decode_mode(item["mode"]),
                item["uid"],
                item["gid"],
                item["size"]
            ])

    else:
        # Table format
        print(f"\n==========================================================================================")
        print(f"SFFS Permissions & Ownership: {args.image} ({len(filtered)} nodes matching)")
        print(f"==========================================================================================")
        print(f"{'Type':<5s} | {'Mode':<6s} | {'UID':<6s} | {'GID':<6s} | {'Size (B)':<9s} | Path (Mode Description)")
        print("-" * 105)
        for item in filtered:
            t_str = "FILE" if item["is_file"] else "DIR"
            mode_hex = f"0x{item['mode']:02x}"
            mode_desc = decode_mode(item["mode"])
            size_str = str(item["size"]) if item["is_file"] else "-"
            print(f"{t_str:<5s} | {mode_hex:<6s} | {item['uid']:<6d} | {item['gid']:<6d} | {size_str:<9s} | {item['path']}  [{mode_desc}]")

if __name__ == '__main__':
    main()
