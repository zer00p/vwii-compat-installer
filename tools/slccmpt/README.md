# vWii SLCCMPT Image Tools & Validation Scripts

This directory contains diagnostic and verification tools for analyzing, inspecting, and validating Wii U vWii `SLCCMPT` NAND filesystem images (`.raw` / `.bin`).

---

## Tool Summary

| Tool | Purpose |
| :--- | :--- |
| **`inspect_permissions.py`** | Dumps and formats the SFFS permission mode, Owner UID, Group GID, size, and path for every file and directory in an SLCCMPT image. |
| **`validate_slccmpt.py`** | Validates an SLCCMPT image against stock vWii permissions and structural rules, dynamically resolving title UIDs from `/sys/uid.sys`. |
| **`sffs_common.py`** | Shared SFFS parsing, decryption, and mode decoding routines. |

---

## 1. Inspect Permissions (`inspect_permissions.py`)

Inspects all SFFS nodes and decodes raw SFFS permission mode bytes into human-readable descriptions and POSIX permission bits.

### Usage
```bash
python3 tools/slccmpt/inspect_permissions.py <image.raw> [options]
```

### Options
* `--otp <path>`: Path to `otp.bin` (default: auto-detects from `testdata/otp.bin`, `testdata/betwiinu/otp.bin`, or `./otp.bin`).
* `--filter <string>`: Filter paths containing the given substring (e.g. `/data`, `/sys`, `/title/00000001`).
* `--format <table|json|csv>`: Output format (default: `table`).
* `--sort <path|uid|gid|mode|size>`: Sort output by the specified column (default: `path`).
* `--files-only`: Show only files.
* `--dirs-only`: Show only directories.

### Example Output
```text
Type  | Mode   | UID    | GID    | Size (B)  | Path (Mode Description)
---------------------------------------------------------------------------------------------------------
DIR   | 0xc2   | 4096   | 1      | -         | /title/00000001/00000002/data  [rwx------ (0700 title data dir)]
FILE  | 0x55   | 4096   | 1      | 256       | /title/00000001/00000002/data/setting.txt  [r--r--r-- (0444 setting.txt)]
DIR   | 0xc2   | 4101   | 23130  | -         | /title/00010002/48435641/data  [rwx------ (0700 title data dir)]
DIR   | 0xc2   | 4099   | 12337  | -         | /title/00010002/48414341/data  [rwx------ (0700 title data dir)]
```

---

## 2. Validate SLCCMPT Image (`validate_slccmpt.py`)

Performs a comprehensive integrity check against factory stock vWii specifications:

1. **Root Directory Hierarchy**: Verifies `/sys`, `/shared1`, `/ticket`, `/title`, `/shared2`, `/tmp`, and `/import` modes and ownership (`UID 0`, `GID 0`).
2. **System Files**: Validates `/sys/cert.sys` (`0xf5`, `0/0`, 2560 B), `/sys/uid.sys` (`0xf1`, `0/0`), and `setting.txt` (`0x55`, `4096/1`, 256 B).
3. **Dynamic UID Ordering Resolution**:
   * Reads the title-to-UID mapping from `/sys/uid.sys`.
   * For every installed title, verifies that its `/title/<idHi>/<idLo>/data` directory exists with mode `0xc2` (`0700`), is owned by that title's **allocated UID from `uid.sys`** (handling any title installation sequence), and has the correct stock GID:
     * `GID = 1` for System titles & IOSes (`00000001/*`)
     * `GID = 23130` (`0x5a5a` / `'ZZ'`) for Return to Wii U (`00010002/48435641`)
     * `GID = 12337` (`0x3031` / `'01'`) for Channels and Disc titles (`00010002/*`, `00010008/*`).
4. **Title Content & Ticket Permissions**: Validates `title.tmd` (`0xf1`, `0/0`), `.app` files (`0xf1`, `0/0`), ticket subdirectories (`0x02`, `0/0`), and tickets (`0xf1`, `0/0`).
5. **Order-Independent Shared Content Validation**: Validates `/shared1/content.map` and all `/shared1/*.app` files (`0xf1`, `0/0`), ensuring all shared content modules are present regardless of the numerical slot indexing determined by installer sequence.
6. **Reference Image Parity (`--reference`)**: Compares installed private `.app` payloads and verifies order-independent shared content distribution against a known good reference image.

### Usage
```bash
# Basic validation
python3 tools/slccmpt/validate_slccmpt.py <image.raw>

# Verbose mode (shows passing checks)
python3 tools/slccmpt/validate_slccmpt.py <image.raw> -v

# JSON output for automated CI / testing
python3 tools/slccmpt/validate_slccmpt.py <image.raw> --json

# Compare against a reference RAW dump
python3 tools/slccmpt/validate_slccmpt.py <image.raw> --reference <reference.raw>
```

### Example Summary
```text
===============================================================================================
SLCCMPT Image Validation Report: SLCCMPT-wipe-reinstall.RAW
===============================================================================================
Total Nodes Scanned:        369
Titles Audited:             38
Valid /data Directories:    38 / 38
Core Files Status:          cert.sys=True, uid.sys=True, setting.txt=True

>>> RESULT: VALIDATION SUCCESSFUL (Image is 100% Stock Compliant) <<<
```
