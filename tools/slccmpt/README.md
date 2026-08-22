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

Inspects all SFFS nodes and decodes raw SFFS permission mode bytes into Unix-like permission bits (read and write bits per Owner, Group, and Other).

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
Type  | Mode   | Permissions | UID        | GID    | Size (B)   | Path
---------------------------------------------------------------------------------------------------------
DIR   | 0xc2   | rw-------   | 4096       | 1      | -          | /title/00000001/00000002/data
FILE  | 0x55   | r--r--r--   | 4096       | 1      | 256        | /title/00000001/00000002/data/setting.txt
DIR   | 0xc2   | rw-------   | 4101       | 23130  | -          | /title/00010002/48435641/data
DIR   | 0xc2   | rw-------   | 4099       | 12337  | -          | /title/00010002/48414341/data
```

---

## 2. Validate SLCCMPT Image (`validate_slccmpt.py`)

Performs a comprehensive integrity check against factory stock vWii specifications:

1. **Root Directory Hierarchy**: Verifies `/sys`, `/shared1`, `/ticket`, `/title`, `/shared2`, `/tmp`, and `/import` modes and ownership (`UID 0`, `GID 0`).
2. **System Files**: Validates `/sys/cert.sys` (`0xf5`, `0/0`, 2560 B), `/sys/uid.sys` (`0xf1`, `0/0`), and `setting.txt` (`0x55`, `4096/1`, 256 B).
3. **Dynamic UID Ordering Resolution**:
   * Reads the title-to-UID mapping from `/sys/uid.sys`.
    * For every installed title, verifies that its `/title/<idHi>/<idLo>/data` directory exists with mode `0xc2` (`rw-------`), is owned by that title's **allocated UID from `uid.sys`** (handling any title installation sequence), and has the correct GID:
      * For System titles: Uses hardcoded stock GIDs (`GID = 1` for System titles & IOSes `00000001/*`, `GID = 23130` / `'ZZ'` for Return to Wii U `00010002/48435641`, `GID = 12337` / `'01'` for system channels & EULAs).
      * For User installed titles: Checks the GID directly from the title's TMD (`tmd->groupId` at offset `0x198`), with fallback to `12337` (`0x3031`) if no TMD is present.
4. **Cryptographic TMD & Ticket Signature Verification**:
   * Extracts retail certificates from `/sys/cert.sys` (`CA00000001`, `CP00000004`, `XS00000003`).
   * Validates RSA PKCS#1 v1.5 signatures on all installed `title.tmd` and `.tik` files, catching patched IOSes (e.g. patched IOS80), forged TMDs, cIOSes, and fake-signed homebrew titles.
   * Validates title permissions (`0xf1`, `0/0`), ticket category directories (`0x02`, `0/0`), and tickets (`0xf1`, `0/0`).
5. **Content Payload SHA-1 Integrity Auditing**:
   * Parses TMD content records and verifies that all declared `.app` files exist on disk with exact sizes and matching SHA-1 hashes.
   * Detects orphaned or tampered `.app` payload files not listed in the title's TMD.
6. **Order-Independent Shared Content Validation**: Validates `/shared1/content.map` and all `/shared1/*.app` files (`0xf1`, `0/0`), ensuring all shared content modules are present and valid regardless of the numerical slot indexing determined by installer sequence.
7. **Reference Image Parity (`--reference`)**: Compares installed private `.app` payloads and verifies order-independent shared content distribution against a known good reference image.

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
