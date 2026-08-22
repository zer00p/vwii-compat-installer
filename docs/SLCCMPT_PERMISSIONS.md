# vWii SLCCMPT Filesystem (SFFS / ISFS) Ownership and Permissions

This document details the file ownership, permission modes, and filesystem rules for the vWii SLCCMPT NAND partition (`/vol/slccmpt01`).

---

## 1. Background & Permission Architecture

The vWii SLCCMPT partition is formatted with **SFFS** (Secure Flash File System, also known as ISFS on the Wii). SFFS node metadata contains:
- **`owner` (UID)**: 32-bit User ID.
- **`group` (GID)**: 16-bit Group ID.
- **`mode`**: 8-bit SFFS permission byte.

### SFFS Mode Byte Layout

> [!NOTE]
> **No Execute (`x`) Permissions & Hexadecimal `FSMode` Bitmasks**: SFFS does **not** support or store execute (`x`) permissions. The underlying on-disk permission byte only encodes 2 bits each for Owner, Group, and Other: read (`r`) and write (`w`). In Cafe OS FSA (`coreinit/filesystem.h`), permissions are represented as **hexadecimal bitmasks** (`FS_MODE_READ_OWNER = 0x400`, `FS_MODE_WRITE_OWNER = 0x200`, `FS_MODE_READ_GROUP = 0x040`, `FS_MODE_WRITE_GROUP = 0x020`, `FS_MODE_READ_OTHER = 0x004`, `FS_MODE_WRITE_OTHER = 0x002`). Across the codebase, all modes are specified using **hexadecimal literals** (`0x660`, `0x664`, `0x666`, `0x600`, `0x444`, `0x000`).

```
Bit:   7   6   5   4   3   2   1   0
     [Owner] [Group] [Other] [D] [F]
```
- **Bit 0 (`0x01`)**: Node Type (`1` = File, `0` = Directory).
- **Bit 1 (`0x02`)**: Directory flag (`1` for directories).
- **Bits 7..6**: Owner permissions (`0` = none, `1` = r, `2` = w, `3` = rw).
- **Bits 5..4**: Group permissions (`0` = none, `1` = r, `2` = w, `3` = rw).
- **Bits 3..2**: Other permissions (`0` = none, `1` = r, `2` = w, `3` = rw).

### Cafe OS vs. vWii Runtime Credentials

* **Cafe OS Process Default**: When files or directories are created from Wii U mode via `/dev/fsa`, IOSU stamps them with Cafe OS process credentials (`UID 0x10050000` / `268755456`, `GID 1024`) and default umask `mode = 0xc1` (`rw-------`, Owner-only access).
* **vWii Mode Execution**: In vWii mode, IOS runs with `UID 0`, the System Menu runs with `UID 4096` (`0x1000`), and titles run with their allocated Title UID.
* **The Access Lockout Problem**: If files on SLCCMPT retain the Cafe OS default `UID 0x10050000` and `0xc1` mode, vWii treats all processes as "Other" and denies access (`ISFS_ERROR_ACCESS_DENIED` / `-102`), resulting in black screens or *"The system files are corrupted"* errors.

---

## 2. Stock Ownership and Permission Matrix

| Path / Pattern | Type | Owner UID | Group GID | SFFS Mode | Cafe OS Mode (`FSMode`) | Permissions | Description / Notes |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| `/title/00000001/00000002/data/setting.txt` | File | **4096** | **1** | `0x55` | `(FSMode)0x444` | `r--r--r--` | System Menu configuration. Read-only for all. |
| `/ticket/00000001/*.tik`, `/ticket/*/*.tik` | File | **0** | **0** | `0xf1` | `(FSMode)0x660` | `rw-rw----` | System tickets. |
| `/title/*/*/content/title.tmd` | File | **0** | **0** | `0xf1` | `(FSMode)0x660` | `rw-rw----` | Title metadata descriptors. |
| `/title/*/*/content/*.app` | File | **0** | **0** | `0xf1` | `(FSMode)0x660` | `rw-rw----` | System and title binaries / contents. |
| `/shared1/*.app` | File | **0** | **0** | `0xf1` | `(FSMode)0x660` | `rw-rw----` | Shared system content. |
| `/shared1/content.map` | File | **0** | **0** | `0xf1` | `(FSMode)0x660` | `rw-rw----` | Shared content SHA-1 mapping table. |
| `/sys/uid.sys`, `/sys/space.sys` | File | **0** | **0** | `0xf1` | `(FSMode)0x660` | `rw-rw----` | System tables / metadata. |
| `/sys/cert.sys` | File | **0** | **0** | `0xf5` | `(FSMode)0x664` | `rw-rw-r--` | Central certificate trust store (`XS00000003`, `CA00000001`, `CP00000004`). Read-access for all UIDs. |
| `/title` | Dir | **0** | **0** | `0xf6` | `(FSMode)0x664` | `rw-rw-r--` | Title root directory. |
| `/sys`, `/shared1`, `/ticket`, `/import` | Dir | **0** | **0** | `0xf2` | `(FSMode)0x660` | `rw-rw----` | System root directories. |
| `/shared2`, `/tmp` | Dir | **0** | **0** | `0xfe` | `(FSMode)0x666` | `rw-rw-rw-` | Shared system & temp directories (writable by all UIDs). |
| `/title/<idHi>` | Dir | **0** | **0** | `0xf6` | `(FSMode)0x664` | `rw-rw-r--` | Title category directory (e.g. `00000001`). |
| `/title/<idHi>/<idLo>` | Dir | **0** | **0** | `0xf6` | `(FSMode)0x664` | `rw-rw-r--` | Specific title directory. |
| `/title/<idHi>/<idLo>/content` | Dir | **0** | **0** | `0xf2` | `(FSMode)0x660` | `rw-rw----` | Title content directory. |
| `/ticket/<idHi>` | Dir | **0** | **0** | `0x02` | `(FSMode)0x000` | `---------` | Ticket category subdirectory. |
| `/title/<idHi>/<idLo>/data` | Dir | **`Title UID`** | **`TMD GID`** | `0xc2` | `(FSMode)0x600` | `rw-------` | Title save data / configuration directory. |

---

## 3. Title UID Allocation (`/sys/uid.sys`)

* **Structure**: `/sys/uid.sys` is a binary table of packed 12-byte entries (`struct __attribute__((packed)) RawUidEntry { uint64_t titleId; uint32_t uid; };`).
* **Base Reservation**: UID `4096` (`0x1000`) is **always reserved for the System Menu** (`0000000100000002`).
* **Allocation Sequence**: Subsequent UIDs iterate monotonically (+1) from `4097` (`0x1001`) onwards as titles are installed.
* **Group ID (GID)**: Extracted from offset `0x98` in the TMD payload (`1` for System/IOS titles, `12337` / `'01'` for channels, `23130` / `'ZZ'` for Wii U Menu Return).
* **Mandatory Save Directory Requirement**: Because titles run in unprivileged user mode, they cannot create directories inside `/title/<idHi>/<idLo>` or `chown` their save folder. Installers must create the `/data` directory and register the title in `/sys/uid.sys` during title installation.
* **UID Reconstruction & Save Data Preservation**: When repairing or reconstructing `/sys/uid.sys`, the installer scans existing `/vol/slccmpt01/title/*/*/data` directories. If valid vWii UID ownership (`stat.owner >= 0x1000` and `!= 0x10050000`) is detected on an existing `/data` directory, that UID is preserved in `/sys/uid.sys`. This prevents save data access lockout in vWii mode and eliminates the need to wipe `/data` folders during repair.

---

## 4. Setting Ownership & Permissions via IPC

Ownership changes on SLCCMPT are performed via raw IOS IPC ioctl `0x70` (`FSA_COMMAND_CHANGE_OWNER`):

```cpp
FSError FSA_ChangeOwner(FSAClientHandle fsaClient, const std::string& path, uint32_t uid, uint32_t gid);
```

- **Directory Permissions**: Directory modes are set during directory creation via `FSAMakeDir(fsaClient, path, mode)`. SFFS does not support `ChangeMode` on directories (returns `FS_ERROR_INVALID_PARAM` `-196641`); never call `FSAChangeMode` on directories.
- **File Permissions**: Files are created with `FSACreateFileWithOwner(...)` and explicitly have their final mode set via `FSAChangeMode(fsaClient, path, mode)` (e.g. `0444` for setting.txt, `0660` for system files).

### Critical Rules for Ownership and Creation

1. **Directory Chown Timing (Must Be Empty)**:
   A directory can **ONLY** have its owner or group changed while it is **STILL EMPTY (0 child entries)** immediately following `FSAMakeDir`. If child files or subdirectories are created inside it first, `FSA_ChangeOwner` on the directory fails with `FS_ERROR_NOT_EMPTY` (`-196632`).
   
2. **File Chown Timing (Must Be 0 Bytes / Empty)**:
   A file can **ONLY** have its owner changed while it is **0 BYTES (EMPTY)**. If payload data is written to the file first, `FSA_ChangeOwner` fails with `FS_ERROR_NOT_EMPTY` (`-196632`).

3. **Always Use `FSACreateFileWithOwner` for Files**:
   To guarantee correct ordering when writing files to SLCCMPT, always use [`FSACreateFileWithOwner`](../src/FSAUtils.cpp):
   ```cpp
   bool FSACreateFileWithOwner(FSAClientHandle fsaClient, const std::string& path,
                               const void* buffer, size_t size,
                               FSMode mode, uint32_t uid, uint32_t gid);
   ```
   This function executes the necessary 5-step sequence:
   1. `FSARemove(path)` (allocates a fresh inode).
   2. `FSAOpenFileEx("wb", mode)` + `FSACloseFile()` (creates empty 0-byte file).
   3. `FSA_ChangeOwner(uid, gid)` (applied while 0 bytes).
   4. `FSAOpenFileEx("r+b", mode)` + `FSAWriteAligned()` + `FSACloseFile()` (writes payload).
   5. `FSAChangeMode(mode)` (locks final permissions like `0444` for setting.txt or `0660` for system files).
