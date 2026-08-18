# vWii SLCCMPT Filesystem (SFFS / ISFS) Ownership and Permissions

This document details the file ownership, permission modes, and filesystem rules for the vWii SLCCMPT NAND partition (`/vol/slccmpt01`).

---

## 1. Background & Permission Architecture

The vWii SLCCMPT partition is formatted with **SFFS** (Secure Flash File System, also known as ISFS on the Wii). SFFS node metadata contains:
- **`owner` (UID)**: 32-bit User ID.
- **`group` (GID)**: 16-bit Group ID.
- **`mode`**: 8-bit SFFS permission byte.

### SFFS Mode Byte Layout

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
| `/sys/uid.sys` | File | **0** | **0** | `0xf1` | `(FSMode)0x660` | `rw-rw----` | Title UID allocation table. |
| `/sys/cert.sys` | File | **0** | **0** | `0xf1` | `(FSMode)0x660` | `rw-rw----` | Central certificate trust store (`XS00000003`, `CA00000001`, `CP00000004`). |
| `/title`, `/content`, `/shared1`, `/sys` | Dir | **0** | **0** | `0xf6` | `(FSMode)0x664` | `rwxrwxr--` | Root system directories. |
| `/title/<idHi>` | Dir | **0** | **0** | `0xf6` | `(FSMode)0x664` | `rwxrwxr--` | Title category directory (e.g. `00000001`). |
| `/title/<idHi>/<idLo>` | Dir | **0** | **0** | `0xf6` | `(FSMode)0x664` | `rwxrwxr--` | Specific title directory. |
| `/title/<idHi>/<idLo>/content` | Dir | **0** | **0** | `0xf2` | `(FSMode)0x660` | `rwxrwx---` | Title content directory. |
| `/ticket/<idHi>` | Dir | **0** | **0** | `0x02` | `(FSMode)0x000` | `---------` | Ticket category subdirectory. |
| `/title/<idHi>/<idLo>/data` | Dir | **`Title UID`** | **`TMD GID`** | `0xc2` | `(FSMode)0x600` | `rwx------` | Title save data / configuration directory. |

---

## 3. Title UID Allocation (`/sys/uid.sys`)

* **Structure**: `/sys/uid.sys` is a binary table of packed 12-byte entries (`struct __attribute__((packed)) RawUidEntry { uint64_t titleId; uint32_t uid; };`).
* **Base Reservation**: UID `4096` (`0x1000`) is **always reserved for the System Menu** (`0000000100000002`).
* **Allocation Sequence**: Subsequent UIDs iterate monotonically (+1) from `4097` (`0x1001`) onwards as titles are installed.
* **Group ID (GID)**: Extracted from offset `0x98` in the TMD payload (`1` for System/IOS titles, `12337` / `'01'` for channels, `23130` / `'ZZ'` for Wii U Menu Return).
* **Mandatory Save Directory Requirement**: Because titles run in unprivileged user mode, they cannot create directories inside `/title/<idHi>/<idLo>` or `chown` their save folder. Installers must create the `/data` directory and register the title in `/sys/uid.sys` during title installation.

---

## 4. Setting Ownership via IPC (`FSA_ChangeOwner`)

Wii U Cafe OS does not expose a high-level `FSAChangeOwner` wrapper in `coreinit`. Ownership must be changed via raw IOS IPC ioctl `0x70` (`FSA_COMMAND_CHANGE_OWNER`):

```cpp
int FSA_ChangeOwner(FSAClientHandle fsaClient, const char* path, uint32_t uid, uint32_t gid);
```

### Critical Rules for `FSA_ChangeOwner`

1. **Directory Chown Timing (Must Be Empty)**:
   A directory can **ONLY** have its owner or group changed while it is **STILL EMPTY (0 child entries)** immediately following `FSAMakeDir`. If child files or subdirectories are created inside it first, `FSA_ChangeOwner` fails with `FS_ERROR_NOT_EMPTY` (`-196632`).
   
2. **File Chown Timing (Must Be 0 Bytes / Empty)**:
   A file can **ONLY** have its owner changed while it is **0 BYTES (EMPTY)**. If payload data is written to the file first, `FSA_ChangeOwner` fails with `FS_ERROR_NOT_EMPTY` (`-196632`).

3. **Always Use `FSACreateFileWithOwner` for Files**:
   To guarantee correct ordering when writing files to SLCCMPT, always use [`FSACreateFileWithOwner`](../src/FSAUtils.cpp):
   ```cpp
   bool FSACreateFileWithOwner(FSAClientHandle fsaClient, const char* path,
                               const void* buffer, size_t size,
                               FSMode mode, uint32_t uid, uint32_t gid);
   ```
   This function executes the necessary 4-step sequence:
   1. `FSARemove(path)` (allocates a fresh inode).
   2. `FSAOpenFileEx("wb")` + `FSACloseFile()` (creates empty 0-byte file).
   3. `FSA_ChangeOwner(uid, gid)` + `FSAChangeMode(mode)` (applied while 0 bytes).
   4. `FSAOpenFileEx("r+b")` + `FSAWriteAligned()` (writes payload).
