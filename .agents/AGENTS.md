# vWii Compat Installer Rules

These rules dictate how agents should interact with the vWii Compat Installer project.

## Building the App
- The application is built using `make`. It relies on the devkitPPC, devkitARM, and `wut` toolchains, as well as the `libmocha` library.
- For compilation verification during development, use standard incremental `make` without `make clean` (do not run `make clean` before building as incremental builds are much faster). Only run `make release` when explicitly packaging release zip bundles (`compat_installer-HBL.zip` and `compat_installer-Aroma.zip`).
- You can also build it using the provided `Dockerfile` which defines the necessary build environment.

## Licenses and Crediting
- If we pull code in or use external documentation, we must credit it in the `README.md` and ensure that we strictly obey the original `LICENSE`.
- **Credits Maintenance**: Whenever a new library, tool, or external code is added to the project, both the in-app credits screen (`WUPI_showCredits()` in `src/main.cpp`) and the Credits section in `README.md` must be updated to include proper attribution.

## Learning from the User
- If the user has to explicitly explain a project-specific concept, rule, or workflow to you, you should proactively append that information to this `AGENTS.md` file so that future agents are aware of it.

## Wii U Filesystem (FSA) Rules
- **Memory Alignment**: FSA operations (like `FSAWriteFile` or `FSAReadFile`) strictly require data buffers to be 64-byte aligned (`0x40`). Always use `memalign(0x40, size)` instead of `malloc(size)` for any buffer that will be passed into FSA functions. Failing to do this can result in silent failures or 0-byte files, particularly when memory becomes fragmented during batch operations.
- **Error Checking**: Never ignore the return value of FSA operations. For example, `FSAWriteFile` returns the number of elements written or a negative error code. Always explicitly check that the return value matches the expected write size, and correctly handle the failure by propagating the error or aborting the operation.

## Workspace Clutter and Temporary Files
- Any test scripts, investigation scripts, or temporary data generated during problem-solving should be placed inside `testdata/scripts/` or `testdata/tmp/` to avoid cluttering the project root.
- The `testdata/` folder is ignored in `.gitignore`, ensuring that ephemeral exploration files do not get committed. Do not leave scripts in the root directory.

## C++ Code Conventions
- **Prefer Modern C++ Strings**: Prefer `std::string` and `const std::string&` over raw C-strings (`char*`, `char[]`) and fixed-size buffers for path manipulation and string handling wherever reasonable. For path parameters that will be passed down to C filesystem APIs, use `const std::string&` so callers can pass `std::string`, string literals, or C-strings and `.c_str()` is readily available without manual conversion.
- **Packed Structures**: Use `struct __attribute__((packed)) Name { ... };` with `static_assert(sizeof(Name) == ...)` for binary on-disk structures to match GCC/devkitPro conventions across the codebase.

## vWii setting.txt Rules
- **Supported Regions**: There is no Korean (KOR) vWii / Wii U. The only valid vWii regions are Europe (`EUR`), USA (`USA`), and Japan (`JPN`).

## vWii SLCCMPT Filesystem (SFFS / ISFS) Ownership and Permissions
> **Full Reference Documentation**: See [docs/SLCCMPT_PERMISSIONS.md](docs/SLCCMPT_PERMISSIONS.md) for the complete permission matrix, SFFS mode byte layout, and architecture details.

- **Cafe OS Process Default Ownership**: When files/directories are created via Cafe OS FSA over `/dev/fsa`, the IOSU kernel stamps them with Cafe OS process credentials (`UID 0x10050000` / `268755456`, `GID 1024`) and default umask `mode = 0xc1` (`rw-------`, Owner only).
- **vWii Access Lockout**: In vWii mode, the System Menu runs with `UID = 4096` (`0x1000`) and IOS runs with `UID = 0`. If files have `0xc1` mode and `UID 0x10050000`, vWii treats them as "Other", gets `ACCESS_DENIED` (`-102`), and black-screens.
  - Stock Ownership and Modes:
    - System tickets (`/ticket/00000001/*.tik`), system TMDs, system `.app` files, shared `.app` files (`/shared1/*.app`), `content.map`, `/sys/uid.sys`, and `/sys/space.sys` are owned by **`UID = 0`**, **`GID = 0`** with mode `0xf1` (`rw-rw----`).
    - `/sys/cert.sys` is owned by **`UID = 0`**, **`GID = 0`** with mode `0xf5` (`rw-rw-r--`, `STOCK_MODE_CERT_SYS`).
    - Directories (`/title`, `/title/<idHi>`, `/title/<idHi>/<idLo>`) are owned by **`UID = 0`**, **`GID = 0`** with mode `0xf6` (`rwxrwxr-x`, `STOCK_MODE_SYSTEM_DIR` = `(FSMode)0x775`).
    - Directories (`/sys`, `/shared1`, `/ticket`, `/content`, `/import`, `/title/<idHi>/<idLo>/content`) are owned by **`UID = 0`**, **`GID = 0`** with mode `0xf2` (`rwxrwx---`, `STOCK_MODE_CONTENT_DIR` = `(FSMode)0x770`).
    - `/shared2` and `/tmp` directories are owned by **`UID = 0`**, **`GID = 0`** with mode `0xfe` (`rwxrwxrwx`, `STOCK_MODE_SHARED2_DIR` / `STOCK_MODE_TMP_DIR` = `(FSMode)0x777`).
    - Title data directories (`/title/<idHi>/<idLo>/data`) are owned by the title's allocated Title UID and TMD Group ID (`0xc2` mode, `STOCK_MODE_DATA_DIR` = `(FSMode)0x700`, `rwx------`).
    - `setting.txt` (`/title/00000001/00000002/data/setting.txt`) is owned by **`UID = 4096`**, **`GID = 1`** with mode `0x55` (read-only for all, `STOCK_MODE_SETTING_TXT` = `(FSMode)0x444`).
- **Changing Ownership via IPC (`FSA_ChangeOwner`)**:
  - `FSA_ChangeOwner` sends raw IOSU ioctl `0x70` (`FSA_COMMAND_CHANGE_OWNER`) with `FSARequest` / `FSAResponse` (`0x40` aligned).
  - **Permission Modes**: Use predefined stock mode constants (`STOCK_MODE_SETTING_TXT`, `STOCK_MODE_SYSTEM_FILE`, `STOCK_MODE_SYSTEM_DIR`, `STOCK_MODE_CONTENT_DIR`, `STOCK_MODE_DATA_DIR`, `STOCK_MODE_TICKET_SUBDIR`, `STOCK_MODE_SHARED2_DIR`, `STOCK_MODE_TMP_DIR`).
  - **Directory Chown Timing (While Empty)**: A directory can ONLY have its owner changed while it is **STILL EMPTY** (immediately following `FSAMakeDir`). If child files or subdirectories are created inside a directory first, `FSA_ChangeOwner` on the directory fails with `FS_ERROR_NOT_EMPTY` (`-196632`).
  - **File Chown Timing (0 Bytes / Empty)**: A file can ONLY have its owner changed while it is **0 BYTES (EMPTY)**. If data is written to the file first, `FSA_ChangeOwner` fails with `FS_ERROR_NOT_EMPTY` (`-196632`). Always use the 6-step `FSACreateFileWithOwner(...)` helper: (1) `FSARemove` any pre-existing file so a fresh inode is allocated, (2) create a 0-byte file via `FSAOpenFileEx(..., "wb", 0x666, ...)` and close it, (3) `FSA_ChangeOwner` while the file is still 0 bytes/empty, (4) reopen with `"r+b"` and write payload, (5) close, (6) set final mode with `FSAChangeMode`.
- **Title UID and Group Allocation (`/sys/uid.sys`)**:
  - `/sys/uid.sys` stores a packed binary table of 12-byte entries (`struct __attribute__((packed)) RawUidEntry { uint64_t titleId; uint32_t uid; };`).
  - Group ID (GID) resolution (`UID_GetTitleGid`): `1` (`VWII_GID_SYSTEM_TITLE`) for System titles/IOSes (`00000001/*`), `23130` (`0x5a5a` / `'ZZ'`, `VWII_GID_HCVA`) for Wii U Menu Return (`00010002/48435641`), and `12337` (`0x3031` / `'01'`, `VWII_GID_CHANNEL`) for all other channels, hidden channels, and disc titles.
  - Titles run unprivileged in user mode and cannot create `/data` or chown directories themselves; installers MUST create the `/data` directory and register the title in `/sys/uid.sys` during title installation for save data persistence.
  - `UID_Reconstruct` recovers `/sys/uid.sys` by scanning all `/vol/slccmpt01/title/*/*/data` directories for existing valid UIDs, preserving save data permissions without clearing data.


