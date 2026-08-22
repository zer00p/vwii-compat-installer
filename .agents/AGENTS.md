# vWii Compat Installer Rules

These rules dictate how agents should interact with the vWii Compat Installer project.

## Building the App
- The application is built using `make`. It relies on the devkitPPC, devkitARM, and `wut` toolchains, as well as the `libmocha` library.
- For compilation verification during development, use standard incremental `make` without `make clean` (do not run `make clean` before building as incremental builds are much faster). Only run `make release` when explicitly packaging release zip bundles (`compat_installer-HBL.zip` and `compat_installer-Aroma.zip`).
- **Background Tasks & Waiting**: When running build commands, set `WaitMsBeforeAsync` appropriately (up to 10000ms). If a command runs in the background, never poll `manage_task` with `status` in a loop; stop calling tools and rely on the automatic completion message/wakeup to avoid wasting tokens.
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

- **No Execute (`x`) Permissions & Hexadecimal `FSMode` Bitmasks**: SFFS / SLCCMPT does not support execute (`x`) permissions. Permissions on SLCCMPT are strictly read (`r`) and write (`w`) for owner, group, and other. Crucially, Cafe OS FSA / `wut` defines `FSMode` as **hexadecimal bitmasks** (`FS_MODE_READ_OWNER = 0x400`, `FS_MODE_WRITE_OWNER = 0x200`, `FS_MODE_READ_GROUP = 0x040`, `FS_MODE_WRITE_GROUP = 0x020`, `FS_MODE_READ_OTHER = 0x004`, `FS_MODE_WRITE_OTHER = 0x002`). Always use **hexadecimal literals** (`0x660`, `0x664`, `0x666`, `0x600`, `0x444`, `0x000`), NOT C++ octal literals (e.g. `0660` in C++ is decimal 432 = `0x1b0`, which causes bitmask comparisons against FSA `stat.mode` to fail).
- **Cafe OS Process Default Ownership**: When files/directories are created via Cafe OS FSA over `/dev/fsa`, the IOSU kernel stamps them with Cafe OS process credentials (`UID 0x10050000` / `268755456`, `GID 1024`) and default umask `mode = 0xc1` (`rw-------`, Owner only).
- **vWii Access Lockout**: In vWii mode, the System Menu runs with `UID = 4096` (`0x1000`) and IOS runs with `UID = 0`. If files have `0xc1` mode and `UID 0x10050000`, vWii treats them as "Other", gets `ACCESS_DENIED` (`-102`), and black-screens.
  - Stock Ownership and Modes:
    - System tickets (`/ticket/00000001/*.tik`), system TMDs, system `.app` files, shared `.app` files (`/shared1/*.app`), `content.map`, `/sys/uid.sys`, and `/sys/space.sys` are owned by **`UID = 0`**, **`GID = 0`** with mode `0xf1` (`rw-rw----`, `(FSMode)0x660`).
    - `/sys/cert.sys` is owned by **`UID = 0`**, **`GID = 0`** with mode `0xf5` (`rw-rw-r--`, `(FSMode)0x664`).
    - Directories (`/title`, `/title/<idHi>`, `/title/<idHi>/<idLo>`) are owned by **`UID = 0`**, **`GID = 0`** with mode `0xf6` (`rw-rw-r--`, `(FSMode)0x664`).
    - Directories (`/sys`, `/shared1`, `/ticket`, `/import`, `/title/<idHi>/<idLo>/content`) are owned by **`UID = 0`**, **`GID = 0`** with mode `0xf2` (`rw-rw----`, `(FSMode)0x660`).
    - `/shared2` and `/tmp` directories are owned by **`UID = 0`**, **`GID = 0`** with mode `0xfe` (`rw-rw-rw-`, `(FSMode)0x666`).
    - Title data directories (`/title/<idHi>/<idLo>/data`) are owned by the title's allocated Title UID and TMD Group ID (`0xc2` mode, `rw-------`, `(FSMode)0x600`).
    - `/meta` is owned by **`UID = 4096`**, **`GID = 1`** with mode `0xfe` (`rw-rw-rw-`, `(FSMode)0x666`).
    - `/wfs` is owned by **`UID = 19`**, **`GID = 19`** with mode `0xc2` (`rw-------`, `(FSMode)0x600`).
    - `setting.txt` (`/title/00000001/00000002/data/setting.txt`) is owned by **`UID = 4096`**, **`GID = 1`** with mode `0x55` (read-only for all, `(FSMode)0x444`, `r--r--r--`).
- **Changing Ownership via IPC (`FSA_ChangeOwner`) & Permissions**:
  - `FSA_ChangeOwner` sends raw IOSU ioctl `0x70` (`FSA_COMMAND_CHANGE_OWNER`) with `FSARequest` / `FSAResponse` (`0x40` aligned).
  - **Directory Permissions**: Directory modes are set during directory creation via `FSAMakeDir(fsa, path, mode)`. SFFS does not support `ChangeMode` on directories (returns `FS_ERROR_INVALID_PARAM` `-196641`); never call `FSAChangeMode` on directories.
  - **File Permissions**: Files are created with `FSACreateFileWithOwner(...)` and explicitly have their final mode set via `FSAChangeMode(fsaClient, path, mode)` (e.g. `0x444` for setting.txt, `0x660` for system files).
  - **Permission Modes & Centralized Path Rules**: All path permissions, modes, UIDs, and GIDs are centrally declared in `GLOBAL_PATH_RULES` in `src/PathRules.cpp`. Directory and file creation routines should use `FSAMakeDir` / `EnsureFSADir` and `FSACreateFile`.
  - **Directory Chown Timing (While Empty)**: A directory can ONLY have its owner changed while it is **STILL EMPTY** (immediately following `FSAMakeDir`). If child files or subdirectories are created inside a directory first, `FSA_ChangeOwner` on the directory fails with `FS_ERROR_NOT_EMPTY` (`-196632`).
  - **File Chown Timing (0 Bytes / Empty)**: A file can ONLY have its owner changed while it is **0 BYTES (EMPTY)**. If data is written to the file first, `FSA_ChangeOwner` fails with `FS_ERROR_NOT_EMPTY` (`-196632`). Always use the 5-step `FSACreateFileWithOwner(...)` helper: (1) `FSARemove` any pre-existing file so a fresh inode is allocated, (2) create a 0-byte file via `FSAOpenFileEx(..., "wb", mode, ...)` and close it, (3) `FSA_ChangeOwner` while the file is still 0 bytes/empty, (4) reopen with `"r+b"` and write payload, (5) `FSAChangeMode` to explicitly apply the final permission mode (e.g. `0x444` for setting.txt, `0x660` for system files).
- **Title UID and Group Allocation (`/sys/uid.sys` & TMD `groupId`)**:
  - `/sys/uid.sys` stores a packed binary table of 12-byte entries (`struct __attribute__((packed)) RawUidEntry { uint64_t titleId; uint32_t uid; };`).
  - **GID Resolution**: Title Group IDs cannot generally be derived from Title IDs. GID must come directly from the title's TMD (`tmd->groupId`). During installation, it is extracted from the in-memory TMD; during scanning or repair operations, it is read directly from `/vol/slccmpt01/title/<idHi>/<idLo>/content/title.tmd` on disk.
  - **System Menu Data Directory**: Uses GID `1` (`RuleGid::SYSTEM_MENU`). (On some stock systems GID is 0; since mode is `0x600`, group mismatch has no access impact).
  - **Access & Permission Tolerance (`FSA_IsPermissionAcceptable`)**: If the group mode bits and other mode bits are 0 (`(stat.mode & 0x0FF) == 0`, e.g. mode `0x600`), group membership grants no access anyway; therefore, a group mismatch is ignored if the owner UID and mode bits match.
  - Titles run unprivileged in user mode and cannot create `/data` or chown directories themselves; installers MUST create the `/data` directory and register the title in `/sys/uid.sys` during title installation for save data persistence.
  - `UID_Reconstruct` recovers `/sys/uid.sys` by scanning all `/vol/slccmpt01/title/*/*/data` directories for existing valid UIDs, preserving save data permissions without clearing data.


