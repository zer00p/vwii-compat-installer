#pragma once

#include <coreinit/filesystem_fsa.h>
#include <stddef.h>
#include <string>
#include <string_view>

// vWii SLCCMPT mount point prefix
inline constexpr std::string_view VWII_MOUNT_POINT = "/vol/slccmpt01";

// Returns the full FSA path by prepending /vol/slccmpt01 if not already present
inline std::string VwiiFsaPath(std::string_view relPath) {
    if (relPath.starts_with(VWII_MOUNT_POINT)) {
        return std::string(relPath);
    }
    if (relPath.empty()) {
        return std::string(VWII_MOUNT_POINT);
    }
    if (relPath.front() == '/') {
        return std::string(VWII_MOUNT_POINT) + std::string(relPath);
    }
    return std::string(VWII_MOUNT_POINT) + "/" + std::string(relPath);
}

// Strips /vol/slccmpt01 prefix for display/logging if present
inline std::string_view VwiiCleanPath(std::string_view fullPath) {
    if (fullPath.starts_with(VWII_MOUNT_POINT)) {
        std::string_view stripped = fullPath.substr(VWII_MOUNT_POINT.size());
        return stripped.empty() ? "/" : stripped;
    }
    return fullPath;
}

// Stock SFFS permission modes (Wii U FSMode representation - pure read/write, no execute bits)
#define STOCK_MODE_SETTING_TXT    ((FSMode)0x444) // SFFS mode 0x55 (r--r--r--)
#define STOCK_MODE_SYSTEM_FILE    ((FSMode)0x660) // SFFS mode 0xf1 (rw-rw----)
#define STOCK_MODE_CERT_SYS       ((FSMode)0x664) // SFFS mode 0xf5 (rw-rw-r--)
#define STOCK_MODE_SYSTEM_DIR     ((FSMode)0x664) // SFFS mode 0xf6 (rw-rw-r--)
#define STOCK_MODE_CONTENT_DIR    ((FSMode)0x660) // SFFS mode 0xf2 (rw-rw----)
#define STOCK_MODE_DATA_DIR       ((FSMode)0x600) // SFFS mode 0xc2 (rw-------)
#define STOCK_MODE_TICKET_SUBDIR  ((FSMode)0x000) // SFFS mode 0x02 (---------)
#define STOCK_MODE_SHARED2_DIR    ((FSMode)0x666) // SFFS mode 0xfe (rw-rw-rw-)
#define STOCK_MODE_TMP_DIR        ((FSMode)0x666) // SFFS mode 0xfe (rw-rw-rw-)

// Stock root directory definition
struct StockRootDir {
    const char* path; // Stored without mount prefix, e.g. "/sys"
    FSMode mode;      // Expected permission mode
};

inline constexpr StockRootDir STOCK_ROOT_DIRS[] = {
    {"/sys",     STOCK_MODE_CONTENT_DIR},
    {"/title",   STOCK_MODE_SYSTEM_DIR},
    {"/ticket",  STOCK_MODE_CONTENT_DIR},
    {"/shared1", STOCK_MODE_CONTENT_DIR},
    {"/shared2", STOCK_MODE_SHARED2_DIR},
    {"/tmp",     STOCK_MODE_TMP_DIR},
    {"/import",  STOCK_MODE_CONTENT_DIR},
};

// Writes a buffer to an FSA file handle using a 0x40 aligned internal buffer
bool FSAWriteAligned(FSAClientHandle fsa, FSAFileHandle fd, const void* buffer, size_t size);

// Recursively creates all parent directories for a file path using FSA. Returns true on success.
bool EnsureFSAParentDir(FSAClientHandle fsaClient, const std::string& filePath);

// Recursively creates a directory and all parent directories using FSA. Returns true on success.
bool EnsureFSADir(FSAClientHandle fsaClient, const std::string& dirPath);

// Recursively removes a directory tree or file using FSA. Set keepRoot=true to keep the root directory itself.
bool FSARemoveTree(FSAClientHandle fsaClient, const std::string& path, bool keepRoot = false);

enum class UninstallResult {
    SUCCESS,
    NOT_PRESENT,
    FAILED
};

// Removes a file or directory tree, distinguishing between not present, success, and failure
UninstallResult FSARemovePathResult(FSAClientHandle fsaClient, const std::string& path, bool isDirectory = true);

// Changes ownership (UID and GID) of a file or directory via raw FSA IPC (ioctl 0x70)
FSError FSA_ChangeOwner(FSAClientHandle fsaClient, const std::string& path, uint32_t uid, uint32_t gid);

// Creates a directory, sets ownership (UID/GID) while empty, returning the FSAMakeDir result
FSError FSAMakeDirWithOwner(FSAClientHandle fsaClient, const std::string& path, FSMode mode = STOCK_MODE_SYSTEM_DIR, uint32_t uid = 0, uint32_t gid = 0);

// Creates an empty file, sets ownership (UID/GID) while empty (size 0), then writes payload
bool FSACreateFileWithOwner(FSAClientHandle fsaClient, const std::string& path, const void* buffer, size_t size, FSMode mode, uint32_t uid, uint32_t gid);

// Reads an entire file into a 0x40-aligned memory buffer using FSA. The caller is responsible for free()-ing outBuf.
bool ReadFileToBuffer(const std::string& path, uint8_t** outBuf, uint32_t* outSize);

// Writes a buffer to a file on FSA setting proper ownership and permission mode
bool WriteBufferToFile(const std::string& path, const uint8_t* buf, uint32_t size, FSMode mode = STOCK_MODE_SYSTEM_FILE, uint32_t uid = 0, uint32_t gid = 0);

// Computes the SHA-1 hash of a file on FSA using 64KB aligned streaming buffers. Returns true if file matches expectedSize and was hashed successfully.
bool FSAGetFileSha1(FSAClientHandle fsa, const std::string& path, uint8_t outHash[20], uint64_t expectedSize);

// Checks if a file exists on FSA, matches expectedSize, and has the matching SHA-1 hash.
bool FSACheckFileSha1(FSAClientHandle fsa, const std::string& path, const uint8_t expectedHash[20], uint64_t expectedSize);

// Re-creates standard stock SLCCMPT root directories with correct ownership and permission modes
bool FSA_InitStockRootDirs(FSAClientHandle fsa);

// Evaluates whether permissions are acceptable (stock or permissive like 0x666 from vWii NAND Restorer)
bool FSA_IsPermissionAcceptable(const FSStat& stat, FSMode stockMode, uint32_t expectedUid = 0, uint32_t expectedGid = 0);
