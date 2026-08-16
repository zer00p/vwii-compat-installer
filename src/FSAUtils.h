#pragma once

#include <coreinit/filesystem_fsa.h>
#include <stddef.h>
#include <string>

// Stock SFFS permission modes (Wii U FSMode representation)
#define STOCK_MODE_SETTING_TXT    ((FSMode)0x444) // SFFS mode 0x55 (r--r--r--)
#define STOCK_MODE_SYSTEM_FILE    ((FSMode)0x660) // SFFS mode 0xf1 (rw-rw----)
#define STOCK_MODE_SYSTEM_DIR     ((FSMode)0x664) // SFFS mode 0xf6 (rwxrwxr--)
#define STOCK_MODE_CONTENT_DIR    ((FSMode)0x660) // SFFS mode 0xf2 (rwxrwx---)
#define STOCK_MODE_DATA_DIR       ((FSMode)0x600) // SFFS mode 0xc2 (rwx------)
#define STOCK_MODE_TICKET_SUBDIR  ((FSMode)0x000) // SFFS mode 0x02 (---------)

// Writes a buffer to an FSA file handle using a 0x40 aligned internal buffer
bool FSAWriteAligned(FSAClientHandle fsa, FSAFileHandle fd, const void* buffer, size_t size);

// Recursively creates all parent directories for a file path using FSA. Returns true on success.
bool EnsureFSAParentDir(FSAClientHandle fsaClient, const std::string& filePath);

// Recursively creates a directory and all parent directories using FSA. Returns true on success.
bool EnsureFSADir(FSAClientHandle fsaClient, const std::string& dirPath);

// Recursively removes a directory tree or file using FSA
bool FSARemoveTree(FSAClientHandle fsaClient, const std::string& path);

enum class UninstallResult {
    SUCCESS,
    NOT_PRESENT,
    FAILED
};

// Removes a file or directory tree, distinguishing between not present, success, and failure
UninstallResult FSARemovePathResult(FSAClientHandle fsaClient, const std::string& path, bool isDirectory = true);

// Changes ownership (UID and GID) of a file or directory via raw FSA IPC (ioctl 0x70)
FSError FSA_ChangeOwner(FSAClientHandle fsaClient, const std::string& path, uint32_t uid, uint32_t gid);

// Creates a directory, sets ownership (UID/GID) and mode while empty, returning the FSAMakeDir result
FSError FSAMakeDirWithOwner(FSAClientHandle fsaClient, const std::string& path, FSMode mode = STOCK_MODE_SYSTEM_DIR, uint32_t uid = 0, uint32_t gid = 0);

// Creates an empty file, sets ownership (UID/GID) and mode while empty (size 0), then writes payload
bool FSACreateFileWithOwner(FSAClientHandle fsaClient, const std::string& path, const void* buffer, size_t size, FSMode mode, uint32_t uid, uint32_t gid);


