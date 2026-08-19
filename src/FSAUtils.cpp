#include "FSAUtils.h"
#include "log.h"
#include <coreinit/ios.h>
#include <mbedtls/sha1.h>
#include <malloc.h>
#include <string.h>
#include <string>
#include <vector>

static std::string TruncatePathStart(const std::string& path, size_t maxLen = 28) {
    if (path.length() <= maxLen) {
        return path;
    }
    if (maxLen <= 3) {
        return path.substr(path.length() - maxLen);
    }
    return "..." + path.substr(path.length() - (maxLen - 3));
}

bool EnsureFSADir(FSAClientHandle fsaClient, const std::string& dirPath) {
    if (dirPath.empty()) return false;

    size_t start = 1;
    // Skip virtual mount points like "/vol/slccmpt01" or "/vol/external01"
    if (dirPath.rfind("/vol/", 0) == 0) {
        size_t mountSlash = dirPath.find('/', 5);
        if (mountSlash == std::string::npos) {
            return true; // The mount point itself already exists
        }
        start = mountSlash + 1;
    }

    // Create intermediate directories
    for (size_t pos = dirPath.find('/', start); pos != std::string::npos; pos = dirPath.find('/', pos + 1)) {
        std::string sub = dirPath.substr(0, pos);
        FSError res = FSAMakeDirWithOwner(fsaClient, sub, STOCK_MODE_SYSTEM_DIR, 0, 0);
        if (res != FS_ERROR_OK && res != FS_ERROR_ALREADY_EXISTS) {
            WUPI_Log("EnsureFSADir: Failed to create intermediate %s (%d)\n", sub.c_str(), res);
            return false;
        }
    }

    // Create final target directory
    FSError res = FSAMakeDirWithOwner(fsaClient, dirPath, STOCK_MODE_SYSTEM_DIR, 0, 0);
    if (res == FS_ERROR_OK || res == FS_ERROR_ALREADY_EXISTS) {
        return true;
    }
    WUPI_Log("EnsureFSADir: Failed to create target %s (%d)\n", dirPath.c_str(), res);
    return false;
}

bool EnsureFSAParentDir(FSAClientHandle fsaClient, const std::string& filePath) {
    size_t lastSlash = filePath.find_last_of('/');
    if (lastSlash == std::string::npos || lastSlash == 0) {
        return true;
    }

    return EnsureFSADir(fsaClient, filePath.substr(0, lastSlash));
}

bool FSAWriteAligned(FSAClientHandle fsa, FSAFileHandle fd, const void* buffer, size_t size) {
    if (size == 0) return true;
    
    const size_t CHUNK_SIZE = 256 * 1024; // 256KB chunks
    void* aligned_buf = memalign(0x40, CHUNK_SIZE);
    if (!aligned_buf) {
        WUPI_Log("Failed to allocate aligned chunk buffer\n");
        return false;
    }
    
    const uint8_t* ptr = (const uint8_t*)buffer;
    size_t remaining = size;
    
    while (remaining > 0) {
        size_t write_size = (remaining > CHUNK_SIZE) ? CHUNK_SIZE : remaining;
        memcpy(aligned_buf, ptr, write_size);
        
        int res = FSAWriteFile(fsa, aligned_buf, 1, write_size, fd, 0);
        if (res < 0 || (size_t)res != write_size) {
            WUPI_Log("FSAWriteFile failed: %d\n", res);
            free(aligned_buf);
            return false;
        }
        
        ptr += write_size;
        remaining -= write_size;
    }
    
    free(aligned_buf);
    return true;
}

bool FSARemoveTree(FSAClientHandle fsaClient, const std::string& path, bool keepRoot) {
    FSStat stat;
    if (FSAGetStat(fsaClient, path.c_str(), &stat) != FS_ERROR_OK) {
        return true;
    }

    bool allOk = true;
    FSADirectoryHandle dir;
    if (FSAOpenDir(fsaClient, path.c_str(), &dir) == FS_ERROR_OK) {
        FSADirectoryEntry* entry = (FSADirectoryEntry*)memalign(0x40, sizeof(FSADirectoryEntry));
        if (entry) {
            while (FSAReadDir(fsaClient, dir, entry) == FS_ERROR_OK) {
                if (strcmp(entry->name, ".") == 0 || strcmp(entry->name, "..") == 0) {
                    continue;
                }
                std::string subPath = path + "/" + entry->name;
                if (entry->info.flags & FS_STAT_DIRECTORY) {
                    if (!FSARemoveTree(fsaClient, subPath, false)) {
                        allOk = false;
                    }
                } else {
                    if (FSARemove(fsaClient, subPath.c_str()) != FS_ERROR_OK) {
                        allOk = false;
                    }
                }
            }
            free(entry);
        } else {
            allOk = false;
        }
        FSACloseDir(fsaClient, dir);
    } else {
        allOk = false;
    }
    if (keepRoot) {
        return allOk;
    }
    if (FSARemove(fsaClient, path.c_str()) != FS_ERROR_OK) {
        allOk = false;
    }
    return allOk;
}

UninstallResult FSARemovePathResult(FSAClientHandle fsaClient, const std::string& path, bool isDirectory) {
    FSStat stat;
    if (FSAGetStat(fsaClient, path.c_str(), &stat) != FS_ERROR_OK) {
        return UninstallResult::NOT_PRESENT;
    }
    bool ok = false;
    if (isDirectory) {
        ok = FSARemoveTree(fsaClient, path);
    } else {
        ok = (FSARemove(fsaClient, path.c_str()) == FS_ERROR_OK);
    }
    return ok ? UninstallResult::SUCCESS : UninstallResult::FAILED;
}

FSError FSA_ChangeOwner(FSAClientHandle fsaClient, const std::string& path, uint32_t uid, uint32_t gid) {
    // FSARequest is 0x520 bytes. FSAResponse is 0x293 bytes.
    // Both must be 0x40-aligned for IOS IPC.
    FSARequest* request = (FSARequest*)memalign(0x40, sizeof(FSARequest));
    FSAResponse* response = (FSAResponse*)memalign(0x40, sizeof(FSAResponse));
    if (!request || !response) {
        if (request) free(request);
        if (response) free(response);
        return (FSError)-1;
    }

    memset(request, 0, sizeof(FSARequest));
    memset(response, 0, sizeof(FSAResponse));

    // Fill the changeOwner request using the wut-defined struct layout:
    //   FSARequestChangeOwner.path   at offset 0x000 (relative to union at 0x04)
    //   FSARequestChangeOwner.owner  at offset 0x284
    //   FSARequestChangeOwner.group  at offset 0x28C
    strncpy(request->changeOwner.path, path.c_str(), FS_MAX_PATH - 1);
    request->changeOwner.owner = uid;
    request->changeOwner.group = gid;

    // FSAClientHandle is an IOS handle to /dev/fsa.
    // FSA_COMMAND_CHANGE_OWNER = 0x70
    int res = IOS_Ioctl(fsaClient,
                        FSA_COMMAND_CHANGE_OWNER,
                        request, sizeof(FSARequest),
                        response, sizeof(FSAResponse));

    free(request);
    free(response);
    return (FSError)res;
}

FSError FSAMakeDirWithOwner(FSAClientHandle fsaClient, const std::string& path, FSMode mode, uint32_t uid, uint32_t gid) {
    FSError ret = FSAMakeDir(fsaClient, path.c_str(), mode);
    if (ret == FS_ERROR_OK) {
        FSError ownRes = FSA_ChangeOwner(fsaClient, path, uid, gid);
        if (ownRes != FS_ERROR_OK) {
            WUPI_Log("FSAMakeDir: Owner err %d: %s\n", ownRes, TruncatePathStart(path).c_str());
            return ownRes;
        }
    }
    return ret;
}

bool FSACreateFileWithOwner(FSAClientHandle fsaClient, const std::string& path, const void* buffer, size_t size, FSMode mode, uint32_t uid, uint32_t gid) {
    // 1. Remove old file so a fresh inode is allocated
    FSARemove(fsaClient, path.c_str());

    // 2. Create empty file (0 bytes) with permissive write mode initially
    FSAFileHandle fd = 0;
    int res = FSAOpenFileEx(fsaClient, path.c_str(), "wb", (FSMode)0x666, FS_OPEN_FLAG_NONE, 0, &fd);
    if (res != FS_ERROR_OK) {
        WUPI_Log("FSACreateFile: Open err %d: %s\n", res, TruncatePathStart(path).c_str());
        return false;
    }
    FSACloseFile(fsaClient, fd);
    fd = 0;

    // 3. Set ownership while the file is 0 bytes (empty)
    FSError ownRes = FSA_ChangeOwner(fsaClient, path, uid, gid);
    if (ownRes != FS_ERROR_OK) {
        WUPI_Log("FSACreateFile: Owner err %d: %s\n", ownRes, TruncatePathStart(path).c_str());
        return false;
    }

    // 4. Open in "r+b" mode to write payload (since mode is still 0x666, write is allowed for Cafe OS)
    if (size > 0 && buffer != nullptr) {
        res = FSAOpenFileEx(fsaClient, path.c_str(), "r+b", (FSMode)0x666, FS_OPEN_FLAG_NONE, 0, &fd);
        if (res != FS_ERROR_OK) {
            WUPI_Log("FSACreateFile: WriteOpen err %d: %s\n", res, TruncatePathStart(path).c_str());
            return false;
        }

        bool writeOk = FSAWriteAligned(fsaClient, fd, buffer, size);
        FSACloseFile(fsaClient, fd);
        if (!writeOk) {
            WUPI_Log("FSACreateFile: Write payload failed: %s\n", TruncatePathStart(path).c_str());
            return false;
        }
    }

    // 5. Finally, set requested permission mode (e.g. 0x444 read-only or 0x660) after data is written
    FSError modeRes = FSAChangeMode(fsaClient, path.c_str(), mode);
    if (modeRes != FS_ERROR_OK) {
        WUPI_Log("FSACreateFile: Mode err %d: %s\n", modeRes, TruncatePathStart(path).c_str());
        return false;
    }

    return true;
}

extern FSAClientHandle fsaClient;

bool ReadFileToBuffer(const std::string& path, uint8_t** outBuf, uint32_t* outSize) {
    if (!outBuf || !outSize) return false;
    *outBuf = nullptr;
    *outSize = 0;

    FSAFileHandle fd = 0;
    if (FSAOpenFileEx(fsaClient, path.c_str(), "rb", (FSMode)0, FS_OPEN_FLAG_NONE, 0, &fd) != FS_ERROR_OK) {
        return false;
    }

    FSStat stat;
    if (FSAGetStatFile(fsaClient, fd, &stat) != FS_ERROR_OK) {
        FSACloseFile(fsaClient, fd);
        return false;
    }
    uint32_t size = stat.size;

    uint8_t* buf = (uint8_t*)memalign(0x40, (size + 0x3F) & ~0x3F);
    if (!buf) {
        FSACloseFile(fsaClient, fd);
        return false;
    }

    if (FSAReadFile(fsaClient, buf, 1, size, fd, FSA_READ_FLAG_NONE) != (int32_t)size) {
        free(buf);
        FSACloseFile(fsaClient, fd);
        return false;
    }

    FSACloseFile(fsaClient, fd);
    *outBuf = buf;
    *outSize = size;
    return true;
}

bool WriteBufferToFile(const std::string& path, const uint8_t* buf, uint32_t size, FSMode mode, uint32_t uid, uint32_t gid) {
    return FSACreateFileWithOwner(fsaClient, path.c_str(), buf, size, mode, uid, gid);
}

bool FSAGetFileSha1(FSAClientHandle fsa, const std::string& path, uint8_t outHash[20], uint64_t expectedSize) {
    if (!outHash) return false;

    FSAFileHandle fd = 0;
    if (FSAOpenFileEx(fsa, path.c_str(), "rb", (FSMode)0, FS_OPEN_FLAG_NONE, 0, &fd) != FS_ERROR_OK) {
        return false;
    }

    FSStat stat;
    if (FSAGetStatFile(fsa, fd, &stat) != FS_ERROR_OK || stat.size != expectedSize) {
        FSACloseFile(fsa, fd);
        return false;
    }

    mbedtls_sha1_context ctx;
    mbedtls_sha1_init(&ctx);
    mbedtls_sha1_starts_ret(&ctx);

    const size_t CHUNK_SIZE = 64 * 1024;
    uint8_t* buf = (uint8_t*)memalign(0x40, CHUNK_SIZE);
    if (!buf) {
        FSACloseFile(fsa, fd);
        mbedtls_sha1_free(&ctx);
        return false;
    }

    uint64_t remaining = expectedSize;
    bool ok = true;
    while (remaining > 0) {
        size_t toRead = (remaining > CHUNK_SIZE) ? CHUNK_SIZE : (size_t)remaining;
        int readBytes = FSAReadFile(fsa, buf, 1, toRead, fd, FSA_READ_FLAG_NONE);
        if (readBytes != (int)toRead) {
            ok = false;
            break;
        }
        mbedtls_sha1_update_ret(&ctx, buf, toRead);
        remaining -= toRead;
    }

    free(buf);
    FSACloseFile(fsa, fd);

    if (ok) {
        mbedtls_sha1_finish_ret(&ctx, outHash);
    }
    mbedtls_sha1_free(&ctx);
    return ok;
}

bool FSACheckFileSha1(FSAClientHandle fsa, const std::string& path, const uint8_t expectedHash[20], uint64_t expectedSize) {
    if (!expectedHash) return false;
    uint8_t actualHash[20];
    if (!FSAGetFileSha1(fsa, path, actualHash, expectedSize)) {
        return false;
    }
    return (memcmp(actualHash, expectedHash, 20) == 0);
}

bool FSA_InitStockRootDirs(FSAClientHandle fsa) {
    // Stock root directories with stock modes and UID 0, GID 0
    const struct {
        const char* path;
        FSMode mode;
    } rootDirs[] = {
        {"/vol/slccmpt01/sys",     STOCK_MODE_CONTENT_DIR}, // 0x660 (SFFS 0xf2)
        {"/vol/slccmpt01/title",   STOCK_MODE_SYSTEM_DIR},  // 0x664 (SFFS 0xf6)
        {"/vol/slccmpt01/ticket",  STOCK_MODE_CONTENT_DIR}, // 0x660 (SFFS 0xf2)
        {"/vol/slccmpt01/shared1", STOCK_MODE_CONTENT_DIR}, // 0x660 (SFFS 0xf2)
        {"/vol/slccmpt01/shared2", STOCK_MODE_SHARED2_DIR}, // 0x777 (SFFS 0xfe)
        {"/vol/slccmpt01/content", STOCK_MODE_CONTENT_DIR}, // 0x660 (SFFS 0xf2)
        {"/vol/slccmpt01/tmp",     STOCK_MODE_TMP_DIR},      // 0x777 (SFFS 0xfe)
        {"/vol/slccmpt01/import",  STOCK_MODE_CONTENT_DIR}, // 0x660 (SFFS 0xf2)
    };

    bool allOk = true;
    for (const auto& d : rootDirs) {
        FSError res = FSAMakeDirWithOwner(fsa, d.path, d.mode, 0, 0);
        if (res == FS_ERROR_ALREADY_EXISTS) {
            FSStat stat;
            if (FSAGetStat(fsa, d.path, &stat) == FS_ERROR_OK) {
                if (stat.owner != 0 || stat.group != 0) {
                    FSError ownRes = FSA_ChangeOwner(fsa, d.path, 0, 0);
                    if (ownRes != FS_ERROR_OK) {
                        WUPI_Log("FSA_InitStockRootDirs: Owner err %d: %s\n", ownRes, d.path);
                        allOk = false;
                    }
                }
                if (stat.mode != d.mode) {
                    FSError modeRes = FSAChangeMode(fsa, d.path, d.mode);
                    if (modeRes != FS_ERROR_OK) {
                        WUPI_Log("FSA_InitStockRootDirs: Mode err %d: %s\n", modeRes, d.path);
                        allOk = false;
                    }
                }
            }
        } else if (res != FS_ERROR_OK) {
            WUPI_Log("FSA_InitStockRootDirs: Failed to create %s (%d)\n", d.path, res);
            allOk = false;
        }
    }
    return allOk;
}

bool FSA_IsFilePermissionAcceptable(const FSStat& stat, FSMode stockMode, uint32_t expectedUid, uint32_t expectedGid) {
    // 1. Ownership matches expected
    if (stat.owner == expectedUid && stat.group == expectedGid) {
        if (stat.mode == stockMode) {
            return true;
        }
        // Match both execute-bit and non-execute-bit variants
        uint32_t statRW = stat.mode & 0x666;
        uint32_t stockRW = stockMode & 0x666;
        if (statRW == stockRW) {
            return true;
        }
    }
    // 2. Permissive 0x666 / 0x777 (or Other has read & write, e.g. restored via vWii NAND Restorer)
    if (stat.mode == 0x666 || stat.mode == 0x777 || (stat.mode & 0x006) == 0x006) {
        return true;
    }
    // 3. For files where Other only needs read access (e.g. cert.sys 0x664, setting.txt 0x444)
    if ((stockMode & 0x004) != 0 && (stat.mode & 0x004) != 0) {
        if (stat.owner == expectedUid && stat.group == expectedGid) {
            return true;
        }
    }
    return false;
}

bool FSA_IsDirPermissionAcceptable(const FSStat& stat, FSMode stockMode, uint32_t expectedUid, uint32_t expectedGid) {
    // 1. Ownership matches expected
    if (stat.owner == expectedUid && stat.group == expectedGid) {
        if (stat.mode == stockMode) {
            return true;
        }
        // Match both execute-bit and non-execute-bit variants (0x700 vs 0x600, 0x770 vs 0x660, 0x775/0x774 vs 0x664)
        uint32_t statRW = stat.mode & 0x666;
        uint32_t stockRW = stockMode & 0x666;
        if (statRW == stockRW) {
            return true;
        }
    }
    // 2. Permissive 0x777 / 0x666 (or Other has rwx / rw, e.g. restored via vWii NAND Restorer)
    if (stat.mode == 0x777 || stat.mode == 0x666 || (stat.mode & 0x007) == 0x007 || (stat.mode & 0x006) == 0x006) {
        return true;
    }
    // 3. For directories where Other only needs read access (e.g. 0x775, 0x774, 0x664)
    if ((stockMode & 0x004) != 0 && (stat.mode & 0x004) != 0) {
        if (stat.owner == expectedUid && stat.group == expectedGid) {
            return true;
        }
    }
    return false;
}
