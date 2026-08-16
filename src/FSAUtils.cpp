#include "FSAUtils.h"
#include "log.h"
#include <coreinit/ios.h>
#include <malloc.h>
#include <string.h>
#include <string>

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

bool FSARemoveTree(FSAClientHandle fsaClient, const std::string& path) {
    FSStat stat;
    if (FSAGetStat(fsaClient, path.c_str(), &stat) != FS_ERROR_OK) {
        return true;
    }

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
                    FSARemoveTree(fsaClient, subPath);
                } else {
                    FSARemove(fsaClient, subPath.c_str());
                }
            }
            free(entry);
        }
        FSACloseDir(fsaClient, dir);
    }
    return (FSARemove(fsaClient, path.c_str()) == FS_ERROR_OK);
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
        FSError modeRes = FSAChangeMode(fsaClient, path.c_str(), mode);
        FSError ownRes = FSA_ChangeOwner(fsaClient, path, uid, gid);
        if (modeRes != FS_ERROR_OK || ownRes != FS_ERROR_OK) {
            WUPI_Log("FSAMakeDirWithOwner: Setting mode/owner on %s failed (mode=%d, own=%d)\n",
                     path.c_str(), modeRes, ownRes);
        }
    }
    return ret;
}

bool FSACreateFileWithOwner(FSAClientHandle fsaClient, const std::string& path, const void* buffer, size_t size, FSMode mode, uint32_t uid, uint32_t gid) {
    // 1. Remove old file so a fresh inode is allocated
    FSARemove(fsaClient, path.c_str());

    // 2. Create empty file (0 bytes)
    FSAFileHandle fd = 0;
    int res = FSAOpenFileEx(fsaClient, path.c_str(), "wb", mode, FS_OPEN_FLAG_NONE, 0, &fd);
    if (res != FS_ERROR_OK) {
        WUPI_Log("FSACreateFileWithOwner: Failed to create empty %s: %d\n", path.c_str(), res);
        return false;
    }
    FSACloseFile(fsaClient, fd);
    fd = 0;

    // 3. Set ownership and mode while the file is 0 bytes (empty)
    FSError ownRes = FSA_ChangeOwner(fsaClient, path, uid, gid);
    FSError modeRes = FSAChangeMode(fsaClient, path.c_str(), mode);
    if (ownRes != FS_ERROR_OK || modeRes != FS_ERROR_OK) {
        WUPI_Log("FSACreateFileWithOwner: ChangeOwner on %s returned own=%d, mode=%d\n", path.c_str(), ownRes, modeRes);
    }

    // 4. Open in "r+b" mode to write payload
    res = FSAOpenFileEx(fsaClient, path.c_str(), "r+b", mode, FS_OPEN_FLAG_NONE, 0, &fd);
    if (res != FS_ERROR_OK) {
        WUPI_Log("FSACreateFileWithOwner: Failed to open %s for writing: %d\n", path.c_str(), res);
        return false;
    }

    bool writeOk = FSAWriteAligned(fsaClient, fd, buffer, size);
    FSACloseFile(fsaClient, fd);

    return writeOk;
}
