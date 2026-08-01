#include "FSAUtils.h"
#include "log.h"
#include <malloc.h>
#include <string.h>
#include <string>


void EnsureFSADirectory(FSAClientHandle fsaClient, const char* path) {
    char temp[256];
    strncpy(temp, path, sizeof(temp));
    temp[sizeof(temp)-1] = '\0';
    for (char* p = temp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            FSAMakeDir(fsaClient, temp, (FSMode)(FS_MODE_READ_OWNER | FS_MODE_WRITE_OWNER | FS_MODE_EXEC_OWNER)); // Ignore errors, as it might already exist
            *p = '/';
        }
    }
}

bool FSAWriteAligned(FSAClientHandle fsa, FSAFileHandle fd, const void* buffer, size_t size) {
    if (size == 0) return true;
    
    const size_t CHUNK_SIZE = 256 * 1024; // 256KB chunks
    void* aligned_buf = memalign(0x40, CHUNK_SIZE);
    if (!aligned_buf) {
        WUPI_Log("Failed to allocate aligned chunk buffer\n");
        return false;
    }
    
    uint8_t* ptr = (uint8_t*)buffer;
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

bool FSARemoveTree(FSAClientHandle fsaClient, const char* path) {
    FSADirectoryHandle dir;
    if (FSAOpenDir(fsaClient, path, &dir) == FS_ERROR_OK) {
        FSADirectoryEntry* entry = (FSADirectoryEntry*)memalign(0x40, sizeof(FSADirectoryEntry));
        if (entry) {
            while (FSAReadDir(fsaClient, dir, entry) == FS_ERROR_OK) {
                if (strcmp(entry->name, ".") == 0 || strcmp(entry->name, "..") == 0) {
                    continue;
                }
                std::string subPath = std::string(path) + "/" + entry->name;
                if (entry->info.flags & FS_STAT_DIRECTORY) {
                    FSARemoveTree(fsaClient, subPath.c_str());
                } else {
                    FSARemove(fsaClient, subPath.c_str());
                }
            }
            free(entry);
        }
        FSACloseDir(fsaClient, dir);
    }
    return (FSARemove(fsaClient, path) == FS_ERROR_OK);
}

