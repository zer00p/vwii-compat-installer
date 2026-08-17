/* Wii title installer for Wii U Mode
 *   Copyright (C) 2021  TheLordScruffy
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "installer.h"
#include "FSAUtils.h"
#include "uid_sys.h"
#include "log.h"
#include <coreinit/filesystem_fsa.h>
#include <stdio.h>
#include <string.h>
#include <format>
#include <sys/stat.h>
#include <malloc.h>
#include "EndianUtils.h"
#include "MenuUtils.h"

#define IOS_SUCCESS             FS_ERROR_OK

#define CINS_PATH_LEN           (sizeof("/vol/slccmpt01") + 63)

#define CINS_TRY(c)                        \
    do { if (!(c)) {                       \
        WUPI_Log("Failed, please exit and try again\n"); \
        goto error;                        \
    } } while (0)

extern FSAClientHandle fsaClient;

int32_t FindSharedContentIndex(const Sha1Hash& expectedHash) {
    FSAFileHandle fd = 0;
    char path[] = "/vol/slccmpt01/shared1/content.map";

    if (FSAOpenFileEx(fsaClient, path, "r", (FSMode) 0x666, FS_OPEN_FLAG_NONE, 0, &fd) != FS_ERROR_OK) {
        return -1;
    }

    ContentMapEntry* entry = (ContentMapEntry*)memalign(0x40, sizeof(ContentMapEntry));
    if (!entry) {
        FSACloseFile(fsaClient, fd);
        return -1;
    }

    int32_t currentIndex = 0;
    while (true) {
        int readRes = FSAReadFile(fsaClient, entry, sizeof(ContentMapEntry), 1, fd, 0);
        if (readRes != 1) {
            break;
        }

        if (entry->hash == expectedHash) {
            FSACloseFile(fsaClient, fd);
            free(entry);
            return currentIndex;
        }
        currentIndex++;
    }

    FSACloseFile(fsaClient, fd);
    free(entry);
    return -1;
}

int32_t FindSharedContentIndex(const uint8_t* expectedHash) {
    if (!expectedHash) return -1;
    return FindSharedContentIndex(*reinterpret_cast<const Sha1Hash*>(expectedHash));
}

static int32_t GetSharedContentIndex(const uint8_t* expectedHash) {
    int32_t existingIndex = FindSharedContentIndex(expectedHash);
    if (existingIndex >= 0) {
        return existingIndex;
    }

    FSAFileHandle fd = 0;
    char path[] = "/vol/slccmpt01/shared1/content.map";

    FSAMakeDirWithOwner(fsaClient, "/vol/slccmpt01/shared1", STOCK_MODE_CONTENT_DIR, 0, 0);

    if (FSAOpenFileEx(fsaClient, path, "r+", STOCK_MODE_SYSTEM_FILE, FS_OPEN_FLAG_NONE, 0, &fd) != FS_ERROR_OK) {
        if (FSAOpenFileEx(fsaClient, path, "w+", STOCK_MODE_SYSTEM_FILE, FS_OPEN_FLAG_NONE, 0, &fd) != FS_ERROR_OK) {
            WUPI_Log("Failed to open content.map\n");
            return -1;
        }
        FSError mRes = FSAChangeMode(fsaClient, path, STOCK_MODE_SYSTEM_FILE);
        FSError oRes = FSA_ChangeOwner(fsaClient, path, 0, 0);
        if (mRes != FS_ERROR_OK || oRes != FS_ERROR_OK) {
            WUPI_Log("Warning: content.map mode/owner (m=%d, o=%d)\n", mRes, oRes);
        }
    }

    ContentMapEntry* entry = (ContentMapEntry*)memalign(0x40, sizeof(ContentMapEntry));
    if (!entry) {
        FSACloseFile(fsaClient, fd);
        return -1;
    }

    int32_t freeIndex = -1;
    int32_t currentIndex = 0;

    while (true) {
        int readRes = FSAReadFile(fsaClient, entry, sizeof(ContentMapEntry), 1, fd, 0);
        if (readRes <= 0) {
            break;
        }

        if (freeIndex < 0 && entry->name[0] == '\0') {
            freeIndex = currentIndex;
        }

        currentIndex++;
    }

    if (freeIndex < 0) {
        freeIndex = currentIndex;
    }

    std::format_to_n(entry->name, sizeof(entry->name), "{:08x}", freeIndex);
    memcpy(entry->hash.data(), expectedHash, 20);

    FSError setPosRes = FSASetPosFile(fsaClient, fd, freeIndex * sizeof(ContentMapEntry));
    if (setPosRes != FS_ERROR_OK) {
        WUPI_Log("Failed to set pos in content.map\n");
        free(entry);
        FSACloseFile(fsaClient, fd);
        return -1;
    }

    int writeRes = FSAWriteFile(fsaClient, entry, sizeof(ContentMapEntry), 1, fd, 0);
    free(entry);
    FSACloseFile(fsaClient, fd);

    if (writeRes <= 0) {
        WUPI_Log("Failed to write to content.map\n");
        return -1;
    }

    return freeIndex;
}

int32_t CINS_Install(uint64_t titleId, const TitleTicket *ticket, uint32_t ticket_size, const TitleTmd *tmd,
                     uint32_t tmd_size, const CINS_Content *contents,
                     uint16_t numContents) {
    FSError ret = FS_ERROR_OK;

    char path[CINS_PATH_LEN], pathd[CINS_PATH_LEN];
    char titlePath[CINS_PATH_LEN], ticketPath[CINS_PATH_LEN],
            ticketFolder[CINS_PATH_LEN];

    uint32_t idHi = (uint32_t)(titleId >> 32);
    uint32_t idLo = (uint32_t)(titleId & 0xFFFFFFFF);

    uint32_t tmdPayloadOffset = GetPayloadOffset((const uint8_t*)tmd);

    WUPI_Log("Starting install\n");

    snprintf(titlePath, CINS_PATH_LEN, "/vol/slccmpt01/title/%08x/%08x", idHi, idLo);
    snprintf(path, CINS_PATH_LEN, "/vol/slccmpt01/title/%08x", idHi);
    snprintf(ticketPath, CINS_PATH_LEN, "/vol/slccmpt01/ticket/%08x/%08x.tik", idHi, idLo);
    snprintf(ticketFolder, CINS_PATH_LEN, "/vol/slccmpt01/ticket/%08x", idHi);

    WUPI_Log("Writing ticket...\n");
    {
        EnsureFSADir(fsaClient, "/vol/slccmpt01/ticket");
        ret = FSAMakeDirWithOwner(fsaClient, ticketFolder, STOCK_MODE_TICKET_SUBDIR, 0, 0);
        if (ret == FS_ERROR_OK || ret == FS_ERROR_ALREADY_EXISTS) {
            CINS_TRY(FSACreateFileWithOwner(fsaClient, ticketPath, ticket, ticket_size, STOCK_MODE_SYSTEM_FILE, 0, 0));
            ret = FS_ERROR_OK;
        }

        CINS_TRY(ret == FS_ERROR_OK); // ret == 0
    }

    WUPI_Log("Creating title directory...\n");
    {
        /* Create the title directory if it doesn't already exist. The first
         * word (type) should exist, but the second one (the unique title)
         * shouldn't unless there is save data. */
        EnsureFSADir(fsaClient, "/vol/slccmpt01/title");
        ret = FSAMakeDirWithOwner(fsaClient, path, STOCK_MODE_SYSTEM_DIR, 0, 0);
        if (ret == FS_ERROR_OK || ret == FS_ERROR_ALREADY_EXISTS) {
            ret = FSAMakeDirWithOwner(fsaClient, titlePath, STOCK_MODE_SYSTEM_DIR, 0, 0);
            if (ret == FS_ERROR_ALREADY_EXISTS) {
                /* The title is already installed, delete content but preserve
                 * the data directory. */
                WUPI_Log(
                        "Title directory already exists, deleting content...\n");
                snprintf(path, CINS_PATH_LEN, "/vol/slccmpt01/title/%08x/%08x/content",
                         idHi, idLo);
                ret = FSARemove(fsaClient, path);
                if (ret == FS_ERROR_OK || ret == FS_ERROR_NOT_FOUND)
                    ret = FS_ERROR_OK;
            }
        }

        CINS_TRY(ret == FS_ERROR_OK); // ret == 0

        /* Ensure the title's data directory exists with correct Title UID and TMD Group ID */
        uint16_t groupId = Read16BE((const uint8_t*)tmd + tmdPayloadOffset + 0x98);
        uint32_t titleUid = UID_GetOrCreate(fsaClient, titleId);

        strncpy(pathd, titlePath, CINS_PATH_LEN);
        strncat(pathd, "/data", CINS_PATH_LEN - 1);
        ret = FSAMakeDirWithOwner(fsaClient, pathd, STOCK_MODE_DATA_DIR, titleUid, groupId);
        if (ret != FS_ERROR_OK && ret != FS_ERROR_ALREADY_EXISTS) {
            WUPI_Log("Failed to create the data directory, ret = %d\n", ret);
            goto error;
        }

        strncpy(pathd, titlePath, CINS_PATH_LEN);
        strncat(pathd, "/content", CINS_PATH_LEN - 1);
        ret = FSAMakeDirWithOwner(fsaClient, pathd, STOCK_MODE_CONTENT_DIR, 0, 0);
        if (ret != FS_ERROR_OK && ret != FS_ERROR_ALREADY_EXISTS) {
            WUPI_Log("Failed to create the content directory, ret = %d\n", ret);
            goto error;
        }
    }

    WUPI_Log("Writing TMD...\n");
    {
        /* pathd should be the content directory */
        strncpy(path, pathd, CINS_PATH_LEN);
        strncat(path, "/title.tmd", CINS_PATH_LEN - 1);

        CINS_TRY(FSACreateFileWithOwner(fsaClient, path, tmd, tmd_size, STOCK_MODE_SYSTEM_FILE, 0, 0));
    }

    WUPI_Log("Writing contents...\n");
    {
        for (uint16_t i = 0; i < numContents; i++) {
            uint32_t recordOffset = tmdPayloadOffset + 0xA4 + (i * 36);
            uint32_t cId = Read32BE((const uint8_t*)tmd + recordOffset);
            uint16_t cType = Read16BE((const uint8_t*)tmd + recordOffset + 6);
            uint64_t cSize = Read64BE((const uint8_t*)tmd + recordOffset + 8);

            if ((cType & 0x8000) != 0) {
                int32_t sharedIndex = GetSharedContentIndex((const uint8_t*)tmd + recordOffset + 0x10);
                if (sharedIndex < 0) {
                    WUPI_Log("Failed to get shared content index for content %08x\n", cId);
                    goto error;
                }
                
                snprintf(path, CINS_PATH_LEN,
                         "/vol/slccmpt01/shared1/%08x.app", sharedIndex);

                FSAFileHandle testFd;
                if (FSAOpenFileEx(fsaClient, path, "r", STOCK_MODE_SYSTEM_FILE, FS_OPEN_FLAG_NONE, 0, &testFd) == FS_ERROR_OK) {
                    bool matches = true;
                    const uint32_t chunkSize = 64 * 1024;
                    void* chunkBuf = memalign(0x40, chunkSize);
                    if (chunkBuf) {
                        uint64_t offset = 0;
                        while (offset < cSize) {
                            uint32_t toRead = (uint32_t)((cSize - offset > chunkSize) ? chunkSize : (cSize - offset));
                            int readRes = FSAReadFile(fsaClient, chunkBuf, toRead, 1, testFd, 0);
                            if (readRes != 1) {
                                matches = false;
                                break;
                            }
                            if (memcmp(chunkBuf, (const uint8_t*)contents[i].data + offset, toRead) != 0) {
                                matches = false;
                                break;
                            }
                            offset += toRead;
                        }
                        
                        if (matches) {
                            int extraRead = FSAReadFile(fsaClient, chunkBuf, 1, 1, testFd, 0);
                            if (extraRead > 0) {
                                matches = false;
                            }
                        }
                        free(chunkBuf);
                    } else {
                        matches = false;
                    }

                    FSACloseFile(fsaClient, testFd);

                    if (matches) {
                        continue;
                    }
                    
                    WUPI_Log("Warning: Shared content %08x exists but differs!\n", cId);
                    WUPI_Log("Press A to reinstall it, B to keep existing.\n");
                    if (!WaitPrompt()) {
                        continue;
                    }
                }
            } else {
                snprintf(path, CINS_PATH_LEN,
                         "/vol/slccmpt01/title/%08x/%08x/content/%08x.app", idHi,
                         idLo, cId);
            }

            EnsureFSAParentDir(fsaClient, path);
            CINS_TRY(FSACreateFileWithOwner(fsaClient, path, contents[i].data, cSize, STOCK_MODE_SYSTEM_FILE, 0, 0));
        }
    }
    ret = IOS_SUCCESS;
    WUPI_Log("Install succeeded!\n");

error:
    if (ret < 0) {
        WUPI_Log("Install failed, attempting to clean up partial content...\n");
        /* Installation failed. We only delete the content directory to clean up
         * partial installations, preserving the data directory and save data. */
        char contentPath[CINS_PATH_LEN];
        snprintf(contentPath, CINS_PATH_LEN, "/vol/slccmpt01/title/%08x/%08x/content", idHi, idLo);
        FSARemove(fsaClient, contentPath);
        FSARemove(fsaClient, ticketPath);
    }

    return ret > 0 ? 0 : ret;
}

bool CINS_TitleExists(uint64_t titleId) {
    uint32_t idHi = (uint32_t)(titleId >> 32);
    uint32_t idLo = (uint32_t)(titleId & 0xFFFFFFFF);

    char titlePath[CINS_PATH_LEN];
    char ticketPath[CINS_PATH_LEN];
    snprintf(titlePath, CINS_PATH_LEN, "/vol/slccmpt01/title/%08x/%08x", idHi, idLo);
    snprintf(ticketPath, CINS_PATH_LEN, "/vol/slccmpt01/ticket/%08x/%08x.tik", idHi, idLo);

    FSStat stat;
    bool titleExists = (FSAGetStat(fsaClient, titlePath, &stat) == FS_ERROR_OK);
    bool ticketExists = (FSAGetStat(fsaClient, ticketPath, &stat) == FS_ERROR_OK);

    return (titleExists || ticketExists);
}

bool CINS_UninstallTitle(uint64_t titleId) {
    uint32_t idHi = (uint32_t)(titleId >> 32);
    uint32_t idLo = (uint32_t)(titleId & 0xFFFFFFFF);

    char titlePath[CINS_PATH_LEN];
    char ticketPath[CINS_PATH_LEN];
    snprintf(titlePath, CINS_PATH_LEN, "/vol/slccmpt01/title/%08x/%08x", idHi, idLo);
    snprintf(ticketPath, CINS_PATH_LEN, "/vol/slccmpt01/ticket/%08x/%08x.tik", idHi, idLo);

    FSStat stat;
    bool titleExists = (FSAGetStat(fsaClient, titlePath, &stat) == FS_ERROR_OK);
    bool ticketExists = (FSAGetStat(fsaClient, ticketPath, &stat) == FS_ERROR_OK);

    if (!titleExists && !ticketExists) {
        return true;
    }

    bool ok = true;
    if (titleExists) {
        if (!FSARemoveTree(fsaClient, titlePath)) {
            ok = false;
        }
    }
    if (ticketExists) {
        if (FSARemove(fsaClient, ticketPath) != FS_ERROR_OK) {
            ok = false;
        }
    }
    return ok;
}

UninstallResult CINS_UninstallTitleResult(uint64_t titleId) {
    if (!CINS_TitleExists(titleId)) {
        return UninstallResult::NOT_PRESENT;
    }
    if (CINS_UninstallTitle(titleId)) {
        return UninstallResult::SUCCESS;
    }
    return UninstallResult::FAILED;
}

