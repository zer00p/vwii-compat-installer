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
#include "content_map.h"
#include "MenuUtils.h"
#include "PathRules.h"

#define IOS_SUCCESS             FS_ERROR_OK

#define CINS_PATH_LEN           (sizeof("/vol/slccmpt01") + 63)

#define CINS_TRY(c)                        \
    do { if (!(c)) {                       \
        WUPI_Log("Failed, please exit and try again\n"); \
        goto error;                        \
    } } while (0)

extern FSAClientHandle fsaClient;

/* Creates the title's /data directory with correct ownership if it does not
 * already exist. Permission repair on an existing directory is left to the
 * dedicated scan-and-restore tool.
 *
 * Returns FS_ERROR_OK on success, or a negative FSError if creation failed. */
static FSError EnsureTitleDataDir(FSAClientHandle fsa, const std::string& titlePath, uint16_t tmdGroupId) {
    std::string dataPath = titlePath + "/data";
    FSError ret = SlcMakeDir(fsa, dataPath, tmdGroupId);
    if (ret != FS_ERROR_OK && ret != FS_ERROR_ALREADY_EXISTS) {
        WUPI_Log("Failed to create the data directory, ret = %d\n", ret);
        return ret;
    }
    return FS_ERROR_OK;
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

    WUPI_Log("Starting install\n");

    snprintf(titlePath, CINS_PATH_LEN, "/vol/slccmpt01/title/%08x/%08x", idHi, idLo);
    snprintf(path, CINS_PATH_LEN, "/vol/slccmpt01/title/%08x", idHi);
    snprintf(ticketPath, CINS_PATH_LEN, "/vol/slccmpt01/ticket/%08x/%08x.tik", idHi, idLo);
    snprintf(ticketFolder, CINS_PATH_LEN, "/vol/slccmpt01/ticket/%08x", idHi);

    WUPI_Log("Writing ticket...\n");
    {
        SlcEnsureDir(fsaClient, ticketFolder);
        CINS_TRY(SlcCreateFile(fsaClient, ticketPath, ticket, ticket_size));
    }

    WUPI_Log("Creating title directory...\n");
    {
        /* Create the title directory if it doesn't already exist. The first
         * word (type) should exist, but the second one (the unique title)
         * shouldn't unless there is save data. */
        SlcEnsureDir(fsaClient, titlePath);
        if (FSAGetStat(fsaClient, titlePath, nullptr) == FS_ERROR_OK) {
            /* If the title content exists already, delete content but preserve data */
            snprintf(path, CINS_PATH_LEN, "/vol/slccmpt01/title/%08x/%08x/content", idHi, idLo);
            FSARemove(fsaClient, path);
        }

        /* Ensure the title's data directory exists with correct Title UID and TMD Group ID */
        uint16_t tmdGroupId = tmd ? FromBE16(tmd->groupId) : 0;
        ret = EnsureTitleDataDir(fsaClient, titlePath, tmdGroupId);
        CINS_TRY(ret == FS_ERROR_OK);

        strncpy(pathd, titlePath, CINS_PATH_LEN);
        strncat(pathd, "/content", CINS_PATH_LEN - 1);
        ret = SlcMakeDir(fsaClient, pathd);
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

        CINS_TRY(SlcCreateFile(fsaClient, path, tmd, tmd_size));
    }

    WUPI_Log("Writing contents...\n");
    {
        for (uint16_t i = 0; i < numContents; i++) {
            const TitleContentRecord& rec = tmd->contents[i];
            uint32_t cId = FromBE32(rec.contentId);
            uint16_t cType = FromBE16(rec.type);
            uint64_t cSize = FromBE64(rec.size);

            if ((cType & 0x8000) != 0) {
                int32_t sharedIndex = GetSharedContentIndex(rec.hash.data());
                if (sharedIndex < 0) {
                    WUPI_Log("Failed to get shared content index for content %08x\n", cId);
                    goto error;
                }
                
                snprintf(path, CINS_PATH_LEN,
                         "/vol/slccmpt01/shared1/%08x.app", sharedIndex);

                FSStat testStat;
                if (FSAGetStat(fsaClient, path, &testStat) == FS_ERROR_OK) {
                    const uint8_t* expectedHash = rec.hash.data();
                    if (FSACheckFileSha1(fsaClient, path, expectedHash, cSize)) {
                        // Shared content exists and hash is verified intact on NAND.
                        // Check if permissions need to be corrected.
                        if (!PathRules_CheckPermissions(fsaClient, path, testStat)) {
                            if (contents[i].data) {
                                CINS_TRY(SlcCreateFile(fsaClient, path, contents[i].data, cSize));
                            } else {
                                CINS_TRY(SlcRepairFilePermissions(fsaClient, path));
                            }
                        }
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

            SlcEnsureParentDir(fsaClient, path);
            CINS_TRY(SlcCreateFile(fsaClient, path, contents[i].data, cSize));
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

