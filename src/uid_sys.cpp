#include "uid_sys.h"
#include "FSAUtils.h"
#include "log.h"

#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include <stdio.h>
#include <map>
#include <set>
#include <vector>
#include <algorithm>
#include <format>

bool UID_Reconstruct(FSAClientHandle fsaClient, size_t* outRecoveredCount) {
    WUPI_Log("UID_Reconstruct: Scanning SLCCMPT for title UIDs...\n");

    std::map<uint64_t, uint32_t> titleToUid;
    std::set<uint32_t> usedUids;

    // 1. Always anchor System Menu (0000000100000002 -> 4096)
    titleToUid[VWII_TITLE_ID_SYSTEM_MENU] = VWII_UID_SYSTEM_MENU;
    usedUids.insert(VWII_UID_SYSTEM_MENU);

    // 2. Read any valid entries from existing uid.sys if available
    FSAFileHandle fd = 0;
    if (FSAOpenFileEx(fsaClient, VWII_UID_SYS_PATH, "rb", (FSMode)0, FS_OPEN_FLAG_NONE, 0, &fd) == FS_ERROR_OK) {
        RawUidEntry* entryBuf = (RawUidEntry*)memalign(0x40, 0x40);
        if (entryBuf) {
            while (true) {
                int readRes = FSAReadFile(fsaClient, entryBuf, sizeof(RawUidEntry), 1, fd, 0);
                if (readRes <= 0) break;

                if (entryBuf->titleId == VWII_TITLE_ID_SYSTEM_MENU) {
                    continue;
                }
                if (UID_IsValidVwiiUid(entryBuf->uid)) {
                    titleToUid[entryBuf->titleId] = entryBuf->uid;
                    usedUids.insert(entryBuf->uid);
                }
            }
            free(entryBuf);
        }
        FSACloseFile(fsaClient, fd);
    }

    // 3. Scan all category subdirectories in /vol/slccmpt01/title
    FSADirectoryHandle titleDir;
    if (FSAOpenDir(fsaClient, "/vol/slccmpt01/title", &titleDir) == FS_ERROR_OK) {
        FSADirectoryEntry* hiEntry = (FSADirectoryEntry*)memalign(0x40, sizeof(FSADirectoryEntry));
        FSADirectoryEntry* loEntry = (FSADirectoryEntry*)memalign(0x40, sizeof(FSADirectoryEntry));

        if (hiEntry && loEntry) {
            while (FSAReadDir(fsaClient, titleDir, hiEntry) == FS_ERROR_OK) {
                if (strcmp(hiEntry->name, ".") == 0 || strcmp(hiEntry->name, "..") == 0) continue;
                if (!(hiEntry->info.flags & FS_STAT_DIRECTORY)) continue;

                uint32_t idHi = strtoul(hiEntry->name, nullptr, 16);
                std::string hiPath = std::format("/vol/slccmpt01/title/{}", hiEntry->name);

                FSADirectoryHandle hiDir;
                if (FSAOpenDir(fsaClient, hiPath.c_str(), &hiDir) == FS_ERROR_OK) {
                    while (FSAReadDir(fsaClient, hiDir, loEntry) == FS_ERROR_OK) {
                        if (strcmp(loEntry->name, ".") == 0 || strcmp(loEntry->name, "..") == 0) continue;
                        if (!(loEntry->info.flags & FS_STAT_DIRECTORY)) continue;

                        uint32_t idLo = strtoul(loEntry->name, nullptr, 16);
                        uint64_t titleId = ((uint64_t)idHi << 32) | (uint64_t)idLo;
                        if (titleId == VWII_TITLE_ID_SYSTEM_MENU) continue;

                        std::string dataPath = std::format("/vol/slccmpt01/title/{}/{}/data", hiEntry->name, loEntry->name);
                        FSStat dstat;
                        if (FSAGetStat(fsaClient, dataPath.c_str(), &dstat) == FS_ERROR_OK) {
                            if (UID_IsValidVwiiUid(dstat.owner)) {
                                uint32_t existingAllocated = titleToUid.count(titleId) ? titleToUid[titleId] : 0;
                                if (existingAllocated != dstat.owner) {
                                    if (existingAllocated != 0) {
                                        usedUids.erase(existingAllocated);
                                    }
                                    if (usedUids.count(dstat.owner) == 0) {
                                        titleToUid[titleId] = dstat.owner;
                                        usedUids.insert(dstat.owner);
                                        WUPI_Log("UID_Reconstruct: Discovered %08x/%08x -> UID %u from /data\n",
                                                 idHi, idLo, dstat.owner);
                                    } else {
                                        WUPI_Log("UID_Reconstruct: Collision for UID %u on %08x/%08x\n",
                                                 dstat.owner, idHi, idLo);
                                    }
                                }
                            }
                        }
                    }
                    FSACloseDir(fsaClient, hiDir);
                }
            }
        }
        if (hiEntry) free(hiEntry);
        if (loEntry) free(loEntry);
        FSACloseDir(fsaClient, titleDir);
    }

    // 4. Build sorted RawUidEntry array
    // System Menu is always entry 0
    std::vector<RawUidEntry> entries;
    entries.push_back({ VWII_TITLE_ID_SYSTEM_MENU, VWII_UID_SYSTEM_MENU });

    std::vector<std::pair<uint64_t, uint32_t>> otherEntries;
    otherEntries.reserve(titleToUid.size());
    for (const auto& [tid, uid] : titleToUid) {
        if (tid != VWII_TITLE_ID_SYSTEM_MENU) {
            otherEntries.push_back({ tid, uid });
        }
    }
    std::sort(otherEntries.begin(), otherEntries.end(), [](const auto& a, const auto& b) {
        return a.second < b.second;
    });

    for (const auto& [tid, uid] : otherEntries) {
        entries.push_back({ tid, uid });
    }

    // 5. Write out /vol/slccmpt01/sys/uid.sys
    EnsureFSADir(fsaClient, "/vol/slccmpt01/sys");

    size_t byteSize = entries.size() * sizeof(RawUidEntry);
    size_t allocSize = (byteSize + 0x3F) & ~0x3F;
    RawUidEntry* writeBuf = (RawUidEntry*)memalign(0x40, allocSize);
    if (!writeBuf) {
        WUPI_Log("UID_Reconstruct: Failed to allocate aligned buffer\n");
        return false;
    }
    memset(writeBuf, 0, allocSize);
    memcpy(writeBuf, entries.data(), byteSize);

    bool ok = FSACreateFileWithOwner(fsaClient, VWII_UID_SYS_PATH, writeBuf, byteSize,
                                     STOCK_MODE_SYSTEM_FILE, 0, 0);
    free(writeBuf);

    if (ok) {
        WUPI_Log("UID_Reconstruct: Saved %zu entries to %s\n", entries.size(), VWII_UID_SYS_PATH);
        if (outRecoveredCount) {
            *outRecoveredCount = entries.size();
        }
    } else {
        WUPI_Log("UID_Reconstruct: Failed to write %s\n", VWII_UID_SYS_PATH);
    }

    return ok;
}

uint32_t UID_GetOrCreate(FSAClientHandle fsaClient, uint64_t titleId) {
    if (titleId == VWII_TITLE_ID_SYSTEM_MENU) {
        // Ensure uid.sys exists with System Menu
        FSStat stat;
        if (FSAGetStat(fsaClient, VWII_UID_SYS_PATH, &stat) != FS_ERROR_OK) {
            UID_Reconstruct(fsaClient, nullptr);
        }
        return VWII_UID_SYSTEM_MENU;
    }

    FSAFileHandle fd = 0;
    int openRes = FSAOpenFileEx(fsaClient, VWII_UID_SYS_PATH, "r+", STOCK_MODE_SYSTEM_FILE, FS_OPEN_FLAG_NONE, 0, &fd);

    // If uid.sys doesn't exist, reconstruct from SLCCMPT first
    if (openRes == FS_ERROR_NOT_FOUND) {
        UID_Reconstruct(fsaClient, nullptr);
        openRes = FSAOpenFileEx(fsaClient, VWII_UID_SYS_PATH, "r+", STOCK_MODE_SYSTEM_FILE, FS_OPEN_FLAG_NONE, 0, &fd);
    }

    if (openRes != FS_ERROR_OK) {
        WUPI_Log("UID: Failed to open %s (%d)\n", VWII_UID_SYS_PATH, openRes);
        return 0;
    }

    // uid.sys exists and is open in "r+"
    uint32_t maxUid = VWII_UID_SYSTEM_MENU;
    bool found = false;
    uint32_t foundUid = 0;
    size_t entryCount = 0;
    std::set<uint32_t> existingUids;
    existingUids.insert(VWII_UID_SYSTEM_MENU);

    RawUidEntry* entry = (RawUidEntry*)memalign(0x40, 0x40);
    if (!entry) {
        FSACloseFile(fsaClient, fd);
        return 0;
    }

    while (true) {
        int readRes = FSAReadFile(fsaClient, entry, sizeof(RawUidEntry), 1, fd, 0);
        if (readRes <= 0) {
            break;
        }

        existingUids.insert(entry->uid);

        if (entry->titleId == titleId) {
            found = true;
            foundUid = entry->uid;
            break;
        }

        if (entry->uid > maxUid) {
            maxUid = entry->uid;
        }
        entryCount++;
    }

    if (found) {
        free(entry);
        FSACloseFile(fsaClient, fd);
        return foundUid;
    }

    // If entryCount == 0 (e.g. empty file), write System Menu first
    if (entryCount == 0) {
        *entry = { VWII_TITLE_ID_SYSTEM_MENU, VWII_UID_SYSTEM_MENU };
        FSASetPosFile(fsaClient, fd, 0);
        FSAWriteFile(fsaClient, entry, sizeof(RawUidEntry), 1, fd, 0);
        entryCount = 1;
    }

    // Check if the title's /data directory already exists on disk with a valid UID
    uint32_t idHi = (uint32_t)(titleId >> 32);
    uint32_t idLo = (uint32_t)(titleId & 0xFFFFFFFF);
    std::string dataPath = std::format("/vol/slccmpt01/title/{:08x}/{:08x}/data", idHi, idLo);

    uint32_t newUid = 0;
    FSStat dstat;
    if (FSAGetStat(fsaClient, dataPath.c_str(), &dstat) == FS_ERROR_OK &&
        UID_IsValidVwiiUid(dstat.owner) &&
        existingUids.count(dstat.owner) == 0) {
        newUid = dstat.owner;
        WUPI_Log("UID: Adopting existing /data owner UID %u for %08x/%08x\n", newUid, idHi, idLo);
    } else {
        newUid = maxUid + 1;
        while (existingUids.count(newUid)) {
            newUid++;
        }
    }

    *entry = { titleId, newUid };
    FSASetPosFile(fsaClient, fd, entryCount * sizeof(RawUidEntry));
    int writeRes = FSAWriteFile(fsaClient, entry, sizeof(RawUidEntry), 1, fd, 0);
    free(entry);
    FSACloseFile(fsaClient, fd);

    WUPI_Log("UID (appended): %08x/%08x -> %u (%s)\n",
             idHi, idLo, newUid, writeRes > 0 ? "OK" : "FAIL");

    return newUid;
}
