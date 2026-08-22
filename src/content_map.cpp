#include "content_map.h"
#include "FSAUtils.h"
#include "PathRules.h"
#include "EndianUtils.h"
#include "log.h"

#include <cstdlib>
#include <cstring>
#include <malloc.h>
#include <cstdio>
#include <format>
#include <map>
#include <set>
#include <vector>
#include <algorithm>

extern FSAClientHandle fsaClient;

int32_t FindSharedContentIndex(const Sha1Hash& expectedHash) {
    FSAFileHandle fd = 0;
    const char* path = VWII_SHARED_CONTENT_MAP_PATH;

    if (FSAOpenFileEx(fsaClient, path, "r", (FSMode)0x666, FS_OPEN_FLAG_NONE, 0, &fd) != FS_ERROR_OK) {
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

extern "C" int32_t FindSharedContentIndex(const uint8_t* expectedHash) {
    if (!expectedHash) return -1;
    return FindSharedContentIndex(*reinterpret_cast<const Sha1Hash*>(expectedHash));
}

int32_t GetSharedContentIndex(const uint8_t* expectedHash) {
    int32_t existingIndex = FindSharedContentIndex(expectedHash);
    if (existingIndex >= 0) {
        return existingIndex;
    }

    FSAFileHandle fd = 0;
    const char* path = VWII_SHARED_CONTENT_MAP_PATH;

    SlcMakeDir(fsaClient, VWII_SHARED1_DIR_PATH);

    FSError openRes = FSAOpenFileEx(fsaClient, path, "r+", (FSMode)0x660, FS_OPEN_FLAG_NONE, 0, &fd);
    if (openRes != FS_ERROR_OK) {
        if (openRes != FS_ERROR_NOT_FOUND) {
            WUPI_Log("Failed to open content.map: %d\n", openRes);
            return -1;
        }
        // File doesn't exist — create it empty with correct ownership via PathRules
        if (!SlcCreateFile(fsaClient, path, nullptr, 0)) {
            WUPI_Log("Failed to create content.map\n");
            return -1;
        }
        if (FSAOpenFileEx(fsaClient, path, "r+", (FSMode)0x660, FS_OPEN_FLAG_NONE, 0, &fd) != FS_ERROR_OK) {
            WUPI_Log("Failed to open new content.map\n");
            return -1;
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
    if (writeRes != 1) {
        WUPI_Log("Failed to write to content.map\n");
        free(entry);
        FSACloseFile(fsaClient, fd);
        return -1;
    }

    free(entry);
    FSACloseFile(fsaClient, fd);
    return freeIndex;
}

bool CONTENTMAP_CheckConsistency(FSAClientHandle fsa, ContentMapReport& outReport) {
    outReport = ContentMapReport();

    // 1. Audit /vol/slccmpt01/shared1/content.map
    FSStat mapStat;
    if (FSAGetStat(fsa, VWII_SHARED_CONTENT_MAP_PATH, &mapStat) != FS_ERROR_OK) {
        outReport.mapFileMissing = true;
        outReport.issues.push_back("Missing /shared1/content.map");
    } else {
        if ((mapStat.size % sizeof(ContentMapEntry)) != 0) {
            outReport.mapFileDamaged = true;
            outReport.issues.push_back(std::format("content.map size {} is not a multiple of {}",
                                                   uint32_t(mapStat.size), sizeof(ContentMapEntry)));
        }

        ResolvedPathRule mapRule;
        if (!PathRules_CheckPermissions(fsa, VWII_SHARED_CONTENT_MAP_PATH, mapStat, &mapRule)) {
            outReport.mapPermissionsInvalid = true;
            outReport.issues.push_back(std::format("content.map bad permissions (mode 0x{:x}, UID {}, GID {})",
                                                   uint32_t(mapStat.mode), uint32_t(mapStat.owner), uint32_t(mapStat.group)));
        }

        outReport.totalSlots = mapStat.size / sizeof(ContentMapEntry);
    }

    // 2. Read existing map entries and detect duplicate entries
    std::map<uint32_t, Sha1Hash> mapEntries;
    std::map<Sha1Hash, uint32_t> mapHashToSlot;

    if (!outReport.mapFileMissing && !outReport.mapFileDamaged) {
        FSAFileHandle fd = 0;
        if (FSAOpenFileEx(fsa, VWII_SHARED_CONTENT_MAP_PATH, "rb", (FSMode)0, FS_OPEN_FLAG_NONE, 0, &fd) == FS_ERROR_OK) {
            ContentMapEntry* entry = (ContentMapEntry*)memalign(0x40, sizeof(ContentMapEntry));
            if (entry) {
                uint32_t slot = 0;
                while (FSAReadFile(fsa, entry, sizeof(ContentMapEntry), 1, fd, 0) == 1) {
                    if (entry->name[0] != '\0') {
                        outReport.activeEntries++;
                        mapEntries[slot] = entry->hash;

                        if (mapHashToSlot.count(entry->hash)) {
                            outReport.duplicateEntriesCount++;
                            outReport.issues.push_back(std::format("content.map duplicate hash at slot {:08x} (matches slot {:08x})",
                                                                   slot, mapHashToSlot[entry->hash]));
                        } else {
                            mapHashToSlot[entry->hash] = slot;
                        }

                        // Check on-disk file
                        std::string appPath = std::format("/vol/slccmpt01/shared1/{:08x}.app", slot);
                        FSStat appStat;
                        if (FSAGetStat(fsa, appPath.c_str(), &appStat) != FS_ERROR_OK) {
                            outReport.missingFilesCount++;
                            outReport.issues.push_back(std::format("Shared content missing from disk: {:08x}.app", slot));
                        } else {
                            if (!FSACheckFileSha1(fsa, appPath, entry->hash.data(), appStat.size)) {
                                outReport.hashMismatchCount++;
                                outReport.issues.push_back(std::format("Shared content hash mismatch: {:08x}.app", slot));
                            } else {
                                outReport.verifiedEntries++;
                            }

                            ResolvedPathRule appRule;
                            if (!PathRules_CheckPermissions(fsa, appPath, appStat, &appRule)) {
                                outReport.filePermissionErrorsCount++;
                                outReport.issues.push_back(std::format("Shared content bad permissions: {:08x}.app", slot));
                            }
                        }
                    }
                    slot++;
                }
                free(entry);
            }
            FSACloseFile(fsa, fd);
        }
    }

    // 3. Scan /vol/slccmpt01/shared1 directory for unindexed or duplicate .app files
    FSADirectoryHandle sharedDir;
    if (FSAOpenDir(fsa, VWII_SHARED1_DIR_PATH, &sharedDir) == FS_ERROR_OK) {
        FSADirectoryEntry* dirEntry = (FSADirectoryEntry*)memalign(0x40, sizeof(FSADirectoryEntry));
        if (dirEntry) {
            while (FSAReadDir(fsa, sharedDir, dirEntry) == FS_ERROR_OK) {
                if (strcmp(dirEntry->name, ".") == 0 || strcmp(dirEntry->name, "..") == 0) continue;
                if (strcmp(dirEntry->name, "content.map") == 0) continue;

                std::string name(dirEntry->name);
                if (name.ends_with(".app")) {
                    char* endPtr = nullptr;
                    uint32_t slot = strtoul(name.c_str(), &endPtr, 16);
                    if (endPtr && *endPtr == '.' && !mapEntries.count(slot)) {
                        std::string fullPath = std::format("{}/{}", VWII_SHARED1_DIR_PATH, name);
                        FSStat st;
                        Sha1Hash fileHash;
                        if (FSAGetStat(fsa, fullPath.c_str(), &st) == FS_ERROR_OK && st.size > 0 &&
                            FSAGetFileSha1(fsa, fullPath, fileHash.data(), st.size)) {
                            if (mapHashToSlot.count(fileHash)) {
                                outReport.duplicateFilesCount++;
                                outReport.issues.push_back(std::format("Duplicate unindexed shared file: {} (matches slot {:08x})",
                                                                       name, mapHashToSlot[fileHash]));
                            } else {
                                outReport.unindexedFilesCount++;
                                outReport.issues.push_back(std::format("Unindexed shared file: {}", name));
                            }
                        } else {
                            outReport.unindexedFilesCount++;
                            outReport.issues.push_back(std::format("Unindexed shared file: {}", name));
                        }
                    }
                }
            }
            free(dirEntry);
        }
        FSACloseDir(fsa, sharedDir);
    }

    // 4. Scan installed title TMDs to verify all required shared contents are indexed
    FSADirectoryHandle titleDir;
    if (FSAOpenDir(fsa, "/vol/slccmpt01/title", &titleDir) == FS_ERROR_OK) {
        FSADirectoryEntry* hiEntry = (FSADirectoryEntry*)memalign(0x40, sizeof(FSADirectoryEntry));
        FSADirectoryEntry* loEntry = (FSADirectoryEntry*)memalign(0x40, sizeof(FSADirectoryEntry));

        if (hiEntry && loEntry) {
            while (FSAReadDir(fsa, titleDir, hiEntry) == FS_ERROR_OK) {
                if (strcmp(hiEntry->name, ".") == 0 || strcmp(hiEntry->name, "..") == 0) continue;
                if (!(hiEntry->info.flags & FS_STAT_DIRECTORY)) continue;

                uint32_t idHi = strtoul(hiEntry->name, nullptr, 16);
                std::string hiPath = std::format("/vol/slccmpt01/title/{}", hiEntry->name);

                FSADirectoryHandle hiDir;
                if (FSAOpenDir(fsa, hiPath.c_str(), &hiDir) == FS_ERROR_OK) {
                    while (FSAReadDir(fsa, hiDir, loEntry) == FS_ERROR_OK) {
                        if (strcmp(loEntry->name, ".") == 0 || strcmp(loEntry->name, "..") == 0) continue;
                        if (!(loEntry->info.flags & FS_STAT_DIRECTORY)) continue;

                        uint32_t idLo = strtoul(loEntry->name, nullptr, 16);
                        uint64_t titleId = ((uint64_t)idHi << 32) | (uint64_t)idLo;

                        std::string tmdPath = std::format("/vol/slccmpt01/title/{}/{}/content/title.tmd",
                                                          hiEntry->name, loEntry->name);
                        uint8_t* tmdBuf = nullptr;
                        uint32_t tmdSize = 0;
                        if (ReadFileToBuffer(tmdPath, &tmdBuf, &tmdSize)) {
                            if (tmdSize >= sizeof(TitleTmd)) {
                                const TitleTmd* tmd = (const TitleTmd*)tmdBuf;
                                uint16_t numContents = FromBE16(tmd->numContents);
                                for (uint16_t c = 0; c < numContents; c++) {
                                    if (tmdSize < sizeof(TitleTmd) + ((c + 1) * sizeof(TitleContentRecord))) break;
                                    const TitleContentRecord& rec = tmd->contents[c];
                                    uint16_t ctype = FromBE16(rec.type);
                                    if ((ctype & 0x8000) != 0) {
                                        if (!mapHashToSlot.count(rec.hash)) {
                                            outReport.titleMissingSharedAssetsCount++;
                                            outReport.issues.push_back(std::format("Title {:016x} missing shared asset cid {:08x}",
                                                                                   titleId, FromBE32(rec.contentId)));
                                        }
                                    }
                                }
                            }
                            free(tmdBuf);
                        }
                    }
                    FSACloseDir(fsa, hiDir);
                }
            }
        }
        if (hiEntry) free(hiEntry);
        if (loEntry) free(loEntry);
        FSACloseDir(fsa, titleDir);
    }

    return outReport.IsClean();
}

bool CONTENTMAP_Reconstruct(FSAClientHandle fsa, size_t* outRecoveredCount, size_t* outDuplicatesRemovedCount) {
    WUPI_Log("CONTENTMAP_Reconstruct: Scanning SLCCMPT shared assets...\n");

    SlcEnsureDir(fsa, VWII_SHARED1_DIR_PATH);

    // 1. Scan all on-disk files in /vol/slccmpt01/shared1
    struct DiskSharedApp {
        uint32_t slot = 0;
        std::string filename;
        Sha1Hash hash;
        uint64_t size = 0;
        bool valid = false;
    };

    std::map<uint32_t, DiskSharedApp> diskApps;

    FSADirectoryHandle sharedDir;
    if (FSAOpenDir(fsa, VWII_SHARED1_DIR_PATH, &sharedDir) == FS_ERROR_OK) {
        FSADirectoryEntry* dirEntry = (FSADirectoryEntry*)memalign(0x40, sizeof(FSADirectoryEntry));
        if (dirEntry) {
            while (FSAReadDir(fsa, sharedDir, dirEntry) == FS_ERROR_OK) {
                if (strcmp(dirEntry->name, ".") == 0 || strcmp(dirEntry->name, "..") == 0) continue;
                if (strcmp(dirEntry->name, "content.map") == 0) continue;

                std::string name(dirEntry->name);
                if (name.ends_with(".app")) {
                    char* endPtr = nullptr;
                    uint32_t slot = strtoul(name.c_str(), &endPtr, 16);
                    if (endPtr && *endPtr == '.') {
                        std::string fullPath = std::format("{}/{}", VWII_SHARED1_DIR_PATH, name);
                        FSStat st;
                        if (FSAGetStat(fsa, fullPath.c_str(), &st) == FS_ERROR_OK && st.size > 0) {
                            DiskSharedApp app;
                            app.slot = slot;
                            app.filename = name;
                            app.size = st.size;

                            if (FSAGetFileSha1(fsa, fullPath, app.hash.data(), st.size)) {
                                app.valid = true;
                                diskApps[slot] = app;

                                // Repair permissions on this shared file if needed
                                SlcRepairFilePermissions(fsa, fullPath);
                            }
                        }
                    }
                }
            }
            free(dirEntry);
        }
        FSACloseDir(fsa, sharedDir);
    }

    // 2. Read existing content.map to preserve existing slot mappings and detect duplicates
    std::map<uint32_t, ContentMapEntry> slotEntries;
    std::map<Sha1Hash, uint32_t> hashToCanonicalSlot;
    std::set<uint32_t> duplicateSlotsToDelete;
    int32_t maxSlot = -1;

    FSAFileHandle fd = 0;
    if (FSAOpenFileEx(fsa, VWII_SHARED_CONTENT_MAP_PATH, "rb", (FSMode)0, FS_OPEN_FLAG_NONE, 0, &fd) == FS_ERROR_OK) {
        ContentMapEntry* entry = (ContentMapEntry*)memalign(0x40, sizeof(ContentMapEntry));
        if (entry) {
            uint32_t currentSlot = 0;
            while (FSAReadFile(fsa, entry, sizeof(ContentMapEntry), 1, fd, 0) == 1) {
                if (entry->name[0] != '\0') {
                    // Check if file on disk matches
                    if (diskApps.count(currentSlot) && diskApps[currentSlot].hash == entry->hash) {
                        if (hashToCanonicalSlot.count(entry->hash)) {
                            uint32_t canonical = hashToCanonicalSlot[entry->hash];
                            duplicateSlotsToDelete.insert(currentSlot);
                            WUPI_Log("CONTENTMAP_Reconstruct: Duplicate slot %08x in content.map (matches slot %08x)\n",
                                     currentSlot, canonical);
                        } else {
                            hashToCanonicalSlot[entry->hash] = currentSlot;
                            slotEntries[currentSlot] = *entry;
                            if ((int32_t)currentSlot > maxSlot) {
                                maxSlot = (int32_t)currentSlot;
                            }
                        }
                    }
                }
                currentSlot++;
            }
            free(entry);
        }
        FSACloseFile(fsa, fd);
    }

    // 3. For any valid disk files not yet recorded, register or mark duplicate
    for (const auto& [slot, app] : diskApps) {
        if (!app.valid) continue;
        if (slotEntries.count(slot) || duplicateSlotsToDelete.count(slot)) continue;

        if (hashToCanonicalSlot.count(app.hash)) {
            uint32_t canonical = hashToCanonicalSlot[app.hash];
            duplicateSlotsToDelete.insert(slot);
            WUPI_Log("CONTENTMAP_Reconstruct: Duplicate unindexed file %s (matches slot %08x)\n",
                     app.filename.c_str(), canonical);
        } else {
            hashToCanonicalSlot[app.hash] = slot;
            ContentMapEntry newEntry;
            memset(&newEntry, 0, sizeof(newEntry));
            std::format_to_n(newEntry.name, sizeof(newEntry.name), "{:08x}", slot);
            newEntry.hash = app.hash;
            slotEntries[slot] = newEntry;
            if ((int32_t)slot > maxSlot) {
                maxSlot = (int32_t)slot;
            }
        }
    }

    // 4. Delete duplicate shared .app files from SLCCMPT
    for (uint32_t dupSlot : duplicateSlotsToDelete) {
        std::string dupPath = std::format("{}/{:08x}.app", VWII_SHARED1_DIR_PATH, dupSlot);
        WUPI_Log("CONTENTMAP_Reconstruct: Deleting duplicate file %s...\n", dupPath.c_str());
        FSARemove(fsa, dupPath.c_str());
    }

    // 5. Construct contiguous ContentMapEntry buffer up to maxSlot
    std::vector<ContentMapEntry> finalEntries;
    if (maxSlot >= 0) {
        finalEntries.resize(maxSlot + 1);
        memset(finalEntries.data(), 0, finalEntries.size() * sizeof(ContentMapEntry));

        for (const auto& [slot, entry] : slotEntries) {
            if (slot < finalEntries.size()) {
                finalEntries[slot] = entry;
            }
        }
    }

    // 6. Write out reconstructed content.map using SlcCreateFile
    size_t byteSize = finalEntries.size() * sizeof(ContentMapEntry);
    bool writeOk = SlcCreateFile(fsa, VWII_SHARED_CONTENT_MAP_PATH,
                                 finalEntries.empty() ? nullptr : finalEntries.data(),
                                 byteSize);

    if (!writeOk) {
        WUPI_Log("CONTENTMAP_Reconstruct: Failed to write reconstructed content.map\n");
        return false;
    }

    if (outRecoveredCount) {
        *outRecoveredCount = slotEntries.size();
    }
    if (outDuplicatesRemovedCount) {
        *outDuplicatesRemovedCount = duplicateSlotsToDelete.size();
    }

    WUPI_Log("CONTENTMAP_Reconstruct: Successfully reconstructed content.map (%zu active entries, %zu duplicates cleaned, %zu total slots)\n",
             slotEntries.size(), duplicateSlotsToDelete.size(), finalEntries.size());

    return true;
}
