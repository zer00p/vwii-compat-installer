/* region_changer.cpp
 *   vWii Region Change Wizard & Shared Content Management
 */

#include "region_changer.h"
#include "settingtxt_manager.h"
#include "installer.h"
#include "content_map.h"
#include "wad.h"
#include "downloader.h"
#include "FSAUtils.h"
#include "log.h"
#include "MenuUtils.h"
#include "StateUtils.h"
#include "EndianUtils.h"
#include <coreinit/filesystem_fsa.h>
#include <malloc.h>
#include <string.h>
#include <unistd.h>
#include <array>
#include <map>
#include <set>
#include <vector>
#include <string>
#include <format>

extern FSAClientHandle fsaClient;

static const KnownRegionSharedContent g_knownRegionSharedContents[] = {
    // USA
    {
        "USA",
        "System Menu USA Font Table (0000000a)",
        {0x29, 0x3d, 0x73, 0x42, 0x60, 0xac, 0x99, 0xf4, 0xd3, 0xde, 0x75, 0x31, 0x0a, 0x7d, 0x27, 0x34, 0x66, 0xf6, 0xbe, 0x08},
        272512
    },
    {
        "USA",
        "System Menu USA Messages (0000000b)",
        {0x53, 0x4d, 0x29, 0x52, 0xfe, 0x2f, 0x66, 0x43, 0x70, 0xd8, 0x36, 0x4b, 0x9a, 0x0a, 0x0d, 0x1f, 0x55, 0xa0, 0x59, 0x31},
        53216
    },
    // EUR
    {
        "EUR",
        "System Menu EUR Font Table (0000000f)",
        {0x76, 0xab, 0xfb, 0xea, 0xcb, 0x2c, 0x4c, 0xa4, 0xeb, 0x3f, 0x03, 0x64, 0x13, 0xc7, 0xe0, 0x01, 0xfd, 0xab, 0x7b, 0x26},
        606016
    },
    {
        "EUR",
        "System Menu EUR Messages (00000010)",
        {0x2f, 0x28, 0xd4, 0xb6, 0xda, 0xeb, 0xeb, 0x15, 0x80, 0x14, 0x77, 0xc6, 0xbe, 0xbc, 0x5f, 0x37, 0xc0, 0x90, 0x9e, 0xae},
        70336
    },
    // JPN
    {
        "JPN",
        "System Menu / Transfer JPN Font 1 (00000006)",
        {0x92, 0xc2, 0x98, 0x38, 0x22, 0xc0, 0xb8, 0x0b, 0x1a, 0xb7, 0xcf, 0x3e, 0x58, 0xe8, 0x8b, 0x65, 0x93, 0xbf, 0x19, 0x34},
        1819808
    },
    {
        "JPN",
        "System Menu / Transfer JPN Font 2 (00000007)",
        {0x29, 0xc4, 0xcb, 0xe7, 0xf5, 0x4a, 0x78, 0xa5, 0xe1, 0x8d, 0x7a, 0x12, 0xc9, 0x0e, 0x6b, 0x92, 0x10, 0x3f, 0x7e, 0x45},
        1572320
    },
    {
        "JPN",
        "System Transfer JPN Extra 1 (0000000f)",
        {0x5b, 0xa4, 0xcc, 0x50, 0xf3, 0xba, 0xc6, 0x97, 0x5a, 0xad, 0x45, 0x39, 0x9c, 0x69, 0x9e, 0xcc, 0x9b, 0x06, 0x6f, 0xf0},
        5216
    },
    {
        "JPN",
        "System Transfer JPN Extra 2 (00000011)",
        {0x40, 0x23, 0x15, 0x6b, 0x2e, 0xae, 0x65, 0xea, 0x3d, 0xed, 0x7d, 0x7a, 0x03, 0x7c, 0x95, 0xa4, 0x3e, 0xb5, 0x06, 0x63},
        15392
    }
};

static bool ScanTitleTmds(FSAClientHandle fsa, std::set<Sha1Hash>& outReferencedHashes) {
    std::string rootTitlePath = "/vol/slccmpt01/title";
    FSADirectoryHandle dirHi;
    if (FSAOpenDir(fsa, rootTitlePath.c_str(), &dirHi) != FS_ERROR_OK) {
        WUPI_Log("ScanTitleTmds: Failed to open %s\n", rootTitlePath.c_str());
        return false;
    }

    FSADirectoryEntry* entryHi = (FSADirectoryEntry*)memalign(0x40, sizeof(FSADirectoryEntry));
    FSADirectoryEntry* entryLo = (FSADirectoryEntry*)memalign(0x40, sizeof(FSADirectoryEntry));
    if (!entryHi || !entryLo) {
        WUPI_Log("ScanTitleTmds: Failed to allocate directory entry buffers\n");
        if (entryHi) free(entryHi);
        if (entryLo) free(entryLo);
        FSACloseDir(fsa, dirHi);
        return false;
    }

    bool scanOk = true;

    while (FSAReadDir(fsa, dirHi, entryHi) == FS_ERROR_OK) {
        if (strcmp(entryHi->name, ".") == 0 || strcmp(entryHi->name, "..") == 0) continue;
        if (!(entryHi->info.flags & FS_STAT_DIRECTORY)) continue;

        std::string subDirPath = rootTitlePath + "/" + entryHi->name;
        FSADirectoryHandle dirLo;
        if (FSAOpenDir(fsa, subDirPath.c_str(), &dirLo) != FS_ERROR_OK) {
            WUPI_Log("ScanTitleTmds: Failed to open %s\n", subDirPath.c_str());
            scanOk = false;
            break;
        }

        while (FSAReadDir(fsa, dirLo, entryLo) == FS_ERROR_OK) {
            if (strcmp(entryLo->name, ".") == 0 || strcmp(entryLo->name, "..") == 0) continue;
            if (!(entryLo->info.flags & FS_STAT_DIRECTORY)) continue;

            std::string tmdPath = subDirPath + "/" + entryLo->name + "/content/title.tmd";
            FSStat stat;
            FSError statRes = FSAGetStat(fsa, tmdPath.c_str(), &stat);
            if (statRes == FS_ERROR_OK && stat.size > 0) {
                uint8_t* tmdBuf = nullptr;
                uint32_t tmdSize = 0;
                if (!ReadFileToBuffer(tmdPath, &tmdBuf, &tmdSize)) {
                    WUPI_Log("ScanTitleTmds: Failed to read TMD %s\n", tmdPath.c_str());
                    scanOk = false;
                    break;
                }

                if (tmdSize < sizeof(TitleTmd)) {
                    WUPI_Log("ScanTitleTmds: TMD header truncated on %s\n", tmdPath.c_str());
                    free(tmdBuf);
                    scanOk = false;
                    break;
                }

                const TitleTmd* tmd = reinterpret_cast<const TitleTmd*>(tmdBuf);
                uint16_t numContents = FromBE16(tmd->numContents);
                if (tmdSize < sizeof(TitleTmd) + (numContents * sizeof(TitleContentRecord))) {
                    WUPI_Log("ScanTitleTmds: TMD contents truncated on %s\n", tmdPath.c_str());
                    free(tmdBuf);
                    scanOk = false;
                    break;
                }

                for (uint16_t i = 0; i < numContents; i++) {
                    if ((FromBE16(tmd->contents[i].type) & 0x8000) != 0) {
                        outReferencedHashes.insert(tmd->contents[i].hash);
                    }
                }
                free(tmdBuf);
                if (!scanOk) break;
            } else if (statRes != FS_ERROR_OK && statRes != FS_ERROR_NOT_FOUND) {
                WUPI_Log("ScanTitleTmds: Stat error %d on %s\n", statRes, tmdPath.c_str());
                scanOk = false;
                break;
            }
        }
        FSACloseDir(fsa, dirLo);
        if (!scanOk) break;
    }

    free(entryHi);
    free(entryLo);
    FSACloseDir(fsa, dirHi);
    return scanOk;
}

std::vector<OrphanSharedContent> SharedContent_ScanRegionOrphans(FSAClientHandle fsa, const std::string& targetRegion) {
    std::vector<OrphanSharedContent> orphans;

    // 1. Candidate target hashes: known region-specific shared contents from other regions
    std::map<Sha1Hash, const KnownRegionSharedContent*> candidateMap;
    for (const auto& known : g_knownRegionSharedContents) {
        if (targetRegion != known.region) {
            candidateMap[known.hash] = &known;
        }
    }

    if (candidateMap.empty()) {
        return orphans;
    }

    // 2. Scan all installed title TMDs to find referenced hashes
    std::set<Sha1Hash> referencedHashes;
    if (!ScanTitleTmds(fsa, referencedHashes)) {
        WUPI_Log("Error: Failed to completely scan all title TMDs. Aborting shared content cleanup for safety.\n");
        return orphans;
    }

    // 3. Subtract all referenced hashes from candidate target hashes
    for (const auto& refHash : referencedHashes) {
        candidateMap.erase(refHash);
    }

    if (candidateMap.empty()) {
        return orphans;
    }

    // 4. Locate on-disk shared files for remaining unreferenced candidate hashes
    for (const auto& [hash, known] : candidateMap) {
        int32_t mapIndex = FindSharedContentIndex(hash);
        if (mapIndex >= 0) {
            std::string hexName = std::format("{:08x}", mapIndex);
            std::string appPath = "/vol/slccmpt01/shared1/" + hexName + ".app";
            FSStat st;
            uint64_t fsize = 0;
            if (FSAGetStat(fsa, appPath.c_str(), &st) == FS_ERROR_OK) {
                fsize = st.size;
            }

            OrphanSharedContent orphan;
            orphan.mapIndex = mapIndex;
            orphan.name = hexName;
            orphan.filePath = appPath;
            orphan.description = known->description;
            orphan.region = known->region;
            orphan.hash = hash;
            orphan.fileSize = fsize;

            orphans.push_back(orphan);
        }
    }

    return orphans;
}

bool SharedContent_CleanRegionOrphans(FSAClientHandle fsa, const std::vector<OrphanSharedContent>& orphans) {
    if (orphans.empty()) return true;

    FSAFileHandle fd = 0;
    const char* mapPath = "/vol/slccmpt01/shared1/content.map";
    if (FSAOpenFileEx(fsa, mapPath, "r+", (FSMode)0x666, FS_OPEN_FLAG_NONE, 0, &fd) != FS_ERROR_OK) {
        WUPI_Log("Failed to open content.map for writing.\n");
        return false;
    }

    ContentMapEntry* zeroEntry = (ContentMapEntry*)memalign(0x40, sizeof(ContentMapEntry));
    if (!zeroEntry) {
        FSACloseFile(fsa, fd);
        return false;
    }
    memset(zeroEntry, 0, sizeof(ContentMapEntry));

    bool allOk = true;
    for (const auto& orphan : orphans) {
        // 1. Delete .app file
        FSARemove(fsa, orphan.filePath.c_str());

        // 2. Zero out content.map entry slot
        FSError setRes = FSASetPosFile(fsa, fd, orphan.mapIndex * sizeof(ContentMapEntry));
        if (setRes == FS_ERROR_OK) {
            int writeRes = FSAWriteFile(fsa, zeroEntry, sizeof(ContentMapEntry), 1, fd, FSA_WRITE_FLAG_NONE);
            if (writeRes != 1) {
                WUPI_Log("Failed to zero map entry for %s\n", orphan.name.c_str());
                allOk = false;
            }
        } else {
            WUPI_Log("Failed to seek map entry for %s\n", orphan.name.c_str());
            allOk = false;
        }
    }

    free(zeroEntry);
    FSACloseFile(fsa, fd);
    return allOk;
}

struct RegionTitleInfo {
    uint64_t titleId;
    std::string name;
    int32_t version;
};

static std::vector<RegionTitleInfo> GetTargetRegionTitles(const std::string& targetRegion) {
    std::vector<RegionTitleInfo> titles;
    uint8_t regionChar = 'P';
    int32_t sysMenuVer = 610; // EUR default

    if (targetRegion == "USA") {
        regionChar = 'E';
        sysMenuVer = 609;
    } else if (targetRegion == "JPN") {
        regionChar = 'J';
        sysMenuVer = 608;
    } else if (targetRegion == "EUR") {
        regionChar = 'P';
        sysMenuVer = 610;
    }

    titles.push_back({0x0000000100000002ULL, "System Menu (vWii)", sysMenuVer});
    titles.push_back({0x0001000248435500ULL | regionChar, "Wii Menu Electronic Manual", 0});
    titles.push_back({0x0001000848414C00ULL | regionChar, "Region Select", 0});
    titles.push_back({0x0001000848435A00ULL | regionChar, "Wii System Transfer", 0});

    return titles;
}

std::vector<OldRegionTitle> GetInstalledOldRegionTitles(const std::string& targetRegion) {
    std::vector<OldRegionTitle> oldTitles;
    const struct {
        const char* reg;
        uint8_t rChar;
    } otherRegions[] = {
        {"EUR", 'P'},
        {"USA", 'E'},
        {"JPN", 'J'}
    };

    for (const auto& r : otherRegions) {
        if (targetRegion == r.reg) continue;

        uint64_t manualId = 0x0001000248435500ULL | r.rChar;
        if (CINS_TitleExists(manualId)) {
            oldTitles.push_back({manualId, "Wii Menu Electronic Manual", r.reg});
        }

        uint64_t regSelectId = 0x0001000848414C00ULL | r.rChar;
        if (CINS_TitleExists(regSelectId)) {
            oldTitles.push_back({regSelectId, "Region Select", r.reg});
        }

        uint64_t transferId = 0x0001000848435A00ULL | r.rChar;
        if (CINS_TitleExists(transferId)) {
            oldTitles.push_back({transferId, "Wii System Transfer", r.reg});
        }
    }

    return oldTitles;
}

void RegionChange_RunWizard() {
    WUPI_resetScreen();

    // 1. Detect Wii U Native Region & Current vWii Region
    VwiiSettings currentVwiiSettings;
    std::string currentVwiiRegion = "";
    if (Setting_ReadCurrent(currentVwiiSettings) && !currentVwiiSettings.area.empty()) {
        currentVwiiRegion = currentVwiiSettings.area;
    }

    std::string targetRegion = Setting_PromptRegionSelection("=== Region Change Wizard ===", currentVwiiRegion);
    if (targetRegion.empty()) {
        return;
    }

    // Confirmation Screen
    std::vector<std::string> confirmHeader = {
        "=== Confirm Region Change ===",
        "Target Region: " + targetRegion,
        "",
        "The wizard will perform the following steps:",
        " 1. Update setting.txt with " + targetRegion + " preset",
        " 2. Download and install " + targetRegion + " system titles from NUS",
        " 3. Prompt to remove old region system channels",
        " 4. Scan and clean up unreferenced region-specific shared contents",
        "",
        "Proceed with Region Change?"
    };
    std::vector<std::string> confirmOpts = {
        "Yes, proceed",
        "No, cancel"
    };

    if (ShowMenu(confirmHeader, confirmOpts) != 0) {
        return;
    }

    WUPI_resetScreen();
    bool settingUpdated = false;
    int titlesInstalled = 0;
    int titlesFailed = 0;
    int oldTitlesRemoved = 0;
    int sharedCleanedCount = 0;
    uint64_t sharedCleanedBytes = 0;

    // STEP 1: Update setting.txt
    WUPI_Log("--- Step 1/4: Updating setting.txt ---");
    VwiiSettings newSettings;
    if (!Setting_ReadCurrent(newSettings)) {
        Setting_RegenerateFromMCP(newSettings);
    }
    Setting_ApplyPreset(newSettings, targetRegion);
    if (Setting_Write(newSettings)) {
        WUPI_Log("setting.txt updated to %s successfully!\n", targetRegion.c_str());
        settingUpdated = true;
        sleep(1);
    } else {
        WUPI_Log("Error: Failed to save setting.txt.\n");
        WUPI_waitButton();
    }

    // STEP 2: Download and install target region titles
    WUPI_Log("\n--- Step 2/4: Installing %s System Titles ---", targetRegion.c_str());
    std::vector<RegionTitleInfo> targetTitles = GetTargetRegionTitles(targetRegion);

    for (size_t i = 0; i < targetTitles.size(); i++) {
        if (!State::AppRunning()) break;
        const auto& t = targetTitles[i];
        WUPI_Log("Processing (%d/%d): %s (ID: %08x-%08x)...",
                 (int)(i + 1), (int)targetTitles.size(), t.name.c_str(),
                 (uint32_t)(t.titleId >> 32), (uint32_t)(t.titleId));

        int32_t verToFetch = t.version;
        if (verToFetch == 0) {
            int32_t latest = NUS_GetLatestVersion(t.titleId);
            if (latest >= 0) {
                verToFetch = latest;
            }
        }

        DownloadResult res = NUS_DownloadAndInstall(t.titleId, verToFetch);
        if (res == DownloadResult::SUCCESS) {
            WUPI_Log("Installed successfully!\n");
            titlesInstalled++;
        } else if (res == DownloadResult::CANCELLED) {
            WUPI_Log("Installation cancelled.\n");
            titlesFailed++;
            break;
        } else {
            WUPI_Log("Installation failed for %s.\n", t.name.c_str());
            titlesFailed++;
        }
    }
    sleep(1);

    // STEP 3: Check and remove old region channel titles
    WUPI_Log("\n--- Step 3/4: Checking Old Region Channels ---");
    std::vector<OldRegionTitle> oldTitles = GetInstalledOldRegionTitles(targetRegion);
    if (!oldTitles.empty()) {
        std::vector<std::string> oldHeader = {
            "Old Region Channels Found:",
            "The following channels from other regions were detected:"
        };
        if (oldTitles.size() <= 4) {
            for (const auto& ot : oldTitles) {
                oldHeader.push_back(std::format(" - {} [{}] ({:08x})", ot.name, ot.region, (uint32_t)ot.titleId));
            }
        } else {
            for (size_t i = 0; i < 3; i++) {
                const auto& ot = oldTitles[i];
                oldHeader.push_back(std::format(" - {} [{}] ({:08x})", ot.name, ot.region, (uint32_t)ot.titleId));
            }
            oldHeader.push_back(std::format(" ... and {} more channel(s)", oldTitles.size() - 3));
        }
        oldHeader.push_back("");
        oldHeader.push_back("Would you like to uninstall these old region channels?");

        std::vector<std::string> oldOpts = {
            "Yes, remove old region channels (Recommended)",
            "No, keep them"
        };

        int oldChoice = ShowMenu(oldHeader, oldOpts);
        if (oldChoice == 0) {
            WUPI_resetScreen();
            WUPI_Log("Removing old region channels...\n");
            for (const auto& ot : oldTitles) {
                if (CINS_UninstallTitle(ot.titleId)) {
                    WUPI_Log("  - Removed: %s [%s]\n", ot.name.c_str(), ot.region.c_str());
                    oldTitlesRemoved++;
                } else {
                    WUPI_Log("  - Failed to remove: %s [%s]\n", ot.name.c_str(), ot.region.c_str());
                }
            }
            sleep(1);
        }
    } else {
        WUPI_Log("No conflicting old region channels found.\n");
    }

    // STEP 4: Scan and offer cleanup of unreferenced region-specific shared content
    WUPI_Log("\n--- Step 4/4: Shared Content Reference Scan ---");
    WUPI_Log("Scanning installed titles and content.map for orphan region assets...\n");
    std::vector<OrphanSharedContent> orphans = SharedContent_ScanRegionOrphans(fsaClient, targetRegion);

    if (!orphans.empty()) {
        uint64_t totalOrphanBytes = 0;
        std::vector<std::string> orphanHeader = {
            "Unreferenced Region Shared Content Found:",
            "These shared assets from other regions are no longer referenced:"
        };
        if (orphans.size() <= 4) {
            for (const auto& o : orphans) {
                totalOrphanBytes += o.fileSize;
                orphanHeader.push_back(std::format(" - {} [{}] ({:.1f} KB)",
                                       o.description, o.region, (double)o.fileSize / 1024.0));
            }
        } else {
            for (size_t i = 0; i < 3; i++) {
                const auto& o = orphans[i];
                totalOrphanBytes += o.fileSize;
                orphanHeader.push_back(std::format(" - {} [{}] ({:.1f} KB)",
                                       o.description, o.region, (double)o.fileSize / 1024.0));
            }
            for (size_t i = 3; i < orphans.size(); i++) {
                totalOrphanBytes += orphans[i].fileSize;
            }
            orphanHeader.push_back(std::format(" ... and {} more file(s)", orphans.size() - 3));
        }
        orphanHeader.push_back("");
        orphanHeader.push_back(std::format("Total space to reclaim: {:.2f} MB", (double)totalOrphanBytes / (1024.0 * 1024.0)));
        orphanHeader.push_back("Clean up these unreferenced shared files from slccmpt?");

        std::vector<std::string> orphanOpts = {
            "Yes, clean up shared content (Recommended)",
            "No, keep them"
        };

        int orphanChoice = ShowMenu(orphanHeader, orphanOpts);
        if (orphanChoice == 0) {
            WUPI_resetScreen();
            WUPI_Log("Cleaning up unreferenced shared contents...\n");
            if (SharedContent_CleanRegionOrphans(fsaClient, orphans)) {
                WUPI_Log("Shared content cleaned up successfully!\n");
                sharedCleanedCount = (int)orphans.size();
                sharedCleanedBytes = totalOrphanBytes;
            } else {
                WUPI_Log("Warning: Error occurred during shared content cleanup.\n");
            }
            sleep(1);
        }
    } else {
        WUPI_Log("No unreferenced region-specific shared content found.\n");
        sleep(1);
    }

    // FINAL SUMMARY SCREEN
    WUPI_resetScreen();
    WUPI_Log("=========================================");
    WUPI_Log("       REGION CHANGE WIZARD SUMMARY      ");
    WUPI_Log("=========================================\n");
    WUPI_Log("Target Region: %s\n", targetRegion.c_str());
    WUPI_Log("setting.txt: %s\n", settingUpdated ? "Updated" : "Failed / Unchanged");
    WUPI_Log("System Titles: %d installed, %d failed\n", titlesInstalled, titlesFailed);
    WUPI_Log("Old Region Channels: %d removed\n", oldTitlesRemoved);
    if (sharedCleanedCount > 0) {
        WUPI_Log("Shared Content Cleaned: %d files (%.2f MB reclaimed)\n",
                 sharedCleanedCount, (double)sharedCleanedBytes / (1024.0 * 1024.0));
    } else {
        WUPI_Log("Shared Content Cleaned: 0 files\n");
    }
    WUPI_Log("\nRegion change process complete!");
    WUPI_waitButton();
}
