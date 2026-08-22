#include "wipe_reinstall.h"
#include "system_scanner.h"
#include "settingtxt_manager.h"
#include "FSAUtils.h"
#include "wad.h"
#include "log.h"
#include "MenuUtils.h"
#include "ScreenUtils.h"
#include "StateUtils.h"
#include "InputUtils.h"

#include <coreinit/filesystem_fsa.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <vector>
#include <string>
#include <utility>

extern FSAClientHandle fsaClient;

enum class WipeMode {
    EXCLUDE_USER_TITLES_AND_TICKETS,
    EXCLUDE_USER_TICKETS,
    FULL_WIPE
};

static bool IsSystemCategory(const std::string& folderName) {
    // 00000001: System titles (System Menu, IOS, BC, MIOS)
    // 00010002: System channels (Mii Channel, Shopping Channel, Wii U Menu Channel, etc.)
    // 00010008: Hidden system titles (Region Select, System Transfer, EULA)
    return (folderName == "00000001" || folderName == "00010002" || folderName == "00010008");
}

static bool RemoveSystemCategories(FSAClientHandle fsa, const std::string& parentPath, FSARemoveCallback onRemove = nullptr) {
    FSADirectoryHandle dir;
    if (FSAOpenDir(fsa, parentPath.c_str(), &dir) != FS_ERROR_OK) {
        return true;
    }

    FSADirectoryEntry* entry = (FSADirectoryEntry*)memalign(0x40, sizeof(FSADirectoryEntry));
    if (!entry) {
        FSACloseDir(fsa, dir);
        return false;
    }

    std::vector<std::string> toRemove;
    while (FSAReadDir(fsa, dir, entry) == FS_ERROR_OK) {
        if (strcmp(entry->name, ".") == 0 || strcmp(entry->name, "..") == 0) {
            continue;
        }
        if (entry->info.flags & FS_STAT_DIRECTORY) {
            if (IsSystemCategory(entry->name)) {
                toRemove.push_back(parentPath + "/" + entry->name);
            }
        } else {
            toRemove.push_back(parentPath + "/" + entry->name);
        }
    }
    free(entry);
    FSACloseDir(fsa, dir);

    bool allOk = true;
    for (const auto& p : toRemove) {
        if (!FSARemoveTree(fsa, p, false, onRemove)) {
            WUPI_Log("RemoveSystemCategories: Failed to remove %s\n", p.c_str());
            allOk = false;
        }
    }
    return allOk;
}

static bool CleanSysDirectory(FSAClientHandle fsa, bool keepUidAndCert, FSARemoveCallback onRemove = nullptr) {
    if (!keepUidAndCert) {
        return FSARemoveTree(fsa, "/vol/slccmpt01/sys", true, onRemove);
    }

    FSADirectoryHandle dir;
    if (FSAOpenDir(fsa, "/vol/slccmpt01/sys", &dir) != FS_ERROR_OK) {
        return true;
    }

    FSADirectoryEntry* entry = (FSADirectoryEntry*)memalign(0x40, sizeof(FSADirectoryEntry));
    if (!entry) {
        FSACloseDir(fsa, dir);
        return false;
    }

    std::vector<std::pair<std::string, bool>> toRemove;
    while (FSAReadDir(fsa, dir, entry) == FS_ERROR_OK) {
        if (strcmp(entry->name, ".") == 0 || strcmp(entry->name, "..") == 0) {
            continue;
        }
        if (strcmp(entry->name, "uid.sys") == 0 || strcmp(entry->name, "cert.sys") == 0) {
            continue;
        }
        toRemove.push_back({"/vol/slccmpt01/sys/" + std::string(entry->name), (entry->info.flags & FS_STAT_DIRECTORY) != 0});
    }
    free(entry);
    FSACloseDir(fsa, dir);

    bool allOk = true;
    for (const auto& item : toRemove) {
        if (item.second) {
            if (!FSARemoveTree(fsa, item.first, false, onRemove)) {
                WUPI_Log("CleanSysDirectory: Failed to remove %s\n", item.first.c_str());
                allOk = false;
            }
        } else {
            if (onRemove) {
                onRemove(item.first);
            }
            if (FSARemove(fsa, item.first.c_str()) != FS_ERROR_OK) {
                WUPI_Log("CleanSysDirectory: Failed to remove %s\n", item.first.c_str());
                allOk = false;
            }
        }
    }
    return allOk;
}

static bool CleanRootUnknownEntries(FSAClientHandle fsa, FSARemoveCallback onRemove = nullptr) {
    FSADirectoryHandle dir;
    if (FSAOpenDir(fsa, "/vol/slccmpt01", &dir) != FS_ERROR_OK) {
        return true;
    }

    FSADirectoryEntry* entry = (FSADirectoryEntry*)memalign(0x40, sizeof(FSADirectoryEntry));
    if (!entry) {
        FSACloseDir(fsa, dir);
        return false;
    }

    const std::vector<std::string> knownDirs = {
        "sys", "title", "ticket", "shared1", "shared2", "tmp", "import", "meta", "wfs"
    };

    std::vector<std::pair<std::string, bool>> toRemove;
    while (FSAReadDir(fsa, dir, entry) == FS_ERROR_OK) {
        if (strcmp(entry->name, ".") == 0 || strcmp(entry->name, "..") == 0) {
            continue;
        }
        bool isKnown = false;
        for (const auto& k : knownDirs) {
            if (k == entry->name) {
                isKnown = true;
                break;
            }
        }
        if (!isKnown) {
            toRemove.push_back({"/vol/slccmpt01/" + std::string(entry->name), (entry->info.flags & FS_STAT_DIRECTORY) != 0});
        }
    }
    free(entry);
    FSACloseDir(fsa, dir);

    bool allOk = true;
    for (const auto& item : toRemove) {
        if (item.second) {
            if (!FSARemoveTree(fsa, item.first, false, onRemove)) {
                WUPI_Log("CleanRootUnknownEntries: Failed to remove %s\n", item.first.c_str());
                allOk = false;
            }
        } else {
            if (onRemove) {
                onRemove(item.first);
            }
            if (FSARemove(fsa, item.first.c_str()) != FS_ERROR_OK) {
                WUPI_Log("CleanRootUnknownEntries: Failed to remove %s\n", item.first.c_str());
                allOk = false;
            }
        }
    }
    return allOk;
}

static bool PerformWipe(FSAClientHandle fsa, WipeMode mode, FSARemoveCallback onRemove = nullptr) {
    if (mode == WipeMode::FULL_WIPE) {
        return FSARemoveTree(fsa, "/vol/slccmpt01", true, onRemove);
    }

    bool allOk = true;

    // Common staging / temp folders
    allOk &= FSARemoveTree(fsa, "/vol/slccmpt01/tmp", true, onRemove);
    allOk &= FSARemoveTree(fsa, "/vol/slccmpt01/import", true, onRemove);

    if (mode == WipeMode::EXCLUDE_USER_TITLES_AND_TICKETS) {
        // Remove system titles only; keep user titles (00010001, 00010000, 00010004, 00010005, etc.)
        allOk &= RemoveSystemCategories(fsa, "/vol/slccmpt01/title", onRemove);

        // Remove system tickets only; keep user tickets
        allOk &= RemoveSystemCategories(fsa, "/vol/slccmpt01/ticket", onRemove);

        // Keep /shared1 and /shared2 for user title assets
        // Clean sys but preserve uid.sys and cert.sys
        allOk &= CleanSysDirectory(fsa, true, onRemove);
    } else if (mode == WipeMode::EXCLUDE_USER_TICKETS) {
        // Remove ALL titles (system and user)
        allOk &= FSARemoveTree(fsa, "/vol/slccmpt01/title", true, onRemove);

        // Remove system tickets only; keep user tickets
        allOk &= RemoveSystemCategories(fsa, "/vol/slccmpt01/ticket", onRemove);

        // Clean shared folders
        allOk &= FSARemoveTree(fsa, "/vol/slccmpt01/shared1", true, onRemove);
        allOk &= FSARemoveTree(fsa, "/vol/slccmpt01/shared2", true, onRemove);

        // Clean sys completely
        allOk &= CleanSysDirectory(fsa, false, onRemove);
    }

    // Clean any stray non-standard entries in SLCCMPT root
    allOk &= CleanRootUnknownEntries(fsa, onRemove);

    return allOk;
}

static bool ConfirmWipe(WipeMode mode) {
    WUPI_resetScreen();
    std::vector<std::string> header;
    std::vector<std::string> options;

    if (mode == WipeMode::EXCLUDE_USER_TITLES_AND_TICKETS) {
        header = {
            "=== WARNING: WIPE (EXCLUDE USER TITLES & TICKETS) ===",
            "This will wipe system files while PRESERVING user channels & saves!",
            "",
            "Wipes: System titles & tickets, custom IOS/patches, cache files",
            "Keeps: User channels (HBC, VC, WiiWare), game saves, user tickets",
            "",
            "THIS ACTION CANNOT BE UNDONE.",
            "Are you sure you want to proceed?"
        };
        options = {
            "No, cancel",
            "Yes, wipe system titles (Keep user titles & tickets)"
        };
    } else if (mode == WipeMode::EXCLUDE_USER_TICKETS) {
        header = {
            "=== WARNING: WIPE (EXCLUDE USER TICKETS) ===",
            "This will wipe all titles and saves while PRESERVING user tickets!",
            "",
            "Wipes: All channels, saves, Miis, system tickets, cIOS",
            "Keeps: User tickets (WiiWare, VC, homebrew, DLC, disc tickets)",
            "",
            "THIS ACTION CANNOT BE UNDONE.",
            "Are you sure you want to proceed?"
        };
        options = {
            "No, cancel",
            "Yes, wipe SLCCMPT (Keep user tickets)"
        };
    } else { // FULL_WIPE
        header = {
            "=== WARNING: FULL WIPE & REINSTALL ===",
            "This will COMPLETELY ERASE all data on SLCCMPT (vWii)!",
            "",
            "Wipes: All channels, saves, Miis, tickets (sys+user), cIOS, & files",
            "Next: Prompt for target region, regenerate setting.txt, NUS install",
            "",
            "THIS ACTION CANNOT BE UNDONE.",
            "Are you sure you want to proceed?"
        };
        options = {
            "No, cancel",
            "Yes, wipe SLCCMPT (vWii)"
        };
    }

    return (ShowMenu(header, options) == 1);
}

static void RunWipeWizard(WipeMode mode) {
    if (!ConfirmWipe(mode)) {
        return;
    }

    if (!State::AppRunning()) return;

    std::string currentVwiiRegion;
    VwiiSettings curSettings;
    if (Setting_ReadCurrent(curSettings) && !curSettings.area.empty()) {
        currentVwiiRegion = curSettings.area;
    }

    // 1. Step 1: Wipe Execution
    WUPI_resetScreen();
    WUPI_Log("=========================================");
    const char* stepTitle = "Step 1/3: Wiping SLCCMPT (vWii)";
    if (mode == WipeMode::EXCLUDE_USER_TITLES_AND_TICKETS) {
        stepTitle = "Step 1/3: Wiping System Titles & Tickets";
    } else if (mode == WipeMode::EXCLUDE_USER_TICKETS) {
        stepTitle = "Step 1/3: Wiping (Preserving User Tickets)";
    }
    WUPI_Log("   %s   ", stepTitle);
    WUPI_Log("=========================================\n");

    auto logDeletion = [](const std::string& path) {
        std::string_view clean = VwiiCleanPath(path);
        WUPI_Log("Deleting %.*s\n", (int)clean.size(), clean.data());
    };

    bool wipeOk = PerformWipe(fsaClient, mode, logDeletion);
    if (wipeOk) {
        WUPI_Log("\nWipe operation completed successfully!\n");
    } else {
        WUPI_Log("\nWarning: Some items could not be removed during wipe.\n");
    }

    WUPI_Log("Ensuring stock root directory hierarchy...\n");
    bool stockDirsOk = FSA_InitStockRootDirs(fsaClient);
    if (stockDirsOk) {
        WUPI_Log("Stock root directories initialized successfully.\n");
    } else {
        WUPI_Log("Warning: Failed to create some stock root directories.\n");
    }
    sleep(1);
    if (!wipeOk || !stockDirsOk) {
        WUPI_putstr("\nErrors encountered during wipe / root directory setup.");
        WUPI_waitButton();
    } else {
        sleep(1);
    }

    if (!State::AppRunning()) return;

    // 2. Step 2: Region Selection & setting.txt Regeneration
    std::string targetRegion = Setting_PromptRegionSelection("=== Step 2/3: Select Target vWii Region ===", currentVwiiRegion);
    if (targetRegion.empty()) {
        WUPI_resetScreen();
        WUPI_Log("Region selection cancelled.\n");
        WUPI_Log("setting.txt was not regenerated.\n");
        WUPI_waitButton();
        return;
    }

    WUPI_resetScreen();
    WUPI_Log("=========================================");
    WUPI_Log("     Regenerating setting.txt (%s)       ", targetRegion.c_str());
    WUPI_Log("=========================================\n");

    VwiiSettings newSettings;
    bool mcpOk = Setting_RegenerateFromMCP(newSettings);
    if (!mcpOk) {
        WUPI_Log("Warning: Could not read MCP SysProd, using defaults.\n");
    }
    Setting_ApplyPreset(newSettings, targetRegion);

    bool settingWritten = Setting_Write(newSettings);
    if (settingWritten) {
        WUPI_Log("setting.txt created and encrypted for %s successfully!\n", targetRegion.c_str());
    } else {
        WUPI_Log("Error: Failed to write setting.txt.\n");
    }
    sleep(1);
    if (!settingWritten || !mcpOk) {
        if (!settingWritten) {
            WUPI_putstr("\nError: Failed to write setting.txt!");
        }
        WUPI_waitButton();
    } else {
        sleep(1);
    }

    if (!State::AppRunning()) return;

    // 3. Step 3: Prompt User Before Reinstalling System Titles from NUS
    std::vector<std::string> nusPromptHeader = {
        "=== Step 3/3: Reinstall System Titles ===",
        "Wipe operation completed and setting.txt regenerated.",
        "",
        "Would you like to download and reinstall all 38 system titles from NUS now?",
        "",
        "If you skip, you can install system WADs manually from the SD card."
    };
    std::vector<std::string> nusPromptOptions = {
        "Yes, download and reinstall from NUS (Recommended)",
        "No, skip NUS download (I will install WADs manually)"
    };

    int nusChoice = ShowMenu(nusPromptHeader, nusPromptOptions);
    bool doNusInstall = (nusChoice == 0);

    int titlesInstalled = 0;
    int titlesFailed = 0;

    if (doNusInstall) {
        WUPI_resetScreen();
        WUPI_Log("=========================================");
        WUPI_Log("   Reinstalling System Titles from NUS   ");
        WUPI_Log("=========================================\n");

        int32_t regionCode = Setting_GetRegionIndex(newSettings);
        if (regionCode == -1) regionCode = 2; // Default to EUR (2) if unknown

        std::vector<const NusTitle*> allTitles;
        for (size_t i = 0; i < g_numNusTitles; i++) {
            allTitles.push_back(&g_nusTitles[i]);
        }
        NUS_InstallTitlesBatch(allTitles, regionCode, titlesInstalled, titlesFailed);
    }

    if (!State::AppRunning()) return;

    // 4. Final Summary Screen
    WUPI_resetScreen();
    WUPI_Log("=========================================");
    WUPI_Log("            OPERATION SUMMARY            ");
    WUPI_Log("=========================================\n");
    const char* modeName = "Full Wipe & Reinstall";
    if (mode == WipeMode::EXCLUDE_USER_TITLES_AND_TICKETS) {
        modeName = "Wipe (Preserved User Titles & Tickets)";
    } else if (mode == WipeMode::EXCLUDE_USER_TICKETS) {
        modeName = "Wipe (Preserved User Tickets)";
    }
    WUPI_Log("Operation: %s\n", modeName);
    WUPI_Log("SLCCMPT (vWii) Wipe: %s\n", wipeOk ? "Completed" : "Warnings encountered");
    WUPI_Log("Target Region: %s\n", targetRegion.c_str());
    WUPI_Log("setting.txt: %s\n", settingWritten ? "Regenerated" : "Failed");
    if (doNusInstall) {
        WUPI_Log("System Titles: %d installed, %d failed (out of %d)\n",
                 titlesInstalled, titlesFailed, (int)g_numNusTitles);
    } else {
        WUPI_Log("System Titles: Skipped (Install WADs manually)\n");
    }
    WUPI_Log("\nProcess complete!");
    WUPI_waitButton();
}

void WUPI_wipeExcludeTitlesAndTickets() {
    RunWipeWizard(WipeMode::EXCLUDE_USER_TITLES_AND_TICKETS);
}

void WUPI_wipeExcludeTickets() {
    RunWipeWizard(WipeMode::EXCLUDE_USER_TICKETS);
}

void WUPI_fullWipeAndReinstall() {
    RunWipeWizard(WipeMode::FULL_WIPE);
}

void WUPI_reinstallWipeMenu() {
    std::vector<std::string> header = {
        "Reinstall & Wipe Menu:",
        "Select an operation:"
    };
    std::vector<std::string> options = {
        "Scan and Restore System",
        "Reinstall System Titles (NUS)",
        "Full Wipe (Exclude User Titles & Tickets)",
        "Full Wipe (Exclude User Tickets)",
        "Full Wipe & Reinstall"
    };

    while (State::AppRunning()) {
        int selected = ShowMenu(header, options);
        if (selected == 0) {
            WUPI_ScanAndRestoreMenu();
        } else if (selected == 1) {
            WUPI_NusMenu();
        } else if (selected == 2) {
            WUPI_wipeExcludeTitlesAndTickets();
        } else if (selected == 3) {
            WUPI_wipeExcludeTickets();
        } else if (selected == 4) {
            WUPI_fullWipeAndReinstall();
        } else if (selected == -1) {
            break;
        }
    }
}
