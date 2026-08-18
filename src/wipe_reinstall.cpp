#include "wipe_reinstall.h"
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

static void RemoveSystemCategories(FSAClientHandle fsa, const std::string& parentPath) {
    FSADirectoryHandle dir;
    if (FSAOpenDir(fsa, parentPath.c_str(), &dir) != FS_ERROR_OK) {
        return;
    }

    FSADirectoryEntry* entry = (FSADirectoryEntry*)memalign(0x40, sizeof(FSADirectoryEntry));
    if (!entry) {
        FSACloseDir(fsa, dir);
        return;
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

    for (const auto& p : toRemove) {
        FSARemoveTree(fsa, p, false);
    }
}

static void CleanSysDirectory(FSAClientHandle fsa, bool keepUidAndCert) {
    if (!keepUidAndCert) {
        FSARemoveTree(fsa, "/vol/slccmpt01/sys", true);
        return;
    }

    FSADirectoryHandle dir;
    if (FSAOpenDir(fsa, "/vol/slccmpt01/sys", &dir) != FS_ERROR_OK) {
        return;
    }

    FSADirectoryEntry* entry = (FSADirectoryEntry*)memalign(0x40, sizeof(FSADirectoryEntry));
    if (!entry) {
        FSACloseDir(fsa, dir);
        return;
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

    for (const auto& item : toRemove) {
        if (item.second) {
            FSARemoveTree(fsa, item.first, false);
        } else {
            FSARemove(fsa, item.first.c_str());
        }
    }
}

static void CleanRootUnknownEntries(FSAClientHandle fsa) {
    FSADirectoryHandle dir;
    if (FSAOpenDir(fsa, "/vol/slccmpt01", &dir) != FS_ERROR_OK) {
        return;
    }

    FSADirectoryEntry* entry = (FSADirectoryEntry*)memalign(0x40, sizeof(FSADirectoryEntry));
    if (!entry) {
        FSACloseDir(fsa, dir);
        return;
    }

    const std::vector<std::string> knownDirs = {
        "sys", "title", "ticket", "shared1", "shared2", "content", "tmp", "import"
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

    for (const auto& item : toRemove) {
        if (item.second) {
            FSARemoveTree(fsa, item.first, false);
        } else {
            FSARemove(fsa, item.first.c_str());
        }
    }
}

static bool PerformWipe(FSAClientHandle fsa, WipeMode mode) {
    if (mode == WipeMode::FULL_WIPE) {
        return FSARemoveTree(fsa, "/vol/slccmpt01", true);
    }

    // Common staging / temp folders
    FSARemoveTree(fsa, "/vol/slccmpt01/content", true);
    FSARemoveTree(fsa, "/vol/slccmpt01/tmp", true);
    FSARemoveTree(fsa, "/vol/slccmpt01/import", true);

    if (mode == WipeMode::EXCLUDE_USER_TITLES_AND_TICKETS) {
        // Remove system titles only; keep user titles (00010001, 00010000, 00010004, 00010005, etc.)
        RemoveSystemCategories(fsa, "/vol/slccmpt01/title");

        // Remove system tickets only; keep user tickets
        RemoveSystemCategories(fsa, "/vol/slccmpt01/ticket");

        // Keep /shared1 and /shared2 for user title assets
        // Clean sys but preserve uid.sys and cert.sys
        CleanSysDirectory(fsa, true);
    } else if (mode == WipeMode::EXCLUDE_USER_TICKETS) {
        // Remove ALL titles (system and user)
        FSARemoveTree(fsa, "/vol/slccmpt01/title", true);

        // Remove system tickets only; keep user tickets
        RemoveSystemCategories(fsa, "/vol/slccmpt01/ticket");

        // Clean shared folders
        FSARemoveTree(fsa, "/vol/slccmpt01/shared1", true);
        FSARemoveTree(fsa, "/vol/slccmpt01/shared2", true);

        // Clean sys completely
        CleanSysDirectory(fsa, false);
    }

    // Clean any stray non-standard entries in SLCCMPT root
    CleanRootUnknownEntries(fsa);

    return true;
}

static bool ConfirmWipe(WipeMode mode) {
    WUPI_resetScreen();
    std::vector<std::string> header;
    std::vector<std::string> options;

    if (mode == WipeMode::EXCLUDE_USER_TITLES_AND_TICKETS) {
        header = {
            "=== WARNING: WIPE (EXCLUDE USER TITLES & TICKETS) ===",
            "",
            "This will wipe system files while PRESERVING user channels & saves!",
            "",
            "The following data will be wiped clean:",
            " - All system titles (System Menu, IOS, BC, MIOS, system channels)",
            " - All system tickets",
            " - All custom IOS (d2x) and patches",
            " - Temporary and cache files",
            "",
            "The following data will be PRESERVED:",
            " - All user channels (HBC, Virtual Console, WiiWare, forwarders)",
            " - All game save data and /sys/uid.sys mappings",
            " - All user tickets and shared assets",
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
            "",
            "This will wipe all titles and saves while PRESERVING user tickets!",
            "",
            "The following data will be wiped clean:",
            " - All installed channels, homebrew & forwarders",
            " - All save data, Miis, and user settings",
            " - All system tickets (IOS, System Menu, system channels)",
            " - All custom IOS (d2x) and patches",
            " - Shared content and cache files",
            "",
            "The following data will be PRESERVED:",
            " - All user tickets (WiiWare, VC, homebrew, DLC, disc tickets)",
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
            "",
            "This will COMPLETELY ERASE all data on SLCCMPT (vWii)!",
            "",
            "The following data will be wiped clean:",
            " - All installed channels, homebrew & forwarders",
            " - All save data, Miis, and user settings",
            " - All tickets (system and user)",
            " - All custom IOS (d2x) and patches",
            " - All shared content and cache files",
            "",
            "After wiping, you will be prompted to select the target region",
            "for setting.txt, and optionally download system titles from NUS.",
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

    bool wipeOk = PerformWipe(fsaClient, mode);
    if (wipeOk) {
        WUPI_Log("Wipe operation completed successfully!\n");
    } else {
        WUPI_Log("Warning: Some items could not be removed during wipe.\n");
    }

    WUPI_Log("Ensuring stock root directory hierarchy...\n");
    if (FSA_InitStockRootDirs(fsaClient)) {
        WUPI_Log("Stock root directories initialized successfully.\n");
    } else {
        WUPI_Log("Warning: Failed to create some stock root directories.\n");
    }
    sleep(1);

    if (!State::AppRunning()) return;

    // 2. Step 2: Region Selection & setting.txt Regeneration
    VwiiSettings mcpSettings;
    std::string wiiuRegion = "EUR";
    if (Setting_RegenerateFromMCP(mcpSettings) && !mcpSettings.area.empty()) {
        wiiuRegion = mcpSettings.area;
    }

    std::vector<std::string> regions;
    // Native Wii U region first as recommended default
    regions.push_back(wiiuRegion);
    for (const char* r : {"EUR", "USA", "JPN"}) {
        if (wiiuRegion != r) {
            regions.push_back(r);
        }
    }

    std::vector<std::string> regionOptions;
    for (size_t i = 0; i < regions.size(); i++) {
        std::string opt = regions[i];
        if (regions[i] == wiiuRegion) {
            opt += " (Console Native Region - Recommended)";
        }
        regionOptions.push_back(opt);
    }

    std::vector<std::string> selectHeader = {
        "=== Step 2/3: Select Target vWii Region ===",
        "Wii U Native Region: " + wiiuRegion,
        "",
        "Select target region for setting.txt:"
    };

    int selectedRegionIdx = ShowMenu(selectHeader, regionOptions);
    if (selectedRegionIdx < 0 || selectedRegionIdx >= (int)regions.size()) {
        WUPI_resetScreen();
        WUPI_Log("Region selection cancelled.\n");
        WUPI_Log("setting.txt was not regenerated.\n");
        WUPI_waitButton();
        return;
    }
    std::string targetRegion = regions[selectedRegionIdx];

    WUPI_resetScreen();
    WUPI_Log("=========================================");
    WUPI_Log("     Regenerating setting.txt (%s)       ", targetRegion.c_str());
    WUPI_Log("=========================================\n");

    VwiiSettings newSettings;
    if (!Setting_RegenerateFromMCP(newSettings)) {
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

        for (size_t i = 0; i < g_numNusTitles; i++) {
            if (!State::AppRunning()) break;
            const auto& t = g_nusTitles[i];

            WUPI_Log("--- Processing %s (%d/%d) ---", t.name, (int)(i + 1), (int)g_numNusTitles);

            if (NUS_InstallSystemTitle(&t, regionCode)) {
                WUPI_Log("Installation complete!\n");
                titlesInstalled++;
                sleep(1);
            } else {
                titlesFailed++;
                WUPI_putstr("Press A to continue with next title, B to abort.");
                if (!WaitPrompt()) break;
            }
        }
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
        "Reinstall System Titles (NUS)",
        "Full Wipe (Exclude User Titles & Tickets)",
        "Full Wipe (Exclude User Tickets)",
        "Full Wipe & Reinstall"
    };

    while (State::AppRunning()) {
        int selected = ShowMenu(header, options);
        if (selected == 0) {
            WUPI_NusMenu();
        } else if (selected == 1) {
            WUPI_wipeExcludeTitlesAndTickets();
        } else if (selected == 2) {
            WUPI_wipeExcludeTickets();
        } else if (selected == 3) {
            WUPI_fullWipeAndReinstall();
        } else if (selected == -1) {
            break;
        }
    }
}
