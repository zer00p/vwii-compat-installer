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
#include <vector>
#include <string>

extern FSAClientHandle fsaClient;

void WUPI_fullWipeAndReinstall() {
    WUPI_resetScreen();

    // 1. Initial Confirmation & Dangerous Warning Screen
    std::vector<std::string> warningHeader = {
        "=== WARNING: FULL WIPE & REINSTALL ===",
        "",
        "This will COMPLETELY ERASE all data on SLCCMPT (vWii)!",
        "",
        "The following data will be wiped clean:",
        " - All installed channels, homebrew & forwarders",
        " - All save data, Miis, and user settings",
        " - All tickets",
        " - All custom IOS (d2x) and patches",
        "",
        "After wiping, you will be prompted to select the target region",
        "for setting.txt, and optionally download system titles from NUS.",
        "",
        "THIS ACTION CANNOT BE UNDONE.",
        "Are you sure you want to proceed?"
    };
    std::vector<std::string> warningOptions = {
        "No, cancel",
        "Yes, wipe SLCCMPT (vWii)"
    };

    if (ShowMenu(warningHeader, warningOptions) != 1) {
        return;
    }

    if (!State::AppRunning()) return;

    // 2. Step 1: Wipe SLCCMPT & Create Stock Root Directories
    WUPI_resetScreen();
    WUPI_Log("=========================================");
    WUPI_Log("      Step 1/3: Wiping SLCCMPT (vWii)    ");
    WUPI_Log("=========================================\n");

    bool wipeOk = FSARemoveTree(fsaClient, "/vol/slccmpt01", true);
    if (wipeOk) {
        WUPI_Log("SLCCMPT (vWii) wiped clean!\n");
    } else {
        WUPI_Log("Warning: Some items could not be removed during wipe.\n");
    }

    WUPI_Log("Creating stock root directory hierarchy...\n");
    if (FSA_InitStockRootDirs(fsaClient)) {
        WUPI_Log("Stock root directories initialized successfully.\n");
    } else {
        WUPI_Log("Warning: Failed to create some stock root directories.\n");
    }
    sleep(1);

    if (!State::AppRunning()) return;

    // 3. Step 2: Region Selection & setting.txt Regeneration
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
        WUPI_Log("SLCCMPT (vWii) was wiped, but setting.txt was not regenerated.\n");
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

    // 4. Step 3: Prompt User Before Reinstalling System Titles from NUS
    std::vector<std::string> nusPromptHeader = {
        "=== Step 3/3: Reinstall System Titles ===",
        "SLCCMPT (vWii) has been wiped and setting.txt regenerated.",
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

    // 5. Final Summary Screen
    WUPI_resetScreen();
    WUPI_Log("=========================================");
    WUPI_Log("     FULL WIPE & REINSTALL SUMMARY       ");
    WUPI_Log("=========================================\n");
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
