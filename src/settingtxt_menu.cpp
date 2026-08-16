#include "settingtxt_menu.h"
#include "settingtxt_manager.h"
#include "MenuUtils.h"
#include "ScreenUtils.h"
#include "StateUtils.h"
#include "log.h"

#include <vector>
#include <string>
#include <cstdio>
#include <unistd.h>

static void ShowViewCurrentScreen() {
    WUPI_resetScreen();
    VwiiSettings settings;
    bool exists = Setting_ReadCurrent(settings);

    std::vector<std::string> header = {
        "=== Current vWii setting.txt ===",
        exists ? "Status: Found on SLCCMPT" : "Status: NOT FOUND (File or directory missing)",
        ""
    };

    std::vector<std::string> options;
    if (exists) {
        options.push_back("AREA:  " + settings.area);
        options.push_back("MODEL: " + settings.model);
        char dvdBuf[32];
        snprintf(dvdBuf, sizeof(dvdBuf), "DVD:   %u%s", (unsigned int)settings.dvd, settings.dvd == 0 ? " (Default)" : "");
        options.push_back(dvdBuf);
        options.push_back("MPCH:  " + settings.mpch);
        options.push_back("CODE:  " + settings.code);
        options.push_back("SERNO: " + settings.serno);
        options.push_back("VIDEO: " + settings.video);
        options.push_back("GAME:  " + settings.game);
        options.push_back("");
        options.push_back("Back");
    } else {
        options.push_back("No setting.txt is present.");
        options.push_back("Use 'Regenerate setting.txt' to restore it.");
        options.push_back("");
        options.push_back("Back");
    }

    ShowMenu(header, options);
}

static void ShowRegenerateScreen() {
    WUPI_resetScreen();
    VwiiSettings mcpSettings;
    if (!Setting_RegenerateFromMCP(mcpSettings)) {
        WUPI_Log("Error: Failed to query Wii U system production settings (MCP).\n");
        WUPI_waitButton();
        return;
    }

    std::vector<std::string> confirmHeader = {
        "=== Regenerate setting.txt ===",
        "Values detected from Wii U Hardware:",
        " - AREA:  " + mcpSettings.area,
        " - MODEL: " + mcpSettings.model,
        " - DVD:   0 (Default)",
        " - MPCH:  " + mcpSettings.mpch,
        " - CODE:  " + mcpSettings.code,
        " - SERNO: " + mcpSettings.serno,
        " - VIDEO: " + mcpSettings.video,
        " - GAME:  " + mcpSettings.game,
        "",
        "This will create/overwrite /vol/slccmpt01/.../setting.txt.",
        "Missing directories will be created automatically.",
        "Are you sure you want to proceed?"
    };

    std::vector<std::string> confirmOptions = {
        "Yes, regenerate and write setting.txt",
        "No, cancel"
    };

    if (ShowMenu(confirmHeader, confirmOptions) != 0) {
        return;
    }

    if (!State::AppRunning()) return;

    WUPI_resetScreen();
    WUPI_Log("Regenerating setting.txt...\n");

    if (Setting_Write(mcpSettings)) {
        WUPI_Log("Success: setting.txt successfully generated and written!\n");
    } else {
        WUPI_Log("Error: Failed to write setting.txt to SLCCMPT!\n");
    }
    WUPI_waitButton();
}

static void ShowRegionPresetsScreen() {
    while (State::AppRunning()) {
        WUPI_resetScreen();
        std::vector<std::string> header = {
            "=== Change Region Preset ===",
            "Select target vWii region preset:"
        };
        std::vector<std::string> options = {
            "Europe (EUR / PAL / EU)",
            "USA (USA / NTSC / US)",
            "Japan (JPN / NTSC / JP)"
        };

        int selected = ShowMenu(header, options);
        if (selected == -1) break;

        std::string targetRegion;
        if (selected == 0) targetRegion = "EUR";
        else if (selected == 1) targetRegion = "USA";
        else if (selected == 2) targetRegion = "JPN";

        VwiiSettings settings;
        if (!Setting_ReadCurrent(settings)) {
            Setting_RegenerateFromMCP(settings);
        }
        Setting_ApplyPreset(settings, targetRegion);

        std::vector<std::string> confirmHeader = {
            "=== Confirm Region Change ===",
            "The following settings will be applied:",
            " - AREA:  " + settings.area,
            " - MODEL: " + settings.model,
            " - VIDEO: " + settings.video,
            " - GAME:  " + settings.game,
            " - CODE:  " + settings.code,
            " - SERNO: " + settings.serno,
            "",
            "Apply preset to setting.txt?"
        };

        std::vector<std::string> confirmOptions = {
            "Yes, apply and save",
            "No, cancel"
        };

        if (ShowMenu(confirmHeader, confirmOptions) == 0) {
            if (!State::AppRunning()) break;
            WUPI_resetScreen();
            WUPI_Log("Writing updated setting.txt...\n");
            if (Setting_Write(settings)) {
                WUPI_Log("Region preset '%s' successfully applied!\n", targetRegion.c_str());
            } else {
                WUPI_Log("Error writing setting.txt!\n");
            }
            WUPI_waitButton();
            break;
        }
    }
}

static void ShowDVDEditor(VwiiSettings& settings) {
    WUPI_resetScreen();
    char curBuf[64];
    snprintf(curBuf, sizeof(curBuf), "Current value: %u%s", (unsigned int)settings.dvd, settings.dvd == 0 ? " (Default)" : "");

    std::vector<std::string> header = {
        "=== Edit DVD Field ===",
        curBuf,
        "Select DVD integer value:"
    };

    std::vector<std::string> options = {
        "0 (Default)",
        "1",
        "2",
        "3",
        "4",
        "5",
        "6"
    };

    int selected = ShowMenu(header, options);
    if (selected >= 0 && selected < (int)options.size()) {
        settings.dvd = (uint8_t)selected;
    }
}

static void ShowFieldEditorScreen() {
    VwiiSettings settings;
    if (!Setting_ReadCurrent(settings)) {
        if (!Setting_RegenerateFromMCP(settings)) {
            settings.area = "EUR";
            settings.model = "RVL-001(EUR)";
            settings.dvd = 0;
            settings.mpch = "0x7FFE";
            settings.code = "IEL";
            settings.serno = "000000000";
            settings.video = "PAL";
            settings.game = "EU";
        }
    }

    while (State::AppRunning()) {
        WUPI_resetScreen();
        std::vector<std::string> header = {
            "=== Edit Individual Fields ===",
            "Select a field to modify, then select Save:"
        };

        char dvdStr[32];
        snprintf(dvdStr, sizeof(dvdStr), "DVD:   %u%s", (unsigned int)settings.dvd, settings.dvd == 0 ? " (Default)" : "");

        std::vector<std::string> options = {
            "AREA:  " + settings.area,
            "MODEL: " + settings.model,
            dvdStr,
            "MPCH:  " + settings.mpch,
            "CODE:  " + settings.code,
            "SERNO: " + settings.serno,
            "VIDEO: " + settings.video,
            "GAME:  " + settings.game,
            "--> Save & Apply to SLCCMPT"
        };

        int selected = ShowMenu(header, options);
        if (selected == -1) break;

        if (selected == 0) { // AREA
            std::vector<std::string> areaOpts = { "EUR", "USA", "JPN" };
            int aSel = ShowMenu({ "Select AREA:" }, areaOpts);
            if (aSel >= 0) {
                settings.area = areaOpts[aSel];
                settings.model = "RVL-001(" + settings.area + ")";
            }
        } else if (selected == 1) { // MODEL
            std::vector<std::string> modelOpts = { "RVL-001(EUR)", "RVL-001(USA)", "RVL-001(JPN)" };
            int mSel = ShowMenu({ "Select MODEL:" }, modelOpts);
            if (mSel >= 0) settings.model = modelOpts[mSel];
        } else if (selected == 2) { // DVD
            ShowDVDEditor(settings);
        } else if (selected == 3) { // MPCH
            std::vector<std::string> mpchOpts = { "0x7FFE (Standard)" };
            int mpSel = ShowMenu({ "Select MPCH:" }, mpchOpts);
            if (mpSel >= 0) settings.mpch = "0x7FFE";
        } else if (selected == 4) { // CODE
            std::vector<std::string> codeOpts = { "IEL (Europe)", "IUL (USA)", "IJL (Japan)", "Keep current (" + settings.code + ")" };
            int cSel = ShowMenu({ "Select CODE prefix:" }, codeOpts);
            if (cSel == 0) settings.code = "IEL";
            else if (cSel == 1) settings.code = "IUL";
            else if (cSel == 2) settings.code = "IJL";
        } else if (selected == 5) { // SERNO
            VwiiSettings mcp;
            if (Setting_RegenerateFromMCP(mcp)) {
                std::vector<std::string> serOpts = { "Re-read from Wii U MCP (" + mcp.serno + ")", "Keep current (" + settings.serno + ")" };
                int sSel = ShowMenu({ "Select Serial Number source:" }, serOpts);
                if (sSel == 0) settings.serno = mcp.serno;
            }
        } else if (selected == 6) { // VIDEO
            std::vector<std::string> vidOpts = { "PAL", "NTSC", "MPAL" };
            int vSel = ShowMenu({ "Select VIDEO standard:" }, vidOpts);
            if (vSel >= 0) settings.video = vidOpts[vSel];
        } else if (selected == 7) { // GAME
            std::vector<std::string> gameOpts = { "EU", "US", "JP" };
            int gSel = ShowMenu({ "Select GAME region:" }, gameOpts);
            if (gSel >= 0) settings.game = gameOpts[gSel];
        } else if (selected == 8) { // Save
            if (!State::AppRunning()) break;
            WUPI_resetScreen();
            WUPI_Log("Writing custom setting.txt to SLCCMPT...\n");
            if (Setting_Write(settings)) {
                WUPI_Log("Success: custom setting.txt saved successfully!\n");
            } else {
                WUPI_Log("Error: Failed to write setting.txt!\n");
            }
            WUPI_waitButton();
            break;
        }
    }
}

static void ShowSDBackupScreen() {
    WUPI_resetScreen();
    WUPI_Log("Backing up setting.txt to SD Card...\n");

    bool okTxt = Setting_ExportToSD("/vol/external01/setting.txt", true);
    bool okRaw = Setting_ExportToSD("/vol/external01/setting_raw.txt", false);

    if (okTxt || okRaw) {
        WUPI_Log("Backup completed:\n");
        if (okTxt) WUPI_Log(" - Decrypted text: sd:/setting.txt\n");
        if (okRaw) WUPI_Log(" - Encrypted raw:  sd:/setting_raw.txt\n");
    } else {
        WUPI_Log("Error: Failed to backup setting.txt (Check SD card or if setting.txt exists).\n");
    }
    WUPI_waitButton();
}

static void ShowSDRestoreScreen() {
    WUPI_resetScreen();
    VwiiSettings settings;

    WUPI_Log("Reading sd:/setting.txt...\n");
    if (!Setting_ImportFromSD("/vol/external01/setting.txt", settings)) {
        WUPI_Log("Error: Could not read or parse /vol/external01/setting.txt\n");
        WUPI_waitButton();
        return;
    }

    std::vector<std::string> confirmHeader = {
        "=== Restore setting.txt from SD ===",
        "The following settings will be written to SLCCMPT:",
        " - AREA:  " + settings.area,
        " - MODEL: " + settings.model,
        " - DVD:   " + std::to_string(settings.dvd),
        " - MPCH:  " + settings.mpch,
        " - CODE:  " + settings.code,
        " - SERNO: " + settings.serno,
        " - VIDEO: " + settings.video,
        " - GAME:  " + settings.game,
        "",
        "Missing directories will be created automatically.",
        "Proceed with restore?"
    };

    std::vector<std::string> confirmOptions = {
        "Yes, restore and write setting.txt",
        "No, cancel"
    };

    if (ShowMenu(confirmHeader, confirmOptions) != 0) {
        return;
    }

    if (!State::AppRunning()) return;

    WUPI_resetScreen();
    WUPI_Log("Writing setting.txt to SLCCMPT...\n");
    if (Setting_Write(settings)) {
        WUPI_Log("Success: setting.txt successfully restored from SD card!\n");
    } else {
        WUPI_Log("Error: Failed to write setting.txt to SLCCMPT!\n");
    }
    WUPI_waitButton();
}

void WUPI_settingTxtMenu() {
    while (State::AppRunning()) {
        WUPI_resetScreen();

        VwiiSettings current;
        bool exists = Setting_ReadCurrent(current);

        std::string statusLine = exists ? ("Status: Present (Region: " + current.area + ")")
                                        : "Status: NOT PRESENT (Missing / Empty)";

        std::vector<std::string> header = {
            "=== vWii setting.txt Management ===",
            statusLine,
            ""
        };

        std::vector<std::string> options = {
            "View Current setting.txt",
            "Regenerate setting.txt (from Wii U)",
            "Change Region (Presets)",
            "Edit Individual Fields",
            "Backup setting.txt to SD Card",
            "Restore setting.txt from SD Card"
        };

        int selected = ShowMenu(header, options);
        if (selected == 0) {
            ShowViewCurrentScreen();
        } else if (selected == 1) {
            ShowRegenerateScreen();
        } else if (selected == 2) {
            ShowRegionPresetsScreen();
        } else if (selected == 3) {
            ShowFieldEditorScreen();
        } else if (selected == 4) {
            ShowSDBackupScreen();
        } else if (selected == 5) {
            ShowSDRestoreScreen();
        } else if (selected == -1) {
            break;
        }
    }
}
