/* Compat Title Installer main source file
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
#include "log.h"
#include <coreinit/cache.h>
#include <coreinit/debug.h>
#include <coreinit/filesystem_fsa.h>
#include <coreinit/ios.h>
#include <coreinit/mcp.h>
#include <coreinit/screen.h>
#include <coreinit/thread.h>
#include <cstring>
#include <malloc.h>
#include <mocha/mocha.h>
#include <padscore/kpad.h>
#include <sndcore2/core.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <whb/proc.h>

#include "InputUtils.h"
#include "ScreenUtils.h"
#include "StateUtils.h"
#include "FSAUtils.h"
#include "filebrowser.h"
#include "wad.h"
#include "d2x_menu.h"
#include "d2x_patcher.h"
#include "ios80_patcher.h"
#include "drive_inquiry_patcher.h"
#include "MenuUtils.h"
#include "downloader.h"

#define FS_ALIGN(x) ((x + 0x3F) & ~(0x3F))

uint8_t *screen_buffer;
uint32_t screen_size;

FSAClientHandle fsaClient;

/* Title data */
extern const uint8_t title_cetk_bin[];
extern const uint32_t title_cetk_bin_size;
extern const uint8_t title_tmd_bin[];
extern const uint32_t title_tmd_bin_size;
extern const uint8_t title_00000000_bin[];
extern const uint32_t title_00000000_bin_size;
extern const uint8_t title_00000001_bin[];
extern const uint32_t title_00000001_bin_size;

bool mounted = false;
bool fsaInit = false;
bool mochaInit = false;
CINS_Content contents[2];
int32_t ret, fsaFd = -1;

bool initFS() {
    if (!fsaInit) {
        FSAInit();
        fsaClient = FSAAddClient(nullptr);
        fsaInit = true;
    }
    bool retUnlock =
            Mocha_UnlockFSClientEx(fsaClient) == MOCHA_RESULT_SUCCESS;
    if (retUnlock) {
        FSAMount(fsaClient, "/dev/slccmpt01", "/vol/slccmpt01", FSA_MOUNT_FLAG_LOCAL_MOUNT, nullptr, 0);
        return true;
    }
    return false;
}

void deinitFS() {
    if (fsaInit) {
        if (mounted) {
            FSAUnmount(fsaClient, "/vol/slccmpt01", FSA_UNMOUNT_FLAG_NONE);
            mounted = false;
        }
        FSADelClient(fsaClient);
        FSAShutdown();
        fsaInit = false;
    }
    if (mochaInit) {
        Mocha_DeInitLibrary();
        mochaInit = false;
    }
    DeinitCurl();
}


int32_t WUPI_setupInstall() {
    if (Mocha_InitLibrary() == MOCHA_RESULT_SUCCESS) {
        mochaInit = true;
        return 0;
    }
    return -1;
}

bool WUPI_installHBCInternal() {
    WUPI_putstr("Installing the Homebrew Channel...\n");

    void *title_cetk_bin_aligned = aligned_alloc(0x40, FS_ALIGN(title_cetk_bin_size));
    void *title_tmd_bin_aligned = aligned_alloc(0x40, FS_ALIGN(title_tmd_bin_size));
    memmove(title_cetk_bin_aligned, title_cetk_bin, title_cetk_bin_size);
    memmove(title_tmd_bin_aligned, title_tmd_bin, title_tmd_bin_size);

    void *title_00000000_bin_aligned = aligned_alloc(0x40, FS_ALIGN(title_00000000_bin_size));
    void *title_00000001_bin_aligned = aligned_alloc(0x40, FS_ALIGN(title_00000001_bin_size));
    memmove(title_00000000_bin_aligned, title_00000000_bin, title_00000000_bin_size);
    memmove(title_00000001_bin_aligned, title_00000001_bin, title_00000001_bin_size);

    contents[0].data = (const void *) title_00000000_bin_aligned;
    contents[0].length = title_00000000_bin_size;
    contents[1].data = (const void *) title_00000001_bin_aligned;
    contents[1].length = title_00000001_bin_size;
    ret = CINS_Install(CINS_TITLEID, (const TitleTicket *) title_cetk_bin_aligned, title_cetk_bin_size,
                       (const TitleTmd *) title_tmd_bin_aligned, title_tmd_bin_size, contents,
                       2);
    free(title_cetk_bin_aligned);
    free(title_tmd_bin_aligned);
    free(title_00000000_bin_aligned);
    free(title_00000001_bin_aligned);
    if (ret < 0) {
        WUPI_Log("Install failed. Error Code: %06X\n", -ret);
        return false;
    }
    return true;
}

void WUPI_install() {
    /* We should only end up here if the A button was pressed. */
    WUPI_resetScreen();
    WUPI_installHBCInternal();
    WUPI_waitButton();
}


static void DrawBatchError(int current, int total, const char* filename) {
    ScreenUtils_ClearBuffer(0);

    char buf[256];
    snprintf(buf, sizeof(buf), "Installing (%d/%d):", current, total);
    ScreenUtils_PutFont(0, 1, buf);
    ScreenUtils_PutFont(0, 2, filename);
    ScreenUtils_PutFont(0, 3, "Installation failed.");
    ScreenUtils_PutFont(0, 5, "Press A to continue with next WAD.");
    ScreenUtils_PutFont(0, 6, "Press B to abort batch install.");
}

/* Shows the batch-error screen and waits for A (continue) or B (abort).
 * Returns true if the user wants to continue, false to abort. */
static bool WaitForBatchError(int current, int total, const char* filename) {
    DrawBatchError(current, total, filename);
    ScreenUtils_FlipBuffers();

    return WaitPrompt();
}

void WUPI_installWAD() {
    WUPI_resetScreen();

    std::vector<std::string> selectedWads = BrowseWADs();
    if (selectedWads.empty()) {
        return;
    }

    int successCount = 0;
    int failCount = 0;

    for (const auto& wadPath : selectedWads) {
        WUPI_Log("Installing (%d/%d):", successCount + failCount + 1, (int)selectedWads.size());

        const char* filename = strrchr(wadPath.c_str(), '/');
        filename = filename ? filename + 1 : wadPath.c_str();
        WUPI_Log("%s\n", filename);

        WUPI_putstr("Loading and decrypting WAD...\n");

        bool failed = false;
        WADContext* ctx = WAD_LoadAndDecrypt(wadPath.c_str());
        if (!ctx) {
            WUPI_putstr("Error: Failed to load or decrypt WAD.\n");
            failed = true;
        } else if (!WAD_IsSafeTitle(ctx)) {
            WUPI_putstr("Error: This is an original Wii System Title!");
            WUPI_putstr("Installing this WILL BRICK your vWii.");
            WUPI_putstr("Skipping this WAD for safety.");
            failed = true;
        } else {
            WUPI_putstr("Writing to slccmpt...\n");
            if (WAD_InstallToVWii(ctx, 0)) {
                WUPI_putstr("WAD Installation complete!\n");
                successCount++;
                sleep(1);
            } else {
                WUPI_putstr("Error: WAD installation failed.\n");
                failed = true;
            }
        }

        if (ctx) {
            WAD_Free(ctx);
        }

        if (failed) {
            failCount++;
            if (!WaitForBatchError(successCount + failCount, (int)selectedWads.size(), filename)) {
                break;
            }
        }
    }

    WUPI_resetScreen();
    WUPI_Log("Batch Install Complete!");
    WUPI_Log("Successful: %d\n", successCount);
    WUPI_Log("Failed: %d\n", failCount);
    WUPI_waitButton();
}


void WUPI_installD2X() {
    WUPI_resetScreen();

    std::string selectedVersion = BrowseD2XVersions();
    if (selectedVersion.empty()) {
        WUPI_resetScreen();
        WUPI_putstr("Installation cancelled.");
        sleep(2);
        return;
    }

    // Perform installation
    WUPI_resetScreen();
    InstallD2X(selectedVersion);
    WUPI_waitButton();
}

void WUPI_installIOS80() {
    WUPI_resetScreen();
    InstallIOS80();
}

void WUPI_openShopChannelMenu() {
    WUPI_resetScreen();
    std::vector<std::string> options = {
        "LibreShop",
        "Homebrew Browser"
    };
    std::vector<std::string> appIds = {
        "libreshop",
        "homebrew_browser"
    };
    std::vector<std::string> header = {
        "Open Shop Channel:"
    };

    std::vector<int> selected = ShowMultiSelectMenu(header, options);
    if (selected.empty()) {
        return;
    }

    int successCount = 0;
    int failCount = 0;

    for (int idx : selected) {
        WUPI_Log("Downloading (%d/%d):", successCount + failCount + 1, (int)selected.size());
        WUPI_Log("%s\n", options[idx].c_str());

        if (DownloadAndExtractApp(appIds[idx])) {
            successCount++;
        } else {
            failCount++;

            WUPI_putstr("Press A to continue with next app, B to abort.");
            if (!WaitPrompt()) {
                break;
            }
        }
    }

    WUPI_resetScreen();
    WUPI_Log("Batch Download Complete!\n");
    WUPI_Log("Successful: %d\n", successCount);
    WUPI_Log("Failed: %d\n", failCount);
    WUPI_waitButton();
}

void WUPI_cIOSMenu() {
    while (State::AppRunning()) {
        WUPI_resetScreen();
        std::vector<std::string> options = {
            "Install d2x cIOS",
            "Uninstall d2x cIOS",
            "Patch IOS80 (SD Card Menu Channels)",
            "Undo IOS80 Patches",
            "Apply Drive Inquiry Patch",
            "Undo Drive Inquiry Patch",
            "Download d2x-cios-installer"
        };
        std::vector<std::string> header = {
            "cIOS Menu:"
        };

        int selected = ShowMenu(header, options);
        if (selected == 0) {
            WUPI_installD2X();
        } else if (selected == 1) {
            WUPI_resetScreen();
            if (UninstallD2X()) {
                WUPI_waitButton();
            }
        } else if (selected == 2) {
            WUPI_installIOS80();
        } else if (selected == 3) {
            WUPI_resetScreen();
            UndoIOS80Patches();
        } else if (selected == 4) {
            InstallDrivePatchAll();
        } else if (selected == 5) {
            UndoDrivePatchAll();
        } else if (selected == 6) {
            WUPI_resetScreen();
            WUPI_Log("Downloading d2x-cios-installer...\n");
            if (DownloadAndExtractApp("d2x-cios-installer-vwii")) {
                WUPI_Log("Download complete!\n");
            } else {
                WUPI_Log("Download failed.\n");
            }
            WUPI_waitButton();
        } else if (selected == -1) {
            break;
        }

    }
}

void WUPI_usbLoaderGXMenu() {
    WUPI_resetScreen();

    std::vector<std::string> options = {
        "Download USB Loader GX (Open Shop Channel)",
        "Download & Install Forwarder Channel",
        "Download Aroma Forwarder (Boot2vWii)"
    };
    std::vector<std::string> header = {
        "USB Loader GX Menu:"
    };

    std::vector<int> selected = ShowMultiSelectMenu(header, options);
    if (selected.empty()) {
        return;
    }

    int successCount = 0;
    int failCount = 0;

    for (int idx : selected) {
        WUPI_Log("Processing (%d/%d):", successCount + failCount + 1, (int)selected.size());
        WUPI_Log("%s\n", options[idx].c_str());

        bool success = false;
        if (idx == 0) {
            success = DownloadAndExtractApp("usbloader_gx");
        } else if (idx == 1) {
            std::string wadUrl = "https://github.com/wiidev/usbloadergx/raw/refs/heads/updates/USBLoaderGX_forwarder%5BUNEO%5D.wad";
            std::string wadPath = "/vol/external01/wad/USBLoaderGX_forwarder_UNEO.wad";
            if (DownloadFile(wadUrl, wadPath)) {
                WUPI_putstr("Loading and decrypting WAD...\n");
                WADContext* ctx = WAD_LoadAndDecrypt(wadPath.c_str());
                if (!ctx) {
                    WUPI_putstr("Error: Failed to load or decrypt WAD.\n");
                } else if (!WAD_IsSafeTitle(ctx)) {
                    WUPI_putstr("Error: Unsafe WAD! Skipping for safety.\n");
                } else {
                    WUPI_putstr("Writing to slccmpt...\n");
                    if (WAD_InstallToVWii(ctx, 0)) {
                        WUPI_putstr("WAD Installation complete!\n");
                        success = true;
                    } else {
                        WUPI_putstr("Error: WAD installation failed.\n");
                    }
                }
                if (ctx) {
                    WAD_Free(ctx);
                }
            }
        } else if (idx == 2) {
            std::string wuhbUrl = "https://github.com/WiiDatabase/Boot2vWii/releases/latest/download/USB-Loader-GX-UNEO.wuhb";
            std::string wuhbPath = "/vol/external01/wiiu/apps/USB-Loader-GX-UNEO.wuhb";
            success = DownloadFile(wuhbUrl, wuhbPath);
        }

        if (success) {
            successCount++;
            sleep(1);
        } else {
            failCount++;

            WUPI_putstr("\nOperation failed.\nPress A to continue, B to abort.\n");

            if (!WaitPrompt()) {
                break;
            }
        }
    }

    WUPI_resetScreen();
    WUPI_Log("Batch Complete!\n");
    WUPI_Log("Successful: %d\n", successCount);
    WUPI_Log("Failed: %d\n", failCount);
    WUPI_waitButton();
}

// Decryption logic documented at: https://wiibrew.org/wiki//title/00000001/00000002/data/setting.txt
void DecryptSettingTxt(char* buf, size_t len) {
    uint32_t key = 0x73B5DBFA;
    for (size_t i = 0; i < len; i++) {
        buf[i] ^= key & 0xff;
        key = (key << 1) | (key >> 31);
    }
}

int32_t GetVWiiRegion() {
    FSAFileHandle fd = 0;
    int openRes = FSAOpenFileEx(fsaClient, "/vol/slccmpt01/title/00000001/00000002/data/setting.txt", "r", (FSMode) 0x666, FS_OPEN_FLAG_NONE, 0, &fd);
    if (openRes == FS_ERROR_OK) {
        char* alignBuf = (char*)memalign(0x40, 2048);
        if (alignBuf) {
            memset(alignBuf, 0, 2048);
            int res = FSAReadFile(fsaClient, alignBuf, 1, 1024, fd, 0);
            FSACloseFile(fsaClient, fd);
            if (res > 0) {
                DecryptSettingTxt(alignBuf, res);
                std::string settings(alignBuf, res);
                free(alignBuf);
                if (settings.find("AREA=EUR") != std::string::npos) return 2;
                if (settings.find("AREA=USA") != std::string::npos) return 1;
                if (settings.find("AREA=JPN") != std::string::npos) return 0;
                // There is no Korean vWii System Menu, but keeping a fallback just in case
                if (settings.find("AREA=KOR") != std::string::npos) return 3;
                WUPI_Log("Setting.txt opened, but AREA= string not found!\n");
            } else {
                WUPI_Log("Failed to read setting.txt, res: %d\n", res);
                free(alignBuf);
            }
        } else {
            WUPI_Log("Failed to allocate memory for setting.txt\n");
            FSACloseFile(fsaClient, fd);
        }
    } else {
        WUPI_Log("Failed to open setting.txt, error: %d\n", openRes);
    }
    return -1;
}

struct NusTitle {
    uint64_t id;
    const char* name;
    bool regionSpecificId;
    bool regionSpecificVersion;
};

static const NusTitle g_nusTitles[] = {
    {0x0000000100000002ULL, "System Menu (vWii)", false, true},
    {0x0000000100000009ULL, "IOS9", false, false},
    {0x000000010000000cULL, "IOS12", false, false},
    {0x000000010000000dULL, "IOS13", false, false},
    {0x000000010000000eULL, "IOS14", false, false},
    {0x000000010000000fULL, "IOS15", false, false},
    {0x0000000100000011ULL, "IOS17", false, false},
    {0x0000000100000015ULL, "IOS21", false, false},
    {0x0000000100000016ULL, "IOS22", false, false},
    {0x000000010000001cULL, "IOS28", false, false},
    {0x000000010000001fULL, "IOS31", false, false},
    {0x0000000100000021ULL, "IOS33", false, false},
    {0x0000000100000022ULL, "IOS34", false, false},
    {0x0000000100000023ULL, "IOS35", false, false},
    {0x0000000100000024ULL, "IOS36", false, false},
    {0x0000000100000025ULL, "IOS37", false, false},
    {0x0000000100000026ULL, "IOS38", false, false},
    {0x0000000100000029ULL, "IOS41", false, false},
    {0x000000010000002bULL, "IOS43", false, false},
    {0x000000010000002dULL, "IOS45", false, false},
    {0x000000010000002eULL, "IOS46", false, false},
    {0x0000000100000030ULL, "IOS48", false, false},
    {0x0000000100000035ULL, "IOS53", false, false},
    {0x0000000100000037ULL, "IOS55", false, false},
    {0x0000000100000038ULL, "IOS56", false, false},
    {0x0000000100000039ULL, "IOS57", false, false},
    {0x000000010000003aULL, "IOS58", false, false},
    {0x000000010000003bULL, "IOS59", false, false},
    {0x000000010000003eULL, "IOS62", false, false},
    {0x0000000100000050ULL, "IOS80", false, false},
    {0x0000000100000200ULL, "BC-Wii", false, false},
    {0x0000000100000201ULL, "MIOS", false, false},
    {0x0001000248414241ULL, "Shopping Channel", false, false},
    {0x0001000248414341ULL, "Mii Channel", false, false},
    {0x0001000248435500ULL, "Wii Menu Electronic Manual", true, false},
    {0x0001000248435641ULL, "Wii U Menu Channel", false, false},
    {0x0001000848414c00ULL, "Region Select", true, false},
    {0x0001000848435a00ULL, "Wii System Transfer", true, false},
};

void WUPI_NusMenu() {
    while (State::AppRunning()) {
        WUPI_resetScreen();
        std::vector<std::string> options;
        for (const auto& t : g_nusTitles) {
            options.push_back(t.name);
        }
        std::vector<std::string> header = {
            "Install System Titles from NUS:"
        };

        std::vector<int> selected_items = ShowMultiSelectMenu(header, options);
        if (selected_items.empty()) {
            break;
        }

        WUPI_resetScreen();
        int32_t regionCode = GetVWiiRegion();
        if (regionCode == -1) {
            WUPI_Log("Error: Could not determine vWii region from setting.txt\n");
            WUPI_waitButton();
            continue;
        }

        int successCount = 0;
        int failCount = 0;

        for (int selected : selected_items) {
            if (selected >= 0 && selected < (int)(sizeof(g_nusTitles) / sizeof(g_nusTitles[0]))) {
                uint64_t titleId = g_nusTitles[selected].id;
                WUPI_Log("--- Processing %s (%d/%d) ---", g_nusTitles[selected].name, successCount + failCount + 1, (int)selected_items.size());

                if (g_nusTitles[selected].regionSpecificId) {
                    uint8_t regionChar = 0;
                    switch (regionCode) {
                        case 0: regionChar = 'J'; break;
                        case 1: regionChar = 'E'; break;
                        case 2: regionChar = 'P'; break;
                        case 3: regionChar = 'K'; break;
                    }
                    if (regionChar != 0) {
                        titleId |= regionChar;
                    }
                }

                int32_t latestVersion = NUS_GetLatestVersion(titleId);
                if (latestVersion == -1) {
                    WUPI_Log("Error: Failed to fetch latest version from NUS.\n");
                    failCount++;
                    WUPI_putstr("Press A to continue with next title, B to abort.");
                    if (!WaitPrompt()) break;
                    continue;
                }

                int32_t version = latestVersion;
                if (g_nusTitles[selected].regionSpecificVersion) {
                    version = (latestVersion & ~3) | regionCode;
                }
                WUPI_Log("Version: %d\n", version);

                bool failed = false;
                WADContext* ctx = NUS_DownloadTitle(titleId, version);
                if (!ctx) {
                    WUPI_Log("Error: Failed to download or prepare title.\n");
                    failed = true;
                } else if (!WAD_IsSafeTitle(ctx)) {
                    WUPI_Log("Error: Title is unsafe. Aborting installation.\n");
                    failed = true;
                } else {
                    WUPI_Log("Writing to slccmpt...\n");
                    if (WAD_InstallToVWii(ctx, 0)) {
                        WUPI_Log("Installation complete!\n");
                        successCount++;
                        sleep(1);
                    } else {
                        WUPI_Log("Error: Installation failed.\n");
                        failed = true;
                    }
                }
                if (ctx) WAD_Free(ctx);

                if (failed) {
                    failCount++;
                    WUPI_putstr("Press A to continue with next title, B to abort.");
                    if (!WaitPrompt()) break;
                }
            }
        }

        WUPI_resetScreen();
        WUPI_Log("Batch Complete!\n");
        WUPI_Log("Successful: %d\n", successCount);
        WUPI_Log("Failed: %d\n", failCount);
        WUPI_waitButton();
    }
}

static std::string GetAutoD2XVersionPath() {
    std::string baseDir = "/vol/external01/apps/d2x-cios-installer-vwii";
    FSADirectoryHandle dir;
    if (FSAOpenDir(fsaClient, baseDir.c_str(), &dir) != FS_ERROR_OK) {
        WUPI_Log("d2x installer not found on SD. Downloading from OSC...\n");
        if (DownloadAndExtractApp("d2x-cios-installer-vwii")) {
            if (FSAOpenDir(fsaClient, baseDir.c_str(), &dir) != FS_ERROR_OK) {
                return "";
            }
        } else {
            return "";
        }
    }

    FSADirectoryEntry entry;
    std::string versionPath = "";
    while (FSAReadDir(fsaClient, dir, &entry) == FS_ERROR_OK) {
        if (entry.info.flags & FS_STAT_DIRECTORY) {
            if (strcmp(entry.name, ".") == 0 || strcmp(entry.name, "..") == 0) continue;
            versionPath = baseDir + "/" + entry.name;
            break;
        }
    }
    FSACloseDir(fsaClient, dir);
    return versionPath;
}

void WUPI_expressSetupInstall() {
    WUPI_resetScreen();
    std::vector<std::string> options = {
        "Homebrew Channel",
        "d2x cIOS",
        "IOS80 Patches",
        "USB Loader GX",
        "Open Shop Channel"
    };
    std::vector<std::string> header = {
        "Express Setup:",
        "Select components to install:"
    };

    std::vector<int> selected = ShowMultiSelectMenu(header, options, true);
    if (selected.empty()) {
        return;
    }

    // Confirmation Screen
    std::vector<std::string> confirmHeader = {
        "Confirm Express Setup:",
        "The following components will be installed:"
    };
    for (int idx : selected) {
        if (idx == 0) confirmHeader.push_back(" - Homebrew Channel");
        else if (idx == 1) confirmHeader.push_back(" - d2x cIOS (Slots 248, 249, 250, 251)");
        else if (idx == 2) confirmHeader.push_back(" - IOS80 Patches (Trucha, ES, FS)");
        else if (idx == 3) confirmHeader.push_back(" - USB Loader GX (App & Forwarders)");
        else if (idx == 4) confirmHeader.push_back(" - Open Shop Channel Apps");
    }
    confirmHeader.push_back("");
    confirmHeader.push_back("Are you sure you want to proceed?");

    std::vector<std::string> confirmOptions = {
        "Yes, start installation",
        "No, cancel"
    };

    if (ShowMenu(confirmHeader, confirmOptions) != 0) {
        return;
    }

    WUPI_resetScreen();

    bool hbcDone = false, hbcSuccess = false;
    bool d2xDone = false;
    std::vector<std::pair<int, bool>> d2xResults;
    bool ios80Done = false, ios80Success = false;
    bool ulgxDone = false, ulgxAppSuccess = false, ulgxWadSuccess = false, ulgxWuhbSuccess = false;
    bool oscDone = false, oscLibreshopSuccess = false, oscHbbSuccess = false;

    for (int idx : selected) {
        if (!State::AppRunning()) break;
        bool stepFailed = false;

        if (idx == 0) {
            hbcDone = true;
            WUPI_Log("--- Installing Homebrew Channel ---");
            hbcSuccess = WUPI_installHBCInternal();
            if (!hbcSuccess) stepFailed = true;
        } else if (idx == 1) {
            d2xDone = true;
            WUPI_Log("--- Installing d2x cIOS ---");
            std::string d2xVersionPath = GetAutoD2XVersionPath();
            if (d2xVersionPath.empty()) {
                WUPI_Log("No d2x version folder found.\n");
                stepFailed = true;
            } else {
                InstallD2XBatch(d2xVersionPath, d2xResults);
                for (const auto& res : d2xResults) {
                    if (!res.second) stepFailed = true;
                }
            }
        } else if (idx == 2) {
            ios80Done = true;
            WUPI_Log("--- Patching IOS80 ---");
            ios80Success = InstallIOS80Batch();
            if (!ios80Success) stepFailed = true;
        } else if (idx == 3) {
            ulgxDone = true;
            WUPI_Log("--- Installing USB Loader GX ---");
            WUPI_Log("Downloading USB Loader GX App...");
            ulgxAppSuccess = DownloadAndExtractApp("usbloader_gx");

            WUPI_Log("Downloading & Installing vWii Forwarder Channel...");
            std::string wadUrl = "https://github.com/wiidev/usbloadergx/raw/refs/heads/updates/USBLoaderGX_forwarder%5BUNEO%5D.wad";
            std::string wadPath = "/vol/external01/wad/USBLoaderGX_forwarder_UNEO.wad";
            if (DownloadFile(wadUrl, wadPath)) {
                WADContext* ctx = WAD_LoadAndDecrypt(wadPath.c_str());
                if (ctx && WAD_IsSafeTitle(ctx)) {
                    if (WAD_InstallToVWii(ctx, 0)) {
                        ulgxWadSuccess = true;
                    }
                }
                if (ctx) WAD_Free(ctx);
            }

            WUPI_Log("Downloading Aroma Forwarder (Boot2vWii)...");
            std::string wuhbUrl = "https://github.com/WiiDatabase/Boot2vWii/releases/latest/download/USB-Loader-GX-UNEO.wuhb";
            std::string wuhbPath = "/vol/external01/wiiu/apps/USB-Loader-GX-UNEO.wuhb";
            ulgxWuhbSuccess = DownloadFile(wuhbUrl, wuhbPath);

            if (!ulgxAppSuccess || !ulgxWadSuccess || !ulgxWuhbSuccess) {
                stepFailed = true;
            }
        } else if (idx == 4) {
            oscDone = true;
            WUPI_Log("--- Installing Open Shop Channel Apps ---");
            WUPI_Log("Downloading LibreShop...");
            oscLibreshopSuccess = DownloadAndExtractApp("libreshop");
            WUPI_Log("Downloading Homebrew Browser...");
            oscHbbSuccess = DownloadAndExtractApp("homebrew_browser");

            if (!oscLibreshopSuccess || !oscHbbSuccess) {
                stepFailed = true;
            }
        }

        if (stepFailed) {
            WUPI_putstr("Error encountered during step.");
            WUPI_putstr("Press A to continue with next component, B to abort.");
            if (!WaitPrompt()) break;
        }
    }

    WUPI_resetScreen();
    WUPI_Log("=========================================");
    WUPI_Log("          EXPRESS SETUP SUMMARY          ");
    WUPI_Log("=========================================\n");

    if (hbcDone) {
        WUPI_Log("Homebrew Channel: %s", hbcSuccess ? "Installed" : "Failed");
    }
    if (d2xDone) {
        WUPI_Log("d2x cIOS:");
        if (d2xResults.empty()) {
            WUPI_Log("  - Installation skipped (No version folder)");
        } else {
            for (const auto& res : d2xResults) {
                WUPI_Log("  - Slot %d: %s", res.first, res.second ? "Installed" : "Failed");
            }
        }
    }
    if (ios80Done) {
        WUPI_Log("IOS80 Patches: %s", ios80Success ? "Applied" : "Failed");
    }
    if (ulgxDone) {
        WUPI_Log("USB Loader GX:");
        WUPI_Log("  - App (sd:/apps/usbloader_gx): %s", ulgxAppSuccess ? "Downloaded" : "Failed");
        WUPI_Log("  - vWii Forwarder (UNEO): %s", ulgxWadSuccess ? "Installed" : "Failed");
        WUPI_Log("  - Aroma Forwarder (WUHB): %s", ulgxWuhbSuccess ? "Downloaded" : "Failed");
    }
    if (oscDone) {
        WUPI_Log("Open Shop Channel Apps:");
        WUPI_Log("  - LibreShop: %s", oscLibreshopSuccess ? "Downloaded" : "Failed");
        WUPI_Log("  - Homebrew Browser: %s", oscHbbSuccess ? "Downloaded" : "Failed");
    }

    WUPI_waitButton();
}

void WUPI_expressSetupUninstall() {
    WUPI_resetScreen();
    std::vector<std::string> options = {
        "Homebrew Channel",
        "d2x cIOS",
        "IOS80 Patches",
        "Drive Inquiry Patches",
        "USB Loader GX",
        "Open Shop Channel"
    };
    std::vector<std::string> header = {
        "Express Uninstall:",
        "Select components to uninstall:"
    };

    std::vector<int> selected = ShowMultiSelectMenu(header, options, true);
    if (selected.empty()) {
        return;
    }

    // Confirmation Screen
    std::vector<std::string> confirmHeader = {
        "Confirm Express Uninstall:",
        "The following components will be uninstalled:"
    };
    for (int idx : selected) {
        if (idx == 0) confirmHeader.push_back(" - Homebrew Channel");
        else if (idx == 1) confirmHeader.push_back(" - d2x cIOS (Slots 248, 249, 250, 251)");
        else if (idx == 2) confirmHeader.push_back(" - IOS80 Patches (Revert to stock)");
        else if (idx == 3) confirmHeader.push_back(" - Drive Inquiry Patches (Revert All IOSes)");
        else if (idx == 4) confirmHeader.push_back(" - USB Loader GX (App & Forwarders)");
        else if (idx == 5) confirmHeader.push_back(" - Open Shop Channel Apps");
    }
    confirmHeader.push_back("");
    confirmHeader.push_back("Are you sure you want to proceed?");

    std::vector<std::string> confirmOptions = {
        "Yes, start uninstallation",
        "No, cancel"
    };

    if (ShowMenu(confirmHeader, confirmOptions) != 0) {
        return;
    }

    WUPI_resetScreen();

    bool hbcDone = false, hbcSuccess = false;
    bool d2xDone = false;
    std::vector<std::pair<int, bool>> d2xResults;
    bool ios80Done = false, ios80Success = false;
    bool driveDone = false, driveSuccess = false;
    bool ulgxDone = false, ulgxWadSuccess = false, ulgxAppSuccess = false, ulgxWuhbSuccess = false;
    bool oscDone = false, oscLibreshopSuccess = false, oscHbbSuccess = false;

    for (int idx : selected) {
        if (!State::AppRunning()) break;
        bool stepFailed = false;

        if (idx == 0) {
            hbcDone = true;
            WUPI_Log("--- Uninstalling Homebrew Channel ---");
            hbcSuccess = CINS_UninstallTitle(CINS_TITLEID);
            if (!hbcSuccess) stepFailed = true;
        } else if (idx == 1) {
            d2xDone = true;
            WUPI_Log("--- Uninstalling d2x cIOS ---");
            UninstallD2XBatch(d2xResults);
            for (const auto& res : d2xResults) {
                if (!res.second) stepFailed = true;
            }
        } else if (idx == 2) {
            ios80Done = true;
            WUPI_Log("--- Reverting IOS80 Patches ---");
            ios80Success = UndoIOS80PatchesBatch();
            if (!ios80Success) stepFailed = true;
        } else if (idx == 3) {
            driveDone = true;
            WUPI_Log("--- Reverting Drive Inquiry Patches ---");
            driveSuccess = UndoDrivePatchAllBatch();
            if (!driveSuccess) stepFailed = true;
        } else if (idx == 4) {
            ulgxDone = true;
            WUPI_Log("--- Uninstalling USB Loader GX ---");
            WUPI_Log("Uninstalling vWii Forwarder Channel...");
            ulgxWadSuccess = CINS_UninstallTitle(0x00010001454E554FULL);

            WUPI_Log("Removing USB Loader GX SD App...");
            ulgxAppSuccess = FSARemoveTree(fsaClient, "/vol/external01/apps/usbloader_gx");

            WUPI_Log("Removing Aroma Forwarder...");
            ulgxWuhbSuccess = (FSARemove(fsaClient, "/vol/external01/wiiu/apps/USB-Loader-GX-UNEO.wuhb") == FS_ERROR_OK);

            if (!ulgxWadSuccess || !ulgxAppSuccess || !ulgxWuhbSuccess) {
                stepFailed = true;
            }
        } else if (idx == 5) {
            oscDone = true;
            WUPI_Log("--- Uninstalling Open Shop Channel Apps ---");
            WUPI_Log("Removing LibreShop...");
            oscLibreshopSuccess = FSARemoveTree(fsaClient, "/vol/external01/apps/libreshop");
            WUPI_Log("Removing Homebrew Browser...");
            oscHbbSuccess = FSARemoveTree(fsaClient, "/vol/external01/apps/homebrew_browser");

            if (!oscLibreshopSuccess || !oscHbbSuccess) {
                stepFailed = true;
            }
        }

        if (stepFailed) {
            WUPI_putstr("Error encountered during step.");
            WUPI_putstr("Press A to continue with next component, B to abort.");
            if (!WaitPrompt()) break;
        }
    }

    WUPI_resetScreen();
    WUPI_Log("=========================================");
    WUPI_Log("        EXPRESS UNINSTALL SUMMARY        ");
    WUPI_Log("=========================================\n");

    if (hbcDone) {
        WUPI_Log("Homebrew Channel: %s", hbcSuccess ? "Uninstalled" : "Failed");
    }
    if (d2xDone) {
        WUPI_Log("d2x cIOS:");
        for (const auto& res : d2xResults) {
            WUPI_Log("  - Slot %d: %s", res.first, res.second ? "Uninstalled" : "Failed");
        }
    }
    if (ios80Done) {
        WUPI_Log("IOS80 Patches: %s", ios80Success ? "Reverted to stock" : "Failed");
    }
    if (driveDone) {
        WUPI_Log("Drive Inquiry Patches: %s", driveSuccess ? "Reverted to stock" : "Failed");
    }
    if (ulgxDone) {
        WUPI_Log("USB Loader GX:");
        WUPI_Log("  - vWii Forwarder (UNEO): %s", ulgxWadSuccess ? "Uninstalled" : "Failed / Not present");
        WUPI_Log("  - SD App (usbloader_gx): %s", ulgxAppSuccess ? "Removed" : "Failed / Not present");
        WUPI_Log("  - Aroma Forwarder (WUHB): %s", ulgxWuhbSuccess ? "Removed" : "Failed / Not present");
    }
    if (oscDone) {
        WUPI_Log("Open Shop Channel Apps:");
        WUPI_Log("  - LibreShop: %s", oscLibreshopSuccess ? "Removed" : "Failed / Not present");
        WUPI_Log("  - Homebrew Browser: %s", oscHbbSuccess ? "Removed" : "Failed / Not present");
    }

    WUPI_waitButton();
}


void WUPI_showCredits() {
    std::vector<std::string> header = {
        "=== Credits ==="
    };
    std::vector<std::string> credits = {
        "-- Original Project --",
        "TheLordScruffy - Compat Title Installer",
        "Xpl0itU (DaThinkingChair) - WUT Port",
        "FIX94 - wuphax (original basis)",
        "@Ingunar - App icons",
        "",
        "-- Open Homebrew Channel --",
        "FIX94 - Open Homebrew Channel (OHBC)",
        "Team Twiizers / fail0verflow - Original HBC",
        "(dhewg, bushing, marcan, segher & others)",
        "",
        "-- IOS Patchers --",
        "Dr Clipper, ZRicky11, FIX94,",
        "damysteryman, GaryOderNichts",
        "& Patched IOS Installer contributors",
        "",
        "-- d2x cIOS --",
        "davebaol, xperia64, blackb0x / wiidev",
        "& d2x-cios-installer contributors",
        "",
        "-- WAD Tools & Crypto --",
        "Segher Boessenkool - Zeventig / WAD tools",
        "BFGR, libertyernie - WAD tools mods",
        "mbedtls contributors - Crypto library",
        "",
        "-- USB Loader GX --",
        "blackb0x / wiidev - USB Loader GX",
        "Brawl345 - Boot2vWii Forwarder",
        "",
        "-- Libraries --",
        "leethomason - tinyxml2",
        "richgel999 - miniz (ZIP library)",
        "cURL contributors - libcurl",
        "",
        "-- Services & Documentation --",
        "Open Shop Channel (oscwii.org) - App repo",
        "WiiBrew (wiibrew.org) - Documentation",
        "Nintendo - NUS (System Titles)",
        "",
        "-- Build Toolchains --",
        "devkitPro - devkitPPC / devkitARM",
        "wut contributors - Wii U Toolchain",
    };
    ShowMenu(header, credits);
}

int main() {
    int32_t tv_screen_size, drc_screen_size;

    State::init();
    AXInit();
    AXQuit();

    WPADInit();
    KPADInit();
    WPADEnableURCC(1);

    /* Initialize screen */
    OSScreenInit();
    tv_screen_size = OSScreenGetBufferSizeEx(SCREEN_TV);
    drc_screen_size = OSScreenGetBufferSizeEx(SCREEN_DRC);
    screen_size = tv_screen_size + drc_screen_size;
    screen_buffer = (uint8_t *) memalign(0x100, screen_size);
    OSScreenSetBufferEx(SCREEN_TV, screen_buffer);                   /* TV */
    OSScreenSetBufferEx(SCREEN_DRC, screen_buffer + tv_screen_size); /* DRC */
    ScreenUtils_Enable();
    ScreenUtils_ClearBuffer(0);

    if (WUPI_setupInstall() < 0) {
        WUPI_resetScreen();
        WUPI_putstr("Error: Mocha not found, you need to run this from Aroma.");
        WUPI_waitButton();
    } else if (!(ret = initFS())) {
        WUPI_resetScreen();
        WUPI_putstr("Error: Failed to mount /vol/slccmpt01.");
        WUPI_waitButton();
    } else {
        mounted = true;
        std::vector<std::string> options = {
            "Install the Homebrew Channel to the Wii Menu",
            "Express Setup",
            "Install a WAD from the SD Card",
            "cIOS Menu",
            "Open Shop Channel",
            "USB Loader GX",
            "Download System Titles (NUS)",
            "Express Uninstall",
            "Credits"
        };
        std::vector<std::string> header = {
            "Compat Title Installer v2.0",
            "COPYRIGHT (c) 2021-2023 TheLordScruffy, DaThinkingChair",
            "",
            "Main Menu:"
        };
        while (State::AppRunning()) {
            int selected = ShowMenu(header, options);
            if (selected == 0) {
                WUPI_install();
            } else if (selected == 1) {
                WUPI_expressSetupInstall();
            } else if (selected == 2) {
                WUPI_installWAD();
            } else if (selected == 3) {
                WUPI_cIOSMenu();
            } else if (selected == 4) {
                WUPI_openShopChannelMenu();
            } else if (selected == 5) {
                WUPI_usbLoaderGXMenu();
            } else if (selected == 6) {
                WUPI_NusMenu();
            } else if (selected == 7) {
                WUPI_expressSetupUninstall();
            } else if (selected == 8) {
                WUPI_showCredits();
            } else if (selected == -1) {
                break;
            }
        }
    }

    deinitFS();
    KPADShutdown();
    WPADShutdown();
    State::shutdown();

    if (screen_buffer)
        free(screen_buffer);
    return 0;
}
