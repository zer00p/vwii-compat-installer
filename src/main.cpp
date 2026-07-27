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
#include "filebrowser.h"
#include "wad.h"
#include "d2x_menu.h"
#include "d2x_patcher.h"
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
}


int32_t WUPI_setupInstall() {
    if (Mocha_InitLibrary() == MOCHA_RESULT_SUCCESS) {
        mochaInit = true;
        return 0;
    }
    return -1;
}

void WUPI_install() {
    /* We should only end up here if the A button was pressed. */
    WUPI_resetScreen();

    if (!mounted) {
        if (!(ret = initFS())) {
            WUPI_putstr("Error: Failed to mount /vol/slccmpt01.\n");
            WUPI_waitButton();
            return;
        }
        mounted = true;
    }

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
    if (ret < 0)
        WUPI_Log("Install failed. Error Code: %06X\n", -ret);
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

    if (!mounted) {
        if (!(ret = initFS())) {
            WUPI_putstr("Error: Failed to mount /vol/slccmpt01.\n");
            WUPI_waitButton();
            return;
        }
        mounted = true;
    }

    std::vector<std::string> selectedWads = BrowseWADs();
    if (selectedWads.empty()) {
        return;
    }

    int successCount = 0;
    int failCount = 0;

    for (const auto& wadPath : selectedWads) {
        WUPI_resetScreen();
        WUPI_Log("Installing (%d/%d):\n", successCount + failCount + 1, (int)selectedWads.size());
        
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
    WUPI_Log("Batch Install Complete!\n");
    WUPI_Log("Successful: %d\n", successCount);
    WUPI_Log("Failed: %d\n", failCount);
    WUPI_waitButton();
}


void WUPI_installD2X() {
    WUPI_resetScreen();
    
    if (!mounted) {
        if (!(ret = initFS())) {
            WUPI_putstr("Error: Failed to mount /vol/slccmpt01.\n");
            WUPI_waitButton();
            return;
        }
        mounted = true;
    }

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

void WUPI_downloadMenu() {
    WUPI_resetScreen();
    std::vector<std::string> options = {
        "LibreShop",
        "Homebrew Browser",
        "USB Loader GX",
        "d2x cIOS installer"
    };
    std::vector<std::string> appIds = {
        "libreshop",
        "homebrew_browser",
        "usbloader_gx",
        "d2x-cios-installer"
    };
    std::vector<std::string> header = {
        "Select apps to download:"
    };

    std::vector<int> selected = ShowMultiSelectMenu(header, options);
    if (selected.empty()) {
        return;
    }

    int successCount = 0;
    int failCount = 0;

    for (int idx : selected) {
        WUPI_resetScreen();
        WUPI_Log("Downloading (%d/%d):\n", successCount + failCount + 1, (int)selected.size());
        WUPI_Log("%s\n", options[idx].c_str());

        if (DownloadAndExtractApp(appIds[idx])) {
            successCount++;
        } else {
            failCount++;
            
            // Wait on error
            ScreenUtils_ClearBuffer(0);
            char buf[256];
            snprintf(buf, sizeof(buf), "Downloading (%d/%d):", successCount + failCount, (int)selected.size());
            ScreenUtils_PutFont(0, 1, buf);
            ScreenUtils_PutFont(0, 2, options[idx].c_str());
            ScreenUtils_PutFont(0, 3, "Download failed.");
            ScreenUtils_PutFont(0, 5, "Press A to continue with next app.");
            ScreenUtils_PutFont(0, 6, "Press B to abort batch download.");
            ScreenUtils_FlipBuffers();
            
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
    } else {
        std::vector<std::string> options = {
            "Install the Homebrew Channel to the Wii Menu",
            "Install a WAD from the SD Card",
            "Install d2x cIOS",
            "Download Apps"
        };
        std::vector<std::string> header = {
            "Compat Title Installer v1.6",
            "COPYRIGHT (c) 2021-2023 TheLordScruffy, DaThinkingChair",
            "",
            "Main Menu:"
        };
        while (State::AppRunning()) {
            int selected = ShowMenu(header, options);
            if (selected == 0) {
                WUPI_install();
            } else if (selected == 1) {
                WUPI_installWAD();
            } else if (selected == 2) {
                WUPI_installD2X();
            } else if (selected == 3) {
                WUPI_downloadMenu();
            } else if (selected == -1) {
                break;
            }
        }
    }

    deinitFS();
    State::shutdown();

    if (screen_buffer)
        free(screen_buffer);
    return 0;
}
