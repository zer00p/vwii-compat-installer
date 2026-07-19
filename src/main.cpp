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
#include "StateUtils.h"
#include "filebrowser.h"
#include "wad.h"
#include "d2x_menu.h"
#include "d2x_patcher.h"

#define FS_ALIGN(x) ((x + 0x3F) & ~(0x3F))

void WUPI_printTop();
void WUPI_putstr(const char *str);
void WUPI_resetScreen();

int32_t wupiLine;
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

static void wupiPrintln(int32_t line, const char *str) {
    /* put line twice for double buffer */
    OSScreenPutFontEx(SCREEN_TV, 0, line, str);
    OSScreenPutFontEx(SCREEN_DRC, 0, line, str);
    OSScreenFlipBuffersEx(SCREEN_TV);
    OSScreenFlipBuffersEx(SCREEN_DRC);

    OSScreenPutFontEx(SCREEN_TV, 0, line, str);
    OSScreenPutFontEx(SCREEN_DRC, 0, line, str);
    OSScreenFlipBuffersEx(SCREEN_TV);
    OSScreenFlipBuffersEx(SCREEN_DRC);
}

void WUPI_printTop() {
    wupiPrintln(0, "Compat Title Installer v1.6");
    wupiPrintln(1, "COPYRIGHT (c) 2021-2023 TheLordScruffy, DaThinkingChair");
}

/* I don't care enough to implement a va arg function */
#define WUPI_printf(...)                             \
    do {                                             \
        char _wupi_print_str[256];                   \
        snprintf(_wupi_print_str, 255, __VA_ARGS__); \
        WUPI_putstr(_wupi_print_str);                \
    } while (0)

void WUPI_putstr(const char *str) {
    wupiPrintln(wupiLine++, str);
}

void WUPI_resetScreen() {
    memset((void *) screen_buffer, 0, screen_size);
    wupiLine = 4;

    WUPI_printTop();
}

void WUPI_waitHome() {
    WUPI_putstr("Press HOME to exit.");
    while (State::AppRunning())
        continue;
    return;
}

void WUPI_waitButton() {
    WUPI_putstr("Press ANY button to return to menu, or HOME to exit.");
    Input input;
    while (State::AppRunning()) {
        input.read();
        if (input.get(TRIGGER, PAD_BUTTON_ANY)) {
            return;
        }
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
    ret = CINS_Install(CINS_TITLEID, (const void *) title_cetk_bin_aligned, title_cetk_bin_size,
                       (const void *) title_tmd_bin_aligned, title_tmd_bin_size, contents,
                       2);
    free(title_cetk_bin_aligned);
    free(title_tmd_bin_aligned);
    free(title_00000000_bin_aligned);
    free(title_00000001_bin_aligned);
    if (ret < 0)
        WUPI_printf("Install failed. Error Code: %06X\n", -ret);
    WUPI_waitButton();
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
        WUPI_resetScreen();
        WUPI_putstr("No WADs selected.");
        WUPI_waitButton();
        return;
    }

    int successCount = 0;
    int failCount = 0;

    for (const auto& wadPath : selectedWads) {
        WUPI_resetScreen();
        WUPI_printf("Installing (%d/%d):\n", successCount + failCount + 1, (int)selectedWads.size());
        
        const char* filename = strrchr(wadPath.c_str(), '/');
        filename = filename ? filename + 1 : wadPath.c_str();
        WUPI_printf("%s\n", filename);

        WUPI_putstr("Loading and decrypting WAD...\n");

        WADContext* ctx = WAD_LoadAndDecrypt(wadPath.c_str());
        if (!ctx) {
            WUPI_putstr("Error: Failed to load or decrypt WAD.\n");
            failCount++;
            sleep(3);
            continue;
        }

        if (!WAD_IsSafeTitle(ctx)) {
            WUPI_putstr("Error: This is an original Wii System Title!");
            WUPI_putstr("Installing this WILL BRICK your vWii.");
            WUPI_putstr("Skipping this WAD for safety.");
            WAD_Free(ctx);
            failCount++;
            sleep(4);
            continue;
        }

        WUPI_putstr("Writing to slccmpt...\n");
        if (WAD_InstallToVWii(ctx, 0)) {
            WUPI_putstr("WAD Installation complete!\n");
            successCount++;
            sleep(1);
        } else {
            WUPI_putstr("Error: WAD installation failed.\n");
            failCount++;
            sleep(3);
        }

        WAD_Free(ctx);
    }

    WUPI_resetScreen();
    WUPI_printf("Batch Install Complete!\n");
    WUPI_printf("Successful: %d\n", successCount);
    WUPI_printf("Failed: %d\n", failCount);
    WUPI_waitButton();
}

void WUPI_showMenu() {
    WUPI_resetScreen();
    WUPI_putstr("Press A to install the Homebrew Channel to the Wii Menu.");
    WUPI_putstr("Press X to install a WAD from the SD Card.");
    WUPI_putstr("Press Y to install d2x cIOS.");
    WUPI_putstr("Press HOME to exit.");
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

    char* selectedVersion = BrowseD2XVersions();
    if (!selectedVersion) {
        WUPI_resetScreen();
        WUPI_putstr("No d2x version selected.");
        WUPI_waitButton();
        return;
    }

    WUPI_resetScreen();

    // Call the patcher engine
    InstallD2X(selectedVersion);

    free(selectedVersion);
    WUPI_waitButton();
}

int main() {
    int32_t tv_screen_size, drc_screen_size;
    Input input;

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
    OSScreenEnableEx(SCREEN_TV, 1);
    OSScreenEnableEx(SCREEN_DRC, 1);
    OSScreenClearBufferEx(SCREEN_TV, 0);
    OSScreenClearBufferEx(SCREEN_DRC, 0);

    if (WUPI_setupInstall() < 0) {
        WUPI_resetScreen();
        WUPI_putstr("Error: Mocha not found, you need to run this from Aroma.");
        WUPI_waitButton();
    } else {
        WUPI_showMenu();

        while (State::AppRunning()) {
            input.read();
            
            if (!State::ForegroundReacquired() && !input.get(TRIGGER, PAD_BUTTON_ANY)) {
                continue;
            }

            if (input.get(TRIGGER, PAD_BUTTON_A)) {
                WUPI_install();
            } else if (input.get(TRIGGER, PAD_BUTTON_X)) {
                WUPI_installWAD();
            } else if (input.get(TRIGGER, PAD_BUTTON_Y)) {
                WUPI_installD2X();
            }
            
            WUPI_showMenu();
        }
    }

    deinitFS();
    State::shutdown();

    if (screen_buffer)
        free(screen_buffer);
    return 0;
}
