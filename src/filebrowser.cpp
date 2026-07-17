/* WAD Installer integration
 *   Copyright (C) 2026
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

#include "filebrowser.h"
#include "InputUtils.h"
#include "StateUtils.h"
#include <coreinit/filesystem_fsa.h>
#include <coreinit/screen.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

extern FSAClientHandle fsaClient;
extern void WUPI_resetScreen();

#define MAX_WADS 100

static char* s_WadFiles[MAX_WADS];
static int s_NumWads = 0;

static void ClearWadList() {
    for (int i = 0; i < s_NumWads; i++) {
        if (s_WadFiles[i]) free(s_WadFiles[i]);
    }
    s_NumWads = 0;
}

static void PopulateWadList(const char* dirPath) {
    FSADirectoryHandle dir;
    if (FSAOpenDir(fsaClient, dirPath, &dir) == FS_ERROR_OK) {
        FSADirectoryEntry entry;
        while (FSAReadDir(fsaClient, dir, &entry) == FS_ERROR_OK && s_NumWads < MAX_WADS) {
            if (!(entry.info.flags & FS_STAT_DIRECTORY)) {
                size_t len = strlen(entry.name);
                if (len > 4 && strcasecmp(entry.name + len - 4, ".wad") == 0) {
                    char fullPath[256];
                    snprintf(fullPath, sizeof(fullPath), "%s/%s", dirPath, entry.name);
                    s_WadFiles[s_NumWads++] = strdup(fullPath);
                }
            }
        }
        FSACloseDir(fsaClient, dir);
    }
}

static void DrawBrowserInner(int selected) {
    OSScreenClearBufferEx(SCREEN_TV, 0);
    OSScreenClearBufferEx(SCREEN_DRC, 0);

    OSScreenPutFontEx(SCREEN_TV, 0, 0, "Compat Title Installer v1.6");
    OSScreenPutFontEx(SCREEN_DRC, 0, 0, "Compat Title Installer v1.6");
    OSScreenPutFontEx(SCREEN_TV, 0, 1, "COPYRIGHT (c) 2021-2023 TheLordScruffy, DaThinkingChair");
    OSScreenPutFontEx(SCREEN_DRC, 0, 1, "COPYRIGHT (c) 2021-2023 TheLordScruffy, DaThinkingChair");

    char buf[256];
    if (s_NumWads > 0) {
        snprintf(buf, sizeof(buf), "Select a WAD to install (Found %d):", s_NumWads);
        OSScreenPutFontEx(SCREEN_TV, 0, 3, buf);
        OSScreenPutFontEx(SCREEN_DRC, 0, 3, buf);

        for (int i = 0; i < s_NumWads; i++) {
            const char* filename = strrchr(s_WadFiles[i], '/');
            filename = filename ? filename + 1 : s_WadFiles[i];
            
            snprintf(buf, sizeof(buf), "%s %s", (i == selected) ? "->" : "  ", filename);
            OSScreenPutFontEx(SCREEN_TV, 0, 5 + i, buf);
            OSScreenPutFontEx(SCREEN_DRC, 0, 5 + i, buf);
        }
    } else {
        snprintf(buf, sizeof(buf), "No .wad files found in sd:/wads or sd:/wad.");
        OSScreenPutFontEx(SCREEN_TV, 0, 3, buf);
        OSScreenPutFontEx(SCREEN_DRC, 0, 3, buf);
    }

    snprintf(buf, sizeof(buf), "A: Select | B: Cancel | UP/DOWN: Move");
    OSScreenPutFontEx(SCREEN_TV, 0, 6 + s_NumWads, buf);
    OSScreenPutFontEx(SCREEN_DRC, 0, 6 + s_NumWads, buf);
}

static void DrawBrowser(int selected) {
    DrawBrowserInner(selected);
    OSScreenFlipBuffersEx(SCREEN_TV);
    OSScreenFlipBuffersEx(SCREEN_DRC);

    DrawBrowserInner(selected);
    OSScreenFlipBuffersEx(SCREEN_TV);
    OSScreenFlipBuffersEx(SCREEN_DRC);
}

char* BrowseWADs(void) {
    ClearWadList();
    PopulateWadList("/vol/external01/wads");
    if (s_NumWads == 0) {
        PopulateWadList("/vol/external01/wad");
    }
    if (s_NumWads == 0) {
        PopulateWadList("/vol/external01"); // fallback to root
    }

    int selected = 0;
    int last_selected = -1;
    Input input;
    char* result = NULL;

    while (State::AppRunning()) {
        input.read();
        if (input.get(TRIGGER, PAD_BUTTON_UP)) {
            if (selected > 0) selected--;
        }
        if (input.get(TRIGGER, PAD_BUTTON_DOWN)) {
            if (selected < s_NumWads - 1) selected++;
        }
        if (input.get(TRIGGER, PAD_BUTTON_B)) {
            break; // Cancel
        }
        if (input.get(TRIGGER, PAD_BUTTON_A) && s_NumWads > 0) {
            result = strdup(s_WadFiles[selected]);
            break; // Confirmed
        }

        if (selected != last_selected) {
            DrawBrowser(selected);
            last_selected = selected;
        }
        usleep(16000); // ~60fps
    }

    ClearWadList();

    // Since we took over the screen loop, we need to clear both buffers
    // to black so main.cpp can redraw its UI cleanly.
    OSScreenClearBufferEx(SCREEN_TV, 0);
    OSScreenClearBufferEx(SCREEN_DRC, 0);
    OSScreenFlipBuffersEx(SCREEN_TV);
    OSScreenFlipBuffersEx(SCREEN_DRC);
    OSScreenClearBufferEx(SCREEN_TV, 0);
    OSScreenClearBufferEx(SCREEN_DRC, 0);
    OSScreenFlipBuffersEx(SCREEN_TV);
    OSScreenFlipBuffersEx(SCREEN_DRC);

    return result;
}
