#include "d2x_menu.h"
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

#define MAX_D2X_VERSIONS 20

static char* s_D2XDirs[MAX_D2X_VERSIONS];
static int s_NumDirs = 0;

static void ClearDirList() {
    for (int i = 0; i < s_NumDirs; i++) {
        if (s_D2XDirs[i]) free(s_D2XDirs[i]);
    }
    s_NumDirs = 0;
}

static void PopulateDirList(const char* dirPath) {
    FSADirectoryHandle dir;
    if (FSAOpenDir(fsaClient, dirPath, &dir) == FS_ERROR_OK) {
        FSADirectoryEntry entry;
        while (FSAReadDir(fsaClient, dir, &entry) == FS_ERROR_OK && s_NumDirs < MAX_D2X_VERSIONS) {
            if (entry.info.flags & FS_STAT_DIRECTORY) {
                // Ignore . and ..
                if (strcmp(entry.name, ".") == 0 || strcmp(entry.name, "..") == 0) continue;

                char fullPath[512];
                snprintf(fullPath, sizeof(fullPath), "%s/%s", dirPath, entry.name);
                s_D2XDirs[s_NumDirs++] = strdup(fullPath);
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
    if (s_NumDirs > 0) {
        snprintf(buf, sizeof(buf), "Select a d2x version to install (Found %d):", s_NumDirs);
        OSScreenPutFontEx(SCREEN_TV, 0, 3, buf);
        OSScreenPutFontEx(SCREEN_DRC, 0, 3, buf);

        for (int i = 0; i < s_NumDirs; i++) {
            const char* filename = strrchr(s_D2XDirs[i], '/');
            filename = filename ? filename + 1 : s_D2XDirs[i];
            
            snprintf(buf, sizeof(buf), "%s %s", (i == selected) ? "->" : "  ", filename);
            OSScreenPutFontEx(SCREEN_TV, 0, 5 + i, buf);
            OSScreenPutFontEx(SCREEN_DRC, 0, 5 + i, buf);
        }
    } else {
        snprintf(buf, sizeof(buf), "No d2x versions found in sd:/apps/d2x-cios-installer.");
        OSScreenPutFontEx(SCREEN_TV, 0, 3, buf);
        OSScreenPutFontEx(SCREEN_DRC, 0, 3, buf);
    }

    snprintf(buf, sizeof(buf), "A: Select | B: Cancel | UP/DOWN: Move");
    OSScreenPutFontEx(SCREEN_TV, 0, 6 + s_NumDirs, buf);
    OSScreenPutFontEx(SCREEN_DRC, 0, 6 + s_NumDirs, buf);
}

static void DrawBrowser(int selected) {
    DrawBrowserInner(selected);
    OSScreenFlipBuffersEx(SCREEN_TV);
    OSScreenFlipBuffersEx(SCREEN_DRC);

    DrawBrowserInner(selected);
    OSScreenFlipBuffersEx(SCREEN_TV);
    OSScreenFlipBuffersEx(SCREEN_DRC);
}

char* BrowseD2XVersions(void) {
    ClearDirList();
    PopulateDirList("/vol/external01/apps/d2x-cios-installer");

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
            if (selected < s_NumDirs - 1) selected++;
        }
        if (input.get(TRIGGER, PAD_BUTTON_B)) {
            break; // Cancel
        }
        if (input.get(TRIGGER, PAD_BUTTON_A) && s_NumDirs > 0) {
            result = strdup(s_D2XDirs[selected]);
            break; // Confirmed
        }

        if (selected != last_selected) {
            DrawBrowser(selected);
            last_selected = selected;
        }
        usleep(16000); // ~60fps
    }

    ClearDirList();

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
