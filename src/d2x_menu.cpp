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
#include "log.h"
#include <vector>
#include <string>

#define MAX_D2X_VERSIONS 20

static std::vector<std::string> s_D2XDirs;
static FSError s_OpenDirErr = FS_ERROR_OK;

static void ClearDirList() {
    s_D2XDirs.clear();
}

static void PopulateDirList(const std::string& dirPath) {
    FSADirectoryHandle dir;
    s_OpenDirErr = FSAOpenDir(fsaClient, dirPath.c_str(), &dir);
    if (s_OpenDirErr == FS_ERROR_OK) {
        FSADirectoryEntry entry;
        while (FSAReadDir(fsaClient, dir, &entry) == FS_ERROR_OK && s_D2XDirs.size() < MAX_D2X_VERSIONS) {
            if (entry.info.flags & FS_STAT_DIRECTORY) {
                // Ignore . and ..
                if (strcmp(entry.name, ".") == 0 || strcmp(entry.name, "..") == 0) continue;

                s_D2XDirs.push_back(dirPath + "/" + entry.name);
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

    if (!s_D2XDirs.empty()) {
        std::string header = "Select a d2x version to install (Found " + std::to_string(s_D2XDirs.size()) + "):";
        OSScreenPutFontEx(SCREEN_TV, 0, 3, header.c_str());
        OSScreenPutFontEx(SCREEN_DRC, 0, 3, header.c_str());

        for (size_t i = 0; i < s_D2XDirs.size(); i++) {
            size_t slashPos = s_D2XDirs[i].find_last_of('/');
            std::string filename = (slashPos != std::string::npos) ? s_D2XDirs[i].substr(slashPos + 1) : s_D2XDirs[i];
            
            std::string line = std::string((i == (size_t)selected) ? "-> " : "   ") + filename;
            OSScreenPutFontEx(SCREEN_TV, 0, 5 + i, line.c_str());
            OSScreenPutFontEx(SCREEN_DRC, 0, 5 + i, line.c_str());
        }
    } else {
        if (s_OpenDirErr != FS_ERROR_OK) {
            std::string errStr = "Error opening dir (Code: " + std::to_string(s_OpenDirErr) + "):";
            OSScreenPutFontEx(SCREEN_TV, 0, 3, errStr.c_str());
            OSScreenPutFontEx(SCREEN_DRC, 0, 3, errStr.c_str());
            OSScreenPutFontEx(SCREEN_TV, 0, 4, "sd:/apps/d2x-cios-installer");
            OSScreenPutFontEx(SCREEN_DRC, 0, 4, "sd:/apps/d2x-cios-installer");
        } else {
            OSScreenPutFontEx(SCREEN_TV, 0, 3, "No d2x versions found in sd:/apps/d2x-cios-installer.");
            OSScreenPutFontEx(SCREEN_DRC, 0, 3, "No d2x versions found in sd:/apps/d2x-cios-installer.");
        }
    }

    OSScreenPutFontEx(SCREEN_TV, 0, 6 + s_D2XDirs.size(), "A: Select | B: Cancel | UP/DOWN: Move");
    OSScreenPutFontEx(SCREEN_DRC, 0, 6 + s_D2XDirs.size(), "A: Select | B: Cancel | UP/DOWN: Move");
}

static void DrawBrowser(int selected) {
    DrawBrowserInner(selected);
    OSScreenFlipBuffersEx(SCREEN_TV);
    OSScreenFlipBuffersEx(SCREEN_DRC);

    DrawBrowserInner(selected);
    OSScreenFlipBuffersEx(SCREEN_TV);
    OSScreenFlipBuffersEx(SCREEN_DRC);
}

std::string BrowseD2XVersions() {
    ClearDirList();
    PopulateDirList("/vol/external01/apps/d2x-cios-installer");

    int selected = 0;
    std::string result = "";

    DoInputLoop([&selected]() {
        DrawBrowser(selected);
    }, [&selected, &result](Input& input) {
        bool needs_redraw = false;
        if (input.get(TRIGGER, PAD_BUTTON_UP)) {
            if (selected > 0) { selected--; needs_redraw = true; }
        }
        if (input.get(TRIGGER, PAD_BUTTON_DOWN)) {
            if (selected < (int)s_D2XDirs.size() - 1) { selected++; needs_redraw = true; }
        }
        if (input.get(TRIGGER, PAD_BUTTON_B)) {
            return true; // Cancel
        }
        if (input.get(TRIGGER, PAD_BUTTON_A) && !s_D2XDirs.empty()) {
            result = s_D2XDirs[selected];
            return true; // Confirmed
        }
        if (needs_redraw) {
            DrawBrowser(selected);
        }
        return false;
    });

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
