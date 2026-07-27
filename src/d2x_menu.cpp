#include "d2x_menu.h"
#include "MenuUtils.h"
#include "ScreenUtils.h"
#include "StateUtils.h"
#include <coreinit/filesystem_fsa.h>
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

std::string BrowseD2XVersions() {
    ClearDirList();
    PopulateDirList("/vol/external01/apps/d2x-cios-installer");

    std::string result = "";

    if (s_D2XDirs.empty()) {
        ScreenUtils_ClearBuffer(0);
        if (s_OpenDirErr != FS_ERROR_OK) {
            std::string errStr = "Error opening dir (Code: " + std::to_string(s_OpenDirErr) + "):";
            ScreenUtils_PutFont(0, 3, errStr.c_str());
            ScreenUtils_PutFont(0, 4, "sd:/apps/d2x-cios-installer");
        } else {
            ScreenUtils_PutFont(0, 3, "No d2x versions found in sd:/apps/d2x-cios-installer.");
        }
        ScreenUtils_FlipBuffers();
        WUPI_waitButton();
    } else {
        std::vector<std::string> displayNames;
        for (const auto& dir : s_D2XDirs) {
            size_t slashPos = dir.find_last_of('/');
            displayNames.push_back((slashPos != std::string::npos) ? dir.substr(slashPos + 1) : dir);
        }

        int selected = ShowMenu({"Select a d2x version to install (Found " + std::to_string(s_D2XDirs.size()) + "):"}, displayNames);
        if (selected != -1) {
            result = s_D2XDirs[selected];
        }
    }

    ClearDirList();
    ScreenUtils_ClearBothBuffers();

    return result;
}
