/* Compat Title Installer
 *   Copyright (C) 2026  zer00p
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
#include "ScreenUtils.h"
#include "StateUtils.h"
#include <coreinit/filesystem_fsa.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <algorithm>

extern FSAClientHandle fsaClient;
#include "log.h"

struct FileEntry {
    std::string name;
    std::string path;
    bool isDir;
    bool isSelected;
};

static std::vector<FileEntry> s_Entries;
static std::string s_CurrentPath;

static void ClearWadList() {
    s_Entries.clear();
}

static void PopulateWadList(const std::string& dirPath) {
    s_CurrentPath = dirPath;
    ClearWadList();

    if (s_CurrentPath != "/vol/external01") {
        s_Entries.push_back({"..", "", true, false});
    }

    FSADirectoryHandle dir;
    FSError err = FSAOpenDir(fsaClient, s_CurrentPath.c_str(), &dir);
    if (err == FS_ERROR_OK) {
        FSADirectoryEntry entry;
        FSError readErr;
        while ((readErr = FSAReadDir(fsaClient, dir, &entry)) == FS_ERROR_OK) {
            std::string name = entry.name;
            bool isDir = (entry.info.flags & FS_STAT_DIRECTORY);

            if (!isDir) {
                if (name.length() > 4 && strcasecmp(name.c_str() + name.length() - 4, ".wad") == 0) {
                    s_Entries.push_back({name, s_CurrentPath + "/" + name, false, false});
                }
            } else {
                s_Entries.push_back({name, s_CurrentPath + "/" + name, true, false});
            }
        }
        
        if (readErr != FS_ERROR_OK && readErr != FS_ERROR_END_OF_DIR) {
            std::string errMsg = "ReadDir Err: " + std::to_string(readErr);
            s_Entries.push_back({errMsg, "", false, false});
        }
        
        FSACloseDir(fsaClient, dir);
    } else {
        std::string errMsg = "OpenDir Err: " + std::to_string(err) + " " + s_CurrentPath;
        s_Entries.push_back({errMsg, "", false, false});
    }

    std::sort(s_Entries.begin(), s_Entries.end(), [](const FileEntry& a, const FileEntry& b) {
        if (a.name == "..") return b.name != "..";
        if (b.name == "..") return false;
        if (a.isDir != b.isDir) return a.isDir > b.isDir;
        return strcasecmp(a.name.c_str(), b.name.c_str()) < 0;
    });
}

static void DrawBrowserInner(int selected) {
    ScreenUtils_ClearBuffer(0);

    std::string headerStr;
    if (s_CurrentPath == "/vol/external01") {
        headerStr = "Select a directory:";
    } else {
        headerStr = "Select WADs to install from " + s_CurrentPath + " (Found " + std::to_string(s_Entries.size()) + "):";
    }
    ScreenUtils_PutFont(0, 0, headerStr.c_str());

    int count = (int)s_Entries.size();
    if (count > 0) {
        int max_display = 15;
        int start_idx = std::max(0, std::min(selected - max_display / 2, count - max_display));

        for (int i = 0; i < max_display && start_idx + i < count; i++) {
            int idx = start_idx + i;
            auto& entry = s_Entries[idx];

            std::string prefix = (idx == selected) ? "-> " : "   ";
            std::string type = entry.isDir ? "[DIR] " : (entry.isSelected ? "[X]  " : "[ ]  ");

            std::string lineStr = prefix + type + entry.name;
            ScreenUtils_PutFont(0, 2 + i, lineStr.c_str());
        }
    } else {
        ScreenUtils_PutFont(0, 2, "No files found.");
    }

    ScreenUtils_PutFont(0, 18, "A: Enter/Select | X: Select All | +: Confirm | B: Back | UP/DOWN/LEFT/RIGHT: Move");
}

static bool ProcessHoldInput(const Input& input, Button button, int& timer) {
    if (input.get(TRIGGER, button)) {
        timer = 0;
        return true;
    }
    if (input.get(HOLD, button)) {
        return (++timer > 20 && timer % 4 == 0);
    }
    timer = 0;
    return false;
}

static void NavigateUp(int& selected) {
    size_t lastSlash = s_CurrentPath.find_last_of('/');
    if (lastSlash != std::string::npos && lastSlash > 0) {
        PopulateWadList(s_CurrentPath.substr(0, lastSlash));
    } else {
        PopulateWadList("/vol/external01");
    }
    selected = 0;
}

std::vector<std::string> BrowseWADs() {
    FSADirectoryHandle dir;
    if (FSAOpenDir(fsaClient, "/vol/external01/wad", &dir) == FS_ERROR_OK) {
        FSACloseDir(fsaClient, dir);
        PopulateWadList("/vol/external01/wad");
    } else if (FSAOpenDir(fsaClient, "/vol/external01/wads", &dir) == FS_ERROR_OK) {
        FSACloseDir(fsaClient, dir);
        PopulateWadList("/vol/external01/wads");
    } else {
        PopulateWadList("/vol/external01");
    }

    int selected = 0;
    Input input;
    std::vector<std::string> result;
    int hold_timer_up = 0, hold_timer_down = 0;
    int hold_timer_left = 0, hold_timer_right = 0;

    DrawBrowserInner(selected);
    ScreenUtils_FlipBuffers();

    while (State::AppRunning()) {
        input.read();
        int count = (int)s_Entries.size();
        bool changed = false;

        // Cursor movement (with hold-repeat)
        if (ProcessHoldInput(input, PAD_BUTTON_UP, hold_timer_up) && selected > 0) {
            selected--;
            changed = true;
        }
        if (ProcessHoldInput(input, PAD_BUTTON_DOWN, hold_timer_down) && selected < count - 1) {
            selected++;
            changed = true;
        }
        if (ProcessHoldInput(input, PAD_BUTTON_LEFT, hold_timer_left) && selected > 0) {
            selected = std::max(0, selected - 10);
            changed = true;
        }
        if (ProcessHoldInput(input, PAD_BUTTON_RIGHT, hold_timer_right) && selected < count - 1) {
            selected = std::min(count - 1, selected + 10);
            changed = true;
        }

        // Directory navigation
        if (input.get(TRIGGER, PAD_BUTTON_B)) {
            if (s_CurrentPath == "/vol/external01") break;
            NavigateUp(selected);
            changed = true;
        }
        if (input.get(TRIGGER, PAD_BUTTON_A) && !s_Entries.empty()) {
            auto& entry = s_Entries[selected];
            if (entry.isDir) {
                if (entry.name == "..") {
                    NavigateUp(selected);
                } else {
                    PopulateWadList(entry.path);
                    selected = 0;
                }
            } else {
                entry.isSelected = !entry.isSelected;
            }
            changed = true;
        }

        // Toggle all
        if (input.get(TRIGGER, PAD_BUTTON_X)) {
            bool anyUnselected = false;
            for (auto& entry : s_Entries) {
                if (!entry.isDir && !entry.isSelected) {
                    anyUnselected = true;
                    break;
                }
            }
            for (auto& entry : s_Entries) {
                if (!entry.isDir) entry.isSelected = anyUnselected;
            }
            changed = true;
        }

        // Confirm selection
        if (input.get(TRIGGER, PAD_BUTTON_PLUS)) {
            for (auto& entry : s_Entries) {
                if (!entry.isDir && entry.isSelected) {
                    result.push_back(entry.path);
                }
            }
            if (result.empty() && !s_Entries.empty() && !s_Entries[selected].isDir) {
                result.push_back(s_Entries[selected].path);
            }
            if (!result.empty()) break;
        }

        if (changed) {
            DrawBrowserInner(selected);
            ScreenUtils_FlipBuffers();
        }

        usleep(16000);
    }

    ClearWadList();
    ScreenUtils_ClearBothBuffers();
    return result;
}
