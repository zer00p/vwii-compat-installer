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
#include <algorithm>

extern FSAClientHandle fsaClient;
extern void WUPI_resetScreen();

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
    OSScreenClearBufferEx(SCREEN_TV, 0);
    OSScreenClearBufferEx(SCREEN_DRC, 0);

    OSScreenPutFontEx(SCREEN_TV, 0, 0, "Compat Title Installer v1.6");
    OSScreenPutFontEx(SCREEN_DRC, 0, 0, "Compat Title Installer v1.6");
    OSScreenPutFontEx(SCREEN_TV, 0, 1, "COPYRIGHT (c) 2021-2023 TheLordScruffy, DaThinkingChair");
    OSScreenPutFontEx(SCREEN_DRC, 0, 1, "COPYRIGHT (c) 2021-2023 TheLordScruffy, DaThinkingChair");

    std::string pathStr = "Path: " + s_CurrentPath;
    OSScreenPutFontEx(SCREEN_TV, 0, 3, pathStr.c_str());
    OSScreenPutFontEx(SCREEN_DRC, 0, 3, pathStr.c_str());

    if (!s_Entries.empty()) {
        int visible_lines = 10;
        int start_idx = selected - visible_lines / 2;
        if (start_idx < 0) start_idx = 0;
        if (start_idx + visible_lines > (int)s_Entries.size()) {
            start_idx = std::max(0, (int)s_Entries.size() - visible_lines);
        }

        for (int i = 0; i < visible_lines && (start_idx + i) < (int)s_Entries.size(); i++) {
            int idx = start_idx + i;
            const auto& entry = s_Entries[idx];
            
            std::string cursor = (idx == selected) ? "->" : "  ";
            std::string checkbox = entry.isDir ? "[DIR]" : (entry.isSelected ? "[X]" : "[ ]");
            
            std::string lineStr = cursor + " " + checkbox + " " + entry.name;
            OSScreenPutFontEx(SCREEN_TV, 0, 5 + i, lineStr.c_str());
            OSScreenPutFontEx(SCREEN_DRC, 0, 5 + i, lineStr.c_str());
        }
    } else {
        OSScreenPutFontEx(SCREEN_TV, 0, 5, "No files or subdirectories found.");
        OSScreenPutFontEx(SCREEN_DRC, 0, 5, "No files or subdirectories found.");
    }

    OSScreenPutFontEx(SCREEN_TV, 0, 16, "A: Select/Enter | B: Back | X: Toggle All | +: Confirm");
    OSScreenPutFontEx(SCREEN_DRC, 0, 16, "A: Select/Enter | B: Back | X: Toggle All | +: Confirm");
}

static void DrawBrowser(int selected) {
    DrawBrowserInner(selected);
    OSScreenFlipBuffersEx(SCREEN_TV);
    OSScreenFlipBuffersEx(SCREEN_DRC);

    DrawBrowserInner(selected);
    OSScreenFlipBuffersEx(SCREEN_TV);
    OSScreenFlipBuffersEx(SCREEN_DRC);
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
        PopulateWadList("/vol/external01"); // fallback to root
    }

    int selected = 0;
    int last_selected = -1;
    Input input;
    std::vector<std::string> result;

    while (State::AppRunning()) {
        input.read();
        bool needsRedraw = false;

        if (input.get(TRIGGER, PAD_BUTTON_UP)) {
            if (selected > 0) { selected--; needsRedraw = true; }
        }
        if (input.get(TRIGGER, PAD_BUTTON_DOWN)) {
            if (selected < (int)s_Entries.size() - 1) { selected++; needsRedraw = true; }
        }
        if (input.get(TRIGGER, PAD_BUTTON_B)) {
            if (s_CurrentPath != "/vol/external01") {
                size_t lastSlash = s_CurrentPath.find_last_of('/');
                if (lastSlash != std::string::npos && lastSlash > 0) {
                    PopulateWadList(s_CurrentPath.substr(0, lastSlash));
                } else {
                    PopulateWadList("/vol/external01");
                }
                selected = 0;
                needsRedraw = true;
            } else {
                break; // Exit browser
            }
        }
        if (input.get(TRIGGER, PAD_BUTTON_A) && !s_Entries.empty()) {
            auto& entry = s_Entries[selected];
            if (entry.isDir) {
                if (entry.name == "..") {
                    size_t lastSlash = s_CurrentPath.find_last_of('/');
                    if (lastSlash != std::string::npos && lastSlash > 0) {
                        PopulateWadList(s_CurrentPath.substr(0, lastSlash));
                    } else {
                        PopulateWadList("/vol/external01");
                    }
                } else {
                    PopulateWadList(entry.path);
                }
                selected = 0;
            } else {
                entry.isSelected = !entry.isSelected;
            }
            needsRedraw = true;
        }
        if (input.get(TRIGGER, PAD_BUTTON_X)) {
            bool anyUnselected = false;
            for (auto& entry : s_Entries) {
                if (!entry.isDir && !entry.isSelected) {
                    anyUnselected = true;
                    break;
                }
            }
            for (auto& entry : s_Entries) {
                if (!entry.isDir) {
                    entry.isSelected = anyUnselected;
                }
            }
            needsRedraw = true;
        }
        if (input.get(TRIGGER, PAD_BUTTON_PLUS)) {
            for (auto& entry : s_Entries) {
                if (!entry.isDir && entry.isSelected) {
                    result.push_back(entry.path);
                }
            }
            if (result.empty() && !s_Entries.empty() && !s_Entries[selected].isDir) {
                result.push_back(s_Entries[selected].path);
            }
            if (!result.empty()) {
                break;
            }
        }

        if (needsRedraw || last_selected == -1) {
            DrawBrowser(selected);
            last_selected = selected;
        }
        usleep(16000); // ~60fps
    }

    ClearWadList();

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
