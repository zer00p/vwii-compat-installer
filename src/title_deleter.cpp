#include "title_deleter.h"
#include "FSAUtils.h"
#include "EndianUtils.h"
#include "MenuUtils.h"
#include "ScreenUtils.h"
#include "StateUtils.h"
#include "InputUtils.h"
#include "log.h"
#include "wad.h"

#include <coreinit/filesystem_fsa.h>
#include <malloc.h>
#include <string.h>
#include <stdio.h>
#include <algorithm>
#include <map>
#include <set>

extern FSAClientHandle fsaClient;

// IMET Header constants & offsets
constexpr size_t IMET_TOTAL_SIZE = 1472; // 0x5C0
constexpr size_t IMET_OFFSET_JP  = 0x1C;
constexpr size_t IMET_OFFSET_EN  = 0x70;
constexpr size_t IMET_OFFSET_DE  = 0xC4;
constexpr size_t IMET_OFFSET_FR  = 0x118;
constexpr size_t IMET_OFFSET_ES  = 0x16C;
constexpr size_t IMET_OFFSET_IT  = 0x1C0;
constexpr size_t IMET_OFFSET_NL  = 0x214;
constexpr size_t IMET_OFFSET_KO  = 0x268;
constexpr size_t IMET_OFFSET_ZH_CN = 0x2BC;
constexpr size_t IMET_OFFSET_ZH_TW = 0x310;

static std::string DecodeUtf16BE(const uint8_t* ptr, size_t maxChars) {
    std::string out;
    for (size_t i = 0; i < maxChars; ++i) {
        uint16_t ch = Read16BE(ptr + i * 2);
        if (ch == 0) break;
        if (ch < 0x80) {
            out.push_back(static_cast<char>(ch));
        } else if (ch < 0x800) {
            out.push_back(static_cast<char>(0xC0 | ((ch >> 6) & 0x1F)));
            out.push_back(static_cast<char>(0x80 | (ch & 0x3F)));
        } else {
            out.push_back(static_cast<char>(0xE0 | ((ch >> 12) & 0x0F)));
            out.push_back(static_cast<char>(0x80 | ((ch >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (ch & 0x3F)));
        }
    }
    while (!out.empty() && (out.back() == ' ' || out.back() == '\t' || out.back() == '\r' || out.back() == '\n')) {
        out.pop_back();
    }
    return out;
}

std::string ExtractTitleNameFromApp(FSAClientHandle fsa, const std::string& appPath) {
    FSAFileHandle file;
    if (FSAOpenFileEx(fsa, appPath.c_str(), "rb", (FSMode)0, FS_OPEN_FLAG_NONE, 0, &file) != FS_ERROR_OK) {
        return "";
    }

    constexpr size_t BUF_SIZE = 0x800; // 2048 bytes
    uint8_t* buffer = (uint8_t*)memalign(0x40, BUF_SIZE);
    if (!buffer) {
        FSACloseFile(fsa, file);
        return "";
    }

    memset(buffer, 0, BUF_SIZE);
    int32_t bytesRead = FSAReadFile(fsa, buffer, 1, BUF_SIZE, file, 0);
    FSACloseFile(fsa, file);

    if (bytesRead < (int32_t)IMET_TOTAL_SIZE) {
        free(buffer);
        return "";
    }

    const uint8_t* imetBase = nullptr;
    for (size_t offset = 0; offset + IMET_TOTAL_SIZE <= (size_t)bytesRead; offset += 4) {
        if (memcmp(buffer + offset, "IMET", 4) == 0) {
            imetBase = buffer + offset;
            break;
        }
    }

    if (!imetBase) {
        free(buffer);
        return "";
    }

    std::string name = DecodeUtf16BE(imetBase + IMET_OFFSET_EN, 42);
    if (name.empty()) {
        name = DecodeUtf16BE(imetBase + IMET_OFFSET_JP, 42);
    }
    if (name.empty()) {
        const size_t offsets[] = {
            IMET_OFFSET_DE, IMET_OFFSET_FR, IMET_OFFSET_ES, IMET_OFFSET_IT,
            IMET_OFFSET_NL, IMET_OFFSET_KO, IMET_OFFSET_ZH_CN, IMET_OFFSET_ZH_TW
        };
        for (size_t off : offsets) {
            name = DecodeUtf16BE(imetBase + off, 42);
            if (!name.empty()) break;
        }
    }

    free(buffer);
    return name;
}

static std::string ExtractTitleNameFromContentDir(FSAClientHandle fsa, const std::string& contentDir) {
    // 1. Try 00000000.app first (standard for channel banners)
    std::string app0 = contentDir + "/00000000.app";
    std::string name = ExtractTitleNameFromApp(fsa, app0);
    if (!name.empty()) return name;

    // 2. Scan contentDir for any other candidate .app files
    FSADirectoryHandle dir;
    if (FSAOpenDir(fsa, contentDir.c_str(), &dir) == FS_ERROR_OK) {
        FSADirectoryEntry* entry = (FSADirectoryEntry*)memalign(0x40, sizeof(FSADirectoryEntry));
        if (entry) {
            while (FSAReadDir(fsa, dir, entry) == FS_ERROR_OK) {
                if (strcmp(entry->name, ".") == 0 || strcmp(entry->name, "..") == 0) continue;
                size_t len = strlen(entry->name);
                if (len > 4 && strcmp(entry->name + len - 4, ".app") == 0) {
                    if (strcmp(entry->name, "00000000.app") != 0) {
                        std::string candidate = contentDir + "/" + entry->name;
                        name = ExtractTitleNameFromApp(fsa, candidate);
                        if (!name.empty()) break;
                    }
                }
            }
            free(entry);
        }
        FSACloseDir(fsa, dir);
    }
    return name;
}

static std::string GetAsciiCode(uint32_t idLo) {
    char code[5] = {0};
    code[0] = (char)((idLo >> 24) & 0xFF);
    code[1] = (char)((idLo >> 16) & 0xFF);
    code[2] = (char)((idLo >> 8) & 0xFF);
    code[3] = (char)(idLo & 0xFF);

    bool printable = true;
    for (int i = 0; i < 4; i++) {
        if (code[i] < 32 || code[i] > 126) {
            printable = false;
            break;
        }
    }

    if (printable) {
        return std::string(code, 4);
    }

    char hexBuf[16];
    snprintf(hexBuf, sizeof(hexBuf), "%08x", idLo);
    return std::string(hexBuf);
}

static std::string LookupSystemTitleName(uint64_t titleId) {
    // 1. Check existing g_nusTitles table in wad.h (covers stock vWii titles)
    for (size_t i = 0; i < g_numNusTitles; i++) {
        const auto& t = g_nusTitles[i];
        if (t.regionSpecificId) {
            if ((t.id & ~0xFFULL) == (titleId & ~0xFFULL)) {
                return t.name;
            }
        } else {
            if (t.id == titleId) {
                return t.name;
            }
        }
    }

    // 2. Mask region character for all known System & Hidden Channels (USA/EUR/JPN/KOR)
    uint64_t maskedId = titleId & ~0xFFULL;
    if (maskedId == 0x0001000248435500ULL) return "Wii Menu Electronic Manual"; // HCU* (HCUA, HCUP, HCUJ, etc.)
    if (maskedId == 0x0001000848414C00ULL) return "Region Select";              // HAL* (HALE, HALP, HALJ, etc.)
    if (maskedId == 0x0001000848435A00ULL) return "Wii System Transfer";        // HCZ* (HCZE, HCZP, HCZJ, etc.)
    if (maskedId == 0x0001000848414B00ULL) return "EULA";                      // HAK* (HAKE, HAKP, HAKJ, etc.)
    if (maskedId == 0x0001000248414400ULL) return "Mii Channel";                // HAD* (HADE, HADA, HADJ, etc.)
    if (maskedId == 0x0001000248414100ULL) return "Photo Channel 1.0";          // HAA*
    if (maskedId == 0x0001000248415900ULL) return "Photo Channel 1.1";          // HAY*
    if (maskedId == 0x0001000248414200ULL) return "News Channel";               // HAB*
    if (maskedId == 0x0001000248414600ULL) return "Forecast Channel";           // HAF*
    if (maskedId == 0x0001000248414700ULL) return "Wii Shop Channel";           // HAG*
    if (maskedId == 0x0001000248435600ULL) return "Wii U Menu Channel";        // HCV*

    // 3. Extra system / GameCube titles (original Wii BC and MIOS if installed)
    if (titleId == 0x0000000100000100ULL) return "BC (GameCube)";
    if (titleId == 0x0000000100000101ULL) return "MIOS (GameCube)";

    // 4. Extra common homebrew channels
    if (titleId == 0x000100014F484243ULL) return "Open Homebrew Channel (OHBC)";
    if (titleId == 0x000100014A4F4449ULL) return "Homebrew Channel (JODI)";
    if (titleId == 0x00010001554E454FULL) return "USB Loader GX Forwarder (UNEO)";

    return "";
}

static bool IsTitleCritical(uint64_t titleId) {
    if (titleId == 0x0000000100000002ULL) return true; // System Menu
    if (titleId == 0x0000000100000050ULL) return true; // IOS80
    if (titleId == 0x0000000100000200ULL) return true; // BC-NAND
    if (titleId == 0x0000000100000201ULL) return true; // BC-WFS
    if (titleId == 0x000000010000003AULL) return true; // IOS58
    return false;
}

std::vector<ManagedTitle> ScanTitlesByCategory(FSAClientHandle fsa, TitleCategory category) {
    std::vector<ManagedTitle> results;

    std::vector<std::string> targetHiFolders;
    switch (category) {
        case TitleCategory::IOS_TITLES:
        case TitleCategory::SYSTEM_TITLES:
            targetHiFolders.push_back("00000001");
            break;
        case TitleCategory::SYSTEM_CHANNELS:
            targetHiFolders.push_back("00010002");
            targetHiFolders.push_back("00010008");
            break;
        case TitleCategory::INSTALLED_CHANNELS:
            targetHiFolders.push_back("00010001");
            targetHiFolders.push_back("00010004");
            break;
        case TitleCategory::DLC_CONTENT:
            targetHiFolders.push_back("00010005");
            break;
    }

    FSADirectoryEntry* entry = (FSADirectoryEntry*)memalign(0x40, sizeof(FSADirectoryEntry));
    if (!entry) return results;

    for (const auto& hiStr : targetHiFolders) {
        uint32_t idHi = strtoul(hiStr.c_str(), nullptr, 16);
        std::set<uint32_t> foundLoIds;

        // 1. Scan title directories (/vol/slccmpt01/title/<hiStr>/)
        std::string hiTitlePath = "/vol/slccmpt01/title/" + hiStr;
        FSADirectoryHandle titleDir;
        if (FSAOpenDir(fsa, hiTitlePath.c_str(), &titleDir) == FS_ERROR_OK) {
            while (FSAReadDir(fsa, titleDir, entry) == FS_ERROR_OK) {
                if (strcmp(entry->name, ".") == 0 || strcmp(entry->name, "..") == 0) continue;
                if (!(entry->info.flags & FS_STAT_DIRECTORY)) continue;

                uint32_t idLo = strtoul(entry->name, nullptr, 16);
                foundLoIds.insert(idLo);
            }
            FSACloseDir(fsa, titleDir);
        }

        // 2. Scan ticket directories (/vol/slccmpt01/ticket/<hiStr>/)
        std::string hiTicketPath = "/vol/slccmpt01/ticket/" + hiStr;
        FSADirectoryHandle ticketDir;
        if (FSAOpenDir(fsa, hiTicketPath.c_str(), &ticketDir) == FS_ERROR_OK) {
            while (FSAReadDir(fsa, ticketDir, entry) == FS_ERROR_OK) {
                if (strcmp(entry->name, ".") == 0 || strcmp(entry->name, "..") == 0) continue;
                size_t len = strlen(entry->name);
                if (len == 12 && strcmp(entry->name + 8, ".tik") == 0) {
                    char hexLo[9] = {0};
                    memcpy(hexLo, entry->name, 8);
                    uint32_t idLo = strtoul(hexLo, nullptr, 16);
                    foundLoIds.insert(idLo);
                }
            }
            FSACloseDir(fsa, ticketDir);
        }

        // 3. Process all found titles in this category
        for (uint32_t idLo : foundLoIds) {
            uint64_t titleId = ((uint64_t)idHi << 32) | idLo;

            // Category filtering
            if (category == TitleCategory::IOS_TITLES) {
                if (idLo < 3 || idLo > 255 || idLo == 2) continue;
            } else if (category == TitleCategory::SYSTEM_TITLES) {
                if (idLo != 2 && idLo < 0x100) continue;
            }

            char loStr[16];
            snprintf(loStr, sizeof(loStr), "%08x", idLo);

            ManagedTitle title;
            title.titleId = titleId;
            title.category = category;
            title.asciiId = GetAsciiCode(idLo);
            title.isCritical = IsTitleCritical(titleId);

            std::string basePath = hiTitlePath + "/" + loStr;
            std::string contentPath = basePath + "/content";
            std::string dataPath = basePath + "/data";

            char ticketPath[128];
            snprintf(ticketPath, sizeof(ticketPath), "/vol/slccmpt01/ticket/%08x/%08x.tik", idHi, idLo);

            FSStat stat;
            title.hasContent = (FSAGetStat(fsa, contentPath.c_str(), &stat) == FS_ERROR_OK);
            title.hasData = (FSAGetStat(fsa, dataPath.c_str(), &stat) == FS_ERROR_OK);
            title.hasTicket = (FSAGetStat(fsa, ticketPath, &stat) == FS_ERROR_OK);

            // Determine Title Name
            if (category == TitleCategory::IOS_TITLES) {
                if (idLo >= 248 && idLo <= 251) {
                    char buf[64];
                    snprintf(buf, sizeof(buf), "d2x cIOS %u (Slot %u)", idLo, idLo);
                    title.titleName = buf;
                } else {
                    std::string known = LookupSystemTitleName(titleId);
                    if (!known.empty()) {
                        title.titleName = known;
                    } else {
                        char buf[32];
                        snprintf(buf, sizeof(buf), "IOS%u", idLo);
                        title.titleName = buf;
                    }
                }
            } else if (category == TitleCategory::SYSTEM_TITLES) {
                std::string known = LookupSystemTitleName(titleId);
                if (!known.empty()) {
                    title.titleName = known;
                } else {
                    char buf[64];
                    snprintf(buf, sizeof(buf), "System Title (%08x)", idLo);
                    title.titleName = buf;
                }
            } else if (category == TitleCategory::DLC_CONTENT) {
                title.titleName = "DLC";
            } else {
                // INSTALLED_CHANNELS or SYSTEM_CHANNELS: Try extracting from content dir
                std::string extracted = ExtractTitleNameFromContentDir(fsa, contentPath);
                if (!extracted.empty()) {
                    title.titleName = extracted;
                } else {
                    std::string known = LookupSystemTitleName(titleId);
                    if (!known.empty()) {
                        title.titleName = known;
                    } else {
                        title.titleName = "Unknown Channel";
                    }
                }
            }

            results.push_back(title);
        }
    }

    free(entry);

    std::sort(results.begin(), results.end(), [](const ManagedTitle& a, const ManagedTitle& b) {
        return a.titleId < b.titleId;
    });

    return results;
}

bool DeleteTitleTarget(FSAClientHandle fsa, const ManagedTitle& title, DeleteMode mode) {
    uint32_t idHi = (uint32_t)(title.titleId >> 32);
    uint32_t idLo = (uint32_t)(title.titleId & 0xFFFFFFFF);

    char titleBase[128];
    snprintf(titleBase, sizeof(titleBase), "/vol/slccmpt01/title/%08x/%08x", idHi, idLo);

    char ticketPath[128];
    snprintf(ticketPath, sizeof(ticketPath), "/vol/slccmpt01/ticket/%08x/%08x.tik", idHi, idLo);

    bool success = true;

    if (mode == DeleteMode::EVERYTHING_INC_TICKET) {
        // Deletes content, data, AND ticket
        if (title.hasContent || title.hasData) {
            if (!FSARemoveTree(fsa, titleBase, false)) {
                success = false;
            }
        }
        if (title.hasTicket) {
            if (FSARemove(fsa, ticketPath) != FS_ERROR_OK) {
                success = false;
            }
        }
    } else if (mode == DeleteMode::CONTENT_AND_DATA) {
        // Deletes all title content and save data, but explicitly PRESERVES the ticket (.tik)
        if (title.hasContent || title.hasData) {
            if (!FSARemoveTree(fsa, titleBase, false)) {
                success = false;
            }
        }
    } else if (mode == DeleteMode::CONTENT_ONLY) {
        // Deletes content/ only; preserves data/ and preserves ticket (.tik)
        std::string contentPath = std::string(titleBase) + "/content";
        if (title.hasContent) {
            if (!FSARemoveTree(fsa, contentPath, false)) {
                success = false;
            }
        }
    } else if (mode == DeleteMode::DATA_ONLY) {
        // Deletes data/ only; preserves content/ and preserves ticket (.tik)
        std::string dataPath = std::string(titleBase) + "/data";
        if (title.hasData) {
            if (!FSARemoveTree(fsa, dataPath, false)) {
                success = false;
            }
        }
    }

    return success;
}

static std::string FormatTitleOption(const ManagedTitle& title) {
    std::string opt = title.titleName + " [" + title.asciiId + "]";
    if (title.isCritical) {
        opt += " <!CRITICAL!>";
    }
    return opt;
}

static void HandleCategoryDeletion(FSAClientHandle fsa, TitleCategory category, const std::string& categoryName) {
    while (State::AppRunning()) {
        WUPI_resetScreen();
        WUPI_Log("Scanning %s on NAND...\n", categoryName.c_str());

        std::vector<ManagedTitle> titles = ScanTitlesByCategory(fsa, category);
        if (titles.empty()) {
            WUPI_resetScreen();
            WUPI_Log("No %s found on NAND.\n", categoryName.c_str());
            WUPI_waitButton();
            return;
        }

        std::vector<std::string> options;
        for (const auto& t : titles) {
            options.push_back(FormatTitleOption(t));
        }

        std::vector<std::string> header = {
            "Delete Titles: " + categoryName,
            "Select title(s) to delete:"
        };

        std::vector<int> selectedIndices = ShowMultiSelectMenu(header, options);
        if (selectedIndices.empty()) {
            return;
        }

        // Select Deletion Mode
        WUPI_resetScreen();
        std::vector<std::string> modeHeader = {
            "Select Deletion Mode:",
            "Chosen for " + std::to_string(selectedIndices.size()) + " title(s):"
        };
        std::vector<std::string> modeOptions = {
            "Delete Content Only (Keep Save Data & Ticket)",
            "Delete Content & Data (Keep Ticket)",
            "Delete Everything (Content, Data & Ticket)",
            "Delete Save / Config Data Only (Keep Content & Ticket)"
        };

        int modeChoice = ShowMenu(modeHeader, modeOptions);
        if (modeChoice < 0) {
            continue;
        }

        DeleteMode mode = DeleteMode::CONTENT_ONLY;
        std::string modeDesc = "Content Only (Save Data & Ticket preserved)";
        if (modeChoice == 0) {
            mode = DeleteMode::CONTENT_ONLY;
            modeDesc = "Content Only (Save Data & Ticket preserved)";
        } else if (modeChoice == 1) {
            mode = DeleteMode::CONTENT_AND_DATA;
            modeDesc = "Content & Data (Ticket preserved)";
        } else if (modeChoice == 2) {
            mode = DeleteMode::EVERYTHING_INC_TICKET;
            modeDesc = "Complete (Content, Data & Ticket deleted)";
        } else if (modeChoice == 3) {
            mode = DeleteMode::DATA_ONLY;
            modeDesc = "Save / Config Data Only (Content & Ticket preserved)";
        }

        // Confirmation Screen
        bool hasCritical = false;
        std::vector<std::string> confirmHeader = {
            "Confirm Deletion (" + modeDesc + "):",
            "The following title(s) will be deleted:"
        };

        for (int idx : selectedIndices) {
            const auto& t = titles[idx];
            confirmHeader.push_back(" - " + t.titleName + " (" + t.asciiId + ")");
            if (t.isCritical) hasCritical = true;
        }

        confirmHeader.push_back("");
        if (hasCritical) {
            confirmHeader.push_back("*** DANGER: CRITICAL SYSTEM SOFTWARE SELECTED ***");
            confirmHeader.push_back("Deleting critical system titles can BRICK vWii mode!");
            confirmHeader.push_back("Are you ABSOLUTELY sure you want to delete?");
        } else {
            confirmHeader.push_back("Are you sure you want to proceed?");
        }

        std::vector<std::string> confirmOptions = {
            "No, cancel",
            "Yes, delete selected title(s)"
        };

        int confirmChoice = ShowMenu(confirmHeader, confirmOptions);
        if (confirmChoice != 1) {
            continue;
        }

        // Execution
        WUPI_resetScreen();
        int successCount = 0;
        int failCount = 0;

        for (size_t i = 0; i < selectedIndices.size(); i++) {
            if (!State::AppRunning()) break;
            const auto& t = titles[selectedIndices[i]];

            WUPI_Log("Deleting (%d/%d): %s...", (int)(i + 1), (int)selectedIndices.size(), t.titleName.c_str());

            if (DeleteTitleTarget(fsa, t, mode)) {
                WUPI_Log(" Done.\n");
                successCount++;
            } else {
                WUPI_Log(" Failed!\n");
                failCount++;
            }
        }

        WUPI_resetScreen();
        WUPI_Log("=========================================\n");
        WUPI_Log("           DELETION SUMMARY              \n");
        WUPI_Log("=========================================\n\n");
        WUPI_Log("Mode: %s\n", modeDesc.c_str());
        WUPI_Log("Successful: %d\n", successCount);
        WUPI_Log("Failed:     %d\n\n", failCount);
        WUPI_waitButton();
    }
}

void WUPI_DeleteTitlesMenu() {
    while (State::AppRunning()) {
        WUPI_resetScreen();

        std::vector<std::string> header = {
            "Delete Titles Menu:",
            "Select a title category:"
        };

        std::vector<std::string> options = {
            "Installed Channels (WiiWare, VC, Custom Channels)",
            "System Channels (Mii, Photo, Shop, EULA, etc.)",
            "IOS Titles (IOS9 - IOS80, d2x cIOS)",
            "System Titles (System Menu, BC-NAND, MIOS)",
            "Downloadable Content (DLC)"
        };

        int selected = ShowMenu(header, options);
        if (selected == 0) {
            HandleCategoryDeletion(fsaClient, TitleCategory::INSTALLED_CHANNELS, "Installed Channels");
        } else if (selected == 1) {
            HandleCategoryDeletion(fsaClient, TitleCategory::SYSTEM_CHANNELS, "System Channels");
        } else if (selected == 2) {
            HandleCategoryDeletion(fsaClient, TitleCategory::IOS_TITLES, "IOS Titles");
        } else if (selected == 3) {
            HandleCategoryDeletion(fsaClient, TitleCategory::SYSTEM_TITLES, "System Titles");
        } else if (selected == 4) {
            HandleCategoryDeletion(fsaClient, TitleCategory::DLC_CONTENT, "DLC Titles");
        } else if (selected == -1) {
            break;
        }
    }
}
