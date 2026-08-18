#include "settingtxt_manager.h"
#include "FSAUtils.h"
#include "uid_sys.h"
#include "MenuUtils.h"
#include "log.h"

#include <coreinit/filesystem_fsa.h>
#include <coreinit/mcp.h>
#include <malloc.h>
#include <cstring>
#include <sstream>
#include <algorithm>
#include <unistd.h>

extern FSAClientHandle fsaClient;

void Setting_Cipher(uint8_t* buf, size_t len) {
    uint32_t key = 0x73B5DBFA;
    for (size_t i = 0; i < len; i++) {
        buf[i] ^= (uint8_t)(key & 0xFF);
        key = (key << 1) | (key >> 31);
    }
}

static std::string TrimString(const std::string& str) {
    size_t start = str.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    size_t end = str.find_last_not_of(" \t\r\n");
    return str.substr(start, end - start + 1);
}

static bool ParseSettingsString(const std::string& content, VwiiSettings& out) {
    std::istringstream stream(content);
    std::string line;
    bool foundAny = false;

    while (std::getline(stream, line)) {
        line = TrimString(line);
        if (line.empty()) continue;

        size_t eqPos = line.find('=');
        if (eqPos == std::string::npos) continue;

        std::string key = TrimString(line.substr(0, eqPos));
        std::string val = TrimString(line.substr(eqPos + 1));

        if (key == "AREA") {
            out.area = val;
            foundAny = true;
        } else if (key == "MODEL") {
            out.model = val;
            foundAny = true;
        } else if (key == "DVD") {
            try {
                unsigned long num = std::stoul(val, nullptr, 0);
                out.dvd = (uint8_t)std::min(num, 255UL);
            } catch (...) {
                out.dvd = 0;
            }
            foundAny = true;
        } else if (key == "MPCH") {
            out.mpch = val;
            foundAny = true;
        } else if (key == "CODE") {
            out.code = val;
            foundAny = true;
        } else if (key == "SERNO") {
            out.serno = val;
            foundAny = true;
        } else if (key == "VIDEO") {
            out.video = val;
            foundAny = true;
        } else if (key == "GAME") {
            out.game = val;
            foundAny = true;
        }
    }

    if (out.mpch.empty()) out.mpch = "0x7FFE";
    return foundAny;
}

bool Setting_ReadCurrent(VwiiSettings& outSettings) {
    uint8_t* buf = nullptr;
    uint32_t size = 0;
    if (!ReadFileToBuffer(VWII_SETTING_TXT_PATH, &buf, &size) || size == 0) {
        return false;
    }

    Setting_Cipher(buf, size);
    std::string decrypted((char*)buf, size);
    free(buf);

    return ParseSettingsString(decrypted, outSettings);
}

bool Setting_Write(const VwiiSettings& settings) {
    char* alignBuf = (char*)memalign(0x40, 256);
    if (!alignBuf) {
        WUPI_Log("Setting_Write: Failed to allocate aligned buffer\n");
        return false;
    }
    memset(alignBuf, 0, 256);

    std::string area = settings.area.empty() ? "EUR" : settings.area;
    std::string model = settings.model.empty() ? ("RVL-001(" + area + ")") : settings.model;
    std::string mpch = settings.mpch.empty() ? "0x7FFE" : settings.mpch;
    std::string code = settings.code.empty() ? "IEL" : settings.code;
    std::string serno = settings.serno.empty() ? "000000000" : settings.serno;
    std::string video = settings.video.empty() ? "PAL" : settings.video;
    std::string game = settings.game.empty() ? "EU" : settings.game;

    int written = snprintf(alignBuf, 256,
        "AREA=%s\n"
        "MODEL=%s\n"
        "DVD=%u\n"
        "MPCH=%s\n"
        "CODE=%s\n"
        "SERNO=%s\n"
        "VIDEO=%s\n"
        "GAME=%s\n",
        area.c_str(),
        model.c_str(),
        (unsigned int)settings.dvd,
        mpch.c_str(),
        code.c_str(),
        serno.c_str(),
        video.c_str(),
        game.c_str());

    if (written <= 0 || written >= 256) {
        WUPI_Log("Setting_Write: snprintf failed or exceeded 256 bytes\n");
        free(alignBuf);
        return false;
    }

    // Encrypt the 256-byte buffer (symmetrical XOR key 0x73B5DBFA)
    Setting_Cipher((uint8_t*)alignBuf, 256);

    // Ensure parent directory hierarchy exists with correct stock ownership and modes:
    // 1. /vol/slccmpt01/title/00000001
    EnsureFSADir(fsaClient, "/vol/slccmpt01/title/00000001");

    // 2. /vol/slccmpt01/title/00000001/00000002 (System Menu Title Dir - must be chowned while empty)
    FSAMakeDirWithOwner(fsaClient, "/vol/slccmpt01/title/00000001/00000002", STOCK_MODE_SYSTEM_DIR, 0, 0);

    // 3. /vol/slccmpt01/title/00000001/00000002/data (System Menu Data Dir - MUST be owned by UID 4096, GID 1 while empty)
    FSAMakeDirWithOwner(fsaClient, "/vol/slccmpt01/title/00000001/00000002/data", STOCK_MODE_DATA_DIR, VWII_UID_SYSTEM_MENU, VWII_GID_SYSTEM_MENU);

    // Ensure /sys/uid.sys exists with entry 0 for System Menu (0x1000)
    UID_GetOrCreate(fsaClient, VWII_TITLE_ID_SYSTEM_MENU);

    // Create file, set stock ownership (UID 4096, GID 1) while 0-byte empty, then write encrypted data
    bool writeOk = FSACreateFileWithOwner(fsaClient, VWII_SETTING_TXT_PATH, alignBuf, 256,
                                          STOCK_MODE_SETTING_TXT, VWII_UID_SYSTEM_MENU, VWII_GID_SYSTEM_MENU);
    free(alignBuf);

    if (!writeOk) {
        WUPI_Log("Failed to write setting.txt with ownership\n");
        return false;
    }

    return true;
}

bool Setting_RegenerateFromMCP(VwiiSettings& outSettings) {
    MCPSysProdSettings* psettings = (MCPSysProdSettings*)memalign(0x40, sizeof(MCPSysProdSettings));
    if (!psettings) {
        WUPI_Log("Setting_RegenerateFromMCP: Failed to allocate aligned buffer\n");
        return false;
    }
    memset(psettings, 0, sizeof(MCPSysProdSettings));

    int handle = MCP_Open();
    if (handle < 0) {
        WUPI_Log("Setting_RegenerateFromMCP: MCP_Open failed\n");
        free(psettings);
        return false;
    }

    int getRes = MCP_GetSysProdSettings(handle, psettings);
    MCP_Close(handle);

    if (getRes < 0) {
        WUPI_Log("Setting_RegenerateFromMCP: MCP_GetSysProdSettings failed\n");
        free(psettings);
        return false;
    }

    std::string areaStr = "EUR";
    std::string modelStr = "RVL-001(EUR)";
    std::string videoStr = "PAL";
    std::string gameStr = "EU";

    if (psettings->product_area == MCP_REGION_USA) {
        areaStr = "USA";
        modelStr = "RVL-001(USA)";
        videoStr = "NTSC";
        gameStr = "US";
    } else if (psettings->product_area == MCP_REGION_JAPAN) {
        areaStr = "JPN";
        modelStr = "RVL-001(JPN)";
        videoStr = "NTSC";
        gameStr = "JP";
    } else {
        areaStr = "EUR";
        modelStr = "RVL-001(EUR)";
        videoStr = "PAL";
        gameStr = "EU";
    }

    char codeBuf[9];
    memset(codeBuf, 0, sizeof(codeBuf));
    strncpy(codeBuf, psettings->code_id, 8);
    // Convert first character from Wii U ('G') to vWii ('I' or 'O')
    if (codeBuf[0] == 'G') {
        codeBuf[0] = 'I';
    } else if (codeBuf[0] != 'I') {
        codeBuf[0] = 'O';
    }

    char serialBuf[13];
    memset(serialBuf, 0, sizeof(serialBuf));
    strncpy(serialBuf, psettings->serial_id, 12);

    if (strlen(psettings->ntsc_pal) > 0) {
        videoStr = psettings->ntsc_pal;
    }

    outSettings.area = areaStr;
    outSettings.model = modelStr;
    outSettings.dvd = 0;
    outSettings.mpch = "0x7FFE";
    outSettings.code = codeBuf;
    outSettings.serno = serialBuf;
    outSettings.video = videoStr;
    outSettings.game = gameStr;

    free(psettings);
    return true;
}

bool Setting_ApplyPreset(VwiiSettings& settings, const std::string& regionCode) {
    if (regionCode == "USA") {
        settings.area = "USA";
        settings.model = "RVL-001(USA)";
        settings.video = "NTSC";
        settings.game = "US";
        if (settings.code.empty() || settings.code[0] == 'I') {
            settings.code = "IUL";
        }
        return true;
    } else if (regionCode == "JPN") {
        settings.area = "JPN";
        settings.model = "RVL-001(JPN)";
        settings.video = "NTSC";
        settings.game = "JP";
        if (settings.code.empty() || settings.code[0] == 'I') {
            settings.code = "IJL";
        }
        return true;
    } else if (regionCode == "EUR") {
        settings.area = "EUR";
        settings.model = "RVL-001(EUR)";
        settings.video = "PAL";
        settings.game = "EU";
        if (settings.code.empty() || settings.code[0] == 'I') {
            settings.code = "IEL";
        }
        return true;
    }
    return false;
}

bool Setting_ExportToSD(const std::string& path, bool decrypted) {
    EnsureFSAParentDir(fsaClient, path);

    VwiiSettings current;
    if (!Setting_ReadCurrent(current)) {
        return false;
    }

    char* alignBuf = (char*)memalign(0x40, 512);
    if (!alignBuf) return false;
    memset(alignBuf, 0, 512);

    int len = snprintf(alignBuf, 512,
        "AREA=%s\n"
        "MODEL=%s\n"
        "DVD=%u\n"
        "MPCH=%s\n"
        "CODE=%s\n"
        "SERNO=%s\n"
        "VIDEO=%s\n"
        "GAME=%s\n",
        current.area.c_str(),
        current.model.c_str(),
        (unsigned int)current.dvd,
        current.mpch.c_str(),
        current.code.c_str(),
        current.serno.c_str(),
        current.video.c_str(),
        current.game.c_str());

    if (!decrypted) {
        // Encrypt standard 256 bytes
        memset(alignBuf + len, 0, 256 - len);
        Setting_Cipher((uint8_t*)alignBuf, 256);
        len = 256;
    }

    FSAFileHandle fd = 0;
    if (FSAOpenFileEx(fsaClient, path.c_str(), "wb", (FSMode)0x666, FS_OPEN_FLAG_NONE, 0, &fd) != FS_ERROR_OK) {
        free(alignBuf);
        return false;
    }

    int res = FSAWriteFile(fsaClient, alignBuf, 1, len, fd, 0);
    FSACloseFile(fsaClient, fd);
    free(alignBuf);

    return res == len;
}

bool Setting_ImportFromSD(const std::string& path, VwiiSettings& outSettings) {
    uint8_t* buf = nullptr;
    uint32_t size = 0;
    if (!ReadFileToBuffer(path, &buf, &size) || size == 0) {
        return false;
    }

    std::string text((char*)buf, size);
    // If not plain text, try decrypting
    if (text.find("AREA=") == std::string::npos) {
        Setting_Cipher(buf, size);
        text = std::string((char*)buf, size);
    }
    free(buf);

    return ParseSettingsString(text, outSettings);
}

std::string Setting_GetRegionName(int32_t regionCode) {
    switch (regionCode) {
        case 0: return "JPN";
        case 1: return "USA";
        case 2: return "EUR";
        default: return "Unknown";
    }
}

int32_t Setting_GetRegionIndex(const std::string& area) {
    if (area == "JPN") return 0;
    if (area == "USA") return 1;
    if (area == "EUR") return 2;
    return -1;
}

int32_t Setting_GetRegionIndex(const VwiiSettings& settings) {
    return Setting_GetRegionIndex(settings.area);
}

int32_t Setting_GetEffectiveRegionCode() {
    VwiiSettings current;
    if (Setting_ReadCurrent(current)) {
        int32_t idx = Setting_GetRegionIndex(current);
        if (idx != -1) return idx;
    }

    // Fallback: Query Wii U MCP SysProd
    VwiiSettings mcpSettings;
    if (Setting_RegenerateFromMCP(mcpSettings)) {
        return Setting_GetRegionIndex(mcpSettings);
    }

    return -1;
}

std::string Setting_PromptRegionSelection(const std::string& headerTitle, const std::string& currentVwiiRegion) {
    VwiiSettings mcpSettings;
    std::string wiiuRegion = "EUR";
    if (Setting_RegenerateFromMCP(mcpSettings) && !mcpSettings.area.empty()) {
        wiiuRegion = mcpSettings.area;
    }

    std::vector<std::string> regions;
    regions.push_back(wiiuRegion);
    for (const char* r : {"EUR", "USA", "JPN"}) {
        if (wiiuRegion != r) {
            regions.push_back(r);
        }
    }

    std::vector<std::string> regionOptions;
    for (size_t i = 0; i < regions.size(); i++) {
        std::string opt = regions[i];
        if (regions[i] == wiiuRegion) {
            opt += " (Console Native - Recommended)";
        }
        if (!currentVwiiRegion.empty() && regions[i] == currentVwiiRegion) {
            opt += " [Current vWii]";
        }
        regionOptions.push_back(opt);
    }

    std::vector<std::string> selectHeader = {
        headerTitle,
    };
    if (!currentVwiiRegion.empty()) {
        selectHeader.push_back("Current vWii Region: " + currentVwiiRegion);
    }
    selectHeader.push_back("Console Native Region: " + wiiuRegion);
    selectHeader.push_back("");
    selectHeader.push_back("Select target vWii region:");

    int selected = ShowMenu(selectHeader, regionOptions);
    if (selected < 0 || selected >= (int)regions.size()) {
        return "";
    }

    return regions[selected];
}
