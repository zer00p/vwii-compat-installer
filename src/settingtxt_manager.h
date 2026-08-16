#pragma once

#include <string>
#include <vector>
#include <cstdint>

#define VWII_SETTING_TXT_PATH "/vol/slccmpt01/title/00000001/00000002/data/setting.txt"

struct VwiiSettings {
    std::string area;   // "EUR", "USA", "JPN"
    std::string model;  // "RVL-001(EUR)", "RVL-001(USA)", "RVL-001(JPN)"
    uint8_t dvd = 0;    // 0-255 (0 = Default)
    std::string mpch;   // "0x7FFE"
    std::string code;   // e.g. "IEL", "IUL", "IJL"
    std::string serno;  // console serial number string
    std::string video;  // "PAL", "NTSC", "MPAL"
    std::string game;   // "EU", "US", "JP"

    bool isValid() const {
        return !area.empty() && !model.empty() && !video.empty() && !game.empty();
    }
};

// Symmetrical cipher for setting.txt (key 0x73B5DBFA)
void Setting_Cipher(uint8_t* buf, size_t len);

// Read and decrypt setting.txt from SLCCMPT
bool Setting_ReadCurrent(VwiiSettings& outSettings);

// Encrypt and write setting.txt to SLCCMPT, automatically creating missing directories
bool Setting_Write(const VwiiSettings& settings);

// Regenerate settings from Wii U MCP system production settings (vWii Decaffeinator logic)
bool Setting_RegenerateFromMCP(VwiiSettings& outSettings);

// Apply standard region presets ("EUR", "USA", "JPN")
bool Setting_ApplyPreset(VwiiSettings& settings, const std::string& regionCode);

// Export setting.txt to SD card (decrypted text or raw encrypted)
bool Setting_ExportToSD(const std::string& path, bool decrypted);

// Import setting.txt from SD card (auto-detects encrypted or plaintext)
bool Setting_ImportFromSD(const std::string& path, VwiiSettings& outSettings);

// Get region code (0: JPN, 1: USA, 2: EUR, -1: Unknown/Error)
int32_t Setting_GetRegionIndex(const VwiiSettings& settings);

// Query region from setting.txt with fallback to MCP if missing
int32_t Setting_GetEffectiveRegionCode();
