#pragma once

#include "wad.h"
#include <string>
#include <vector>
#include <cstdint>
#include <functional>

enum class ScanIssueType {
    MISSING_TITLE,
    UNSIGNED_TMD,
    REGION_MISMATCH,
    CONTENT_MODIFIED,
    CONTENT_MISSING,
    PERMISSIONS_INCORRECT,
    SETTING_TXT_INVALID,
    SETTING_TXT_PERMISSIONS,
    CERT_SYS_INVALID,
    UID_SYS_INVALID,
    FOREIGN_TITLE
};

struct SystemScanIssue {
    std::string titleName;              // e.g. "System Menu (vWii)", "IOS80", "setting.txt"
    uint64_t titleId = 0;               // Resolved Title ID (0 for system config files)
    const NusTitle* nusTitle = nullptr; // Pointer to g_nusTitles entry if restorable via NUS
    std::vector<std::string> reasons;   // Detailed list of detected faults
    bool isSettingTxt = false;
    bool isCertSys = false;
    bool isUidSys = false;
    bool isStockDirs = false;
    bool isForeignTitle = false;
    bool isPermissionOnly = false;
    uint16_t groupId = 0;

    std::string FormatOption() const;
};

struct SystemScanReport {
    int32_t targetRegionCode = -1;      // 0: JPN, 1: USA, 2: EUR
    std::string targetRegionStr;         // "JPN", "USA", "EUR"
    bool regionWasAmbiguous = false;
    int totalTitlesScanned = 0;
    int missingTitlesCount = 0;
    int modifiedTitlesCount = 0;
    int permissionErrorsCount = 0;
    bool settingTxtDamaged = false;
    bool certSysDamaged = false;
    bool uidSysDamaged = false;
    std::vector<SystemScanIssue> issues;
};

// Determines target region by checking setting.txt, installed titles, and MCP SysProd.
// Sets outIsAmbiguous to true if setting.txt is missing/invalid or conflicts with installed titles.
int32_t SCAN_DetermineTargetRegion(bool& outIsAmbiguous);

// Executes a full scan of vWii system titles, setting.txt, cert.sys, uid.sys, and SFFS permissions.
SystemScanReport SCAN_RunFullSystemScan(int32_t targetRegionCode, std::function<void(const std::string&)> progressCb);

// Restores selected issues (installs titles from NUS, regenerates setting.txt, fixes certs/UIDs).
bool SCAN_RestoreSelectedIssues(const std::vector<SystemScanIssue>& selectedIssues, int32_t targetRegionCode);

// Main interactive UI entry point for the Scan & Restore feature.
void WUPI_ScanAndRestoreMenu();
