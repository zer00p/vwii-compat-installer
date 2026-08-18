#include "system_scanner.h"
#include "settingtxt_manager.h"
#include "region_changer.h"
#include "FSAUtils.h"
#include "cert_sys.h"
#include "uid_sys.h"
#include "log.h"
#include "MenuUtils.h"
#include "ScreenUtils.h"
#include "StateUtils.h"
#include "InputUtils.h"
#include "EndianUtils.h"

extern "C" {
#include "wad_tools/tools.h"
}

#include <coreinit/filesystem_fsa.h>
#include <mbedtls/sha1.h>
#include <malloc.h>
#include <unistd.h>
#include <cstring>
#include <format>
#include <algorithm>
#include <vector>
#include <string>

extern FSAClientHandle fsaClient;

std::string SystemScanIssue::FormatOption() const {
    std::string opt = titleName;
    if (!reasons.empty()) {
        opt += " [";
        for (size_t i = 0; i < reasons.size(); i++) {
            if (i > 0) opt += ", ";
            opt += reasons[i];
        }
        opt += "]";
    }
    return opt;
}

static bool VerifyTmdSignature(const uint8_t* tmdData, uint32_t tmdSize, const std::vector<ParsedCert>& certs) {
    if (!tmdData || tmdSize < 0x1E4 || certs.empty()) return false;

    uint32_t sigType = Read32BE(tmdData);
    if (sigType != 0x00010001) {
        return false;
    }

    uint32_t payloadOffset = GetPayloadOffset(tmdData);
    if (tmdSize <= payloadOffset) return false;

    char issuerStr[65] = {0};
    memcpy(issuerStr, tmdData + payloadOffset, 64);
    std::string issuer(issuerStr);

    std::string signerCertName = issuer;
    size_t lastDash = issuer.rfind('-');
    if (lastDash != std::string::npos) {
        signerCertName = issuer.substr(lastDash + 1);
    }

    const ParsedCert* matchingCert = nullptr;
    for (const auto& c : certs) {
        if (c.name == signerCertName && c.size >= 0x2CC && c.sigType == 0x00010001) {
            matchingCert = &c;
            break;
        }
    }

    if (!matchingCert) {
        return false;
    }

    uint32_t payloadLen = tmdSize - payloadOffset;
    uint8_t hash[20];
    sha(const_cast<uint8_t*>(tmdData + payloadOffset), payloadLen, hash);

    uint8_t* sig = const_cast<uint8_t*>(tmdData + 4);
    uint8_t* key = const_cast<uint8_t*>(matchingCert->data + 0x1C8);

    return (check_rsa(hash, sig, key, 0x100) == 0);
}



int32_t SCAN_DetermineTargetRegion(bool& outIsAmbiguous) {
    outIsAmbiguous = false;

    // 1. Check setting.txt
    VwiiSettings currentSettings;
    bool settingOk = Setting_ReadCurrent(currentSettings);
    int32_t settingRegion = settingOk ? Setting_GetRegionIndex(currentSettings) : -1;

    // 2. Check installed region-specific titles on disk
    std::vector<int32_t> detectedTitleRegions;

    // Check System Menu (0000000100000002) version
    uint8_t* sysMenuTmd = nullptr;
    uint32_t sysMenuTmdSize = 0;
    if (ReadFileToBuffer("/vol/slccmpt01/title/00000001/00000002/content/title.tmd", &sysMenuTmd, &sysMenuTmdSize) && sysMenuTmdSize >= 0x1E0) {
        uint32_t payloadOffset = GetPayloadOffset(sysMenuTmd);
        if (sysMenuTmdSize >= payloadOffset + 0x9E) {
            uint16_t version = Read16BE(sysMenuTmd + payloadOffset + 0x9C);
            int32_t reg = version & 3;
            if (reg >= 0 && reg <= 2) {
                detectedTitleRegions.push_back(reg);
            }
        }
        free(sysMenuTmd);
    }

    // Check Region Select channels (0001000848414cxx)
    FSStat stat;
    if (FSAGetStat(fsaClient, "/vol/slccmpt01/title/00010008/48414c4a", &stat) == FS_ERROR_OK) detectedTitleRegions.push_back(0); // JPN
    if (FSAGetStat(fsaClient, "/vol/slccmpt01/title/00010008/48414c45", &stat) == FS_ERROR_OK) detectedTitleRegions.push_back(1); // USA
    if (FSAGetStat(fsaClient, "/vol/slccmpt01/title/00010008/48414c50", &stat) == FS_ERROR_OK) detectedTitleRegions.push_back(2); // EUR

    // Check Manual channels (00010002484355xx)
    if (FSAGetStat(fsaClient, "/vol/slccmpt01/title/00010002/4843554a", &stat) == FS_ERROR_OK) detectedTitleRegions.push_back(0); // JPN
    if (FSAGetStat(fsaClient, "/vol/slccmpt01/title/00010002/48435545", &stat) == FS_ERROR_OK) detectedTitleRegions.push_back(1); // USA
    if (FSAGetStat(fsaClient, "/vol/slccmpt01/title/00010002/48435550", &stat) == FS_ERROR_OK) detectedTitleRegions.push_back(2); // EUR

    // Check Native Wii U MCP region
    VwiiSettings mcpSettings;
    int32_t mcpRegion = 2; // default EUR
    if (Setting_RegenerateFromMCP(mcpSettings)) {
        int32_t r = Setting_GetRegionIndex(mcpSettings);
        if (r != -1) mcpRegion = r;
    }

    // If setting.txt is invalid or missing -> Ambiguous
    if (settingRegion == -1) {
        outIsAmbiguous = true;
        return !detectedTitleRegions.empty() ? detectedTitleRegions[0] : mcpRegion;
    }

    // Check if detected title regions conflict with each other or setting.txt
    for (int32_t reg : detectedTitleRegions) {
        if (reg != settingRegion) {
            outIsAmbiguous = true;
            break;
        }
    }

    return settingRegion;
}

SystemScanReport SCAN_RunFullSystemScan(int32_t targetRegionCode, std::function<void(const std::string&)> progressCb) {
    SystemScanReport report;
    report.targetRegionCode = targetRegionCode;
    report.targetRegionStr = Setting_GetRegionName(targetRegionCode);

    auto LogProgress = [&](const std::string& msg) {
        if (progressCb) progressCb(msg);
    };

    // 1. Audit setting.txt
    LogProgress("Auditing setting.txt...");
    {
        SystemScanIssue settingIssue;
        settingIssue.titleName = "setting.txt";
        settingIssue.isSettingTxt = true;

        FSStat stat;
        if (FSAGetStat(fsaClient, VWII_SETTING_TXT_PATH, &stat) != FS_ERROR_OK) {
            settingIssue.reasons.push_back("File missing");
            report.settingTxtDamaged = true;
        } else {
            uint32_t owner = stat.owner;
            uint32_t group = stat.group;
            uint32_t mode = (uint32_t)stat.mode;

            if (owner != 4096 || group != 1) {
                settingIssue.reasons.push_back(std::format("Ownership: UID {}, GID {} (expected 4096, 1)", owner, group));
                report.settingTxtDamaged = true;
            }
            if (stat.mode != STOCK_MODE_SETTING_TXT) {
                settingIssue.reasons.push_back(std::format("Mode: 0x{:x} (expected 0x444)", mode));
                report.settingTxtDamaged = true;
            }

            VwiiSettings cur;
            if (!Setting_ReadCurrent(cur) || !cur.isValid()) {
                settingIssue.reasons.push_back("Corrupted / invalid format");
                report.settingTxtDamaged = true;
            } else if (cur.area != report.targetRegionStr) {
                settingIssue.reasons.push_back(std::format("Region mismatch ({} != {})", cur.area, report.targetRegionStr));
                report.settingTxtDamaged = true;
            }
        }

        if (!settingIssue.reasons.empty()) {
            report.issues.push_back(settingIssue);
        }
    }

    // 2. Audit cert.sys and load certificates for TMD signature verification
    LogProgress("Auditing /sys/cert.sys...");
    std::vector<ParsedCert> systemCerts;
    uint8_t* certSysBuf = nullptr;
    uint32_t certSysSize = 0;
    {
        SystemScanIssue certIssue;
        certIssue.titleName = "/sys/cert.sys";
        certIssue.isCertSys = true;

        FSStat stat;
        if (FSAGetStat(fsaClient, VWII_CERT_SYS_PATH, &stat) != FS_ERROR_OK || stat.size < 0x300) {
            certIssue.reasons.push_back("Missing or truncated");
            report.certSysDamaged = true;
        } else {
            if (stat.owner != 0 || stat.group != 0 || stat.mode != STOCK_MODE_SYSTEM_FILE) {
                certIssue.reasons.push_back("Permissions/Ownership incorrect");
                report.certSysDamaged = true;
            }

            if (ReadFileToBuffer(VWII_CERT_SYS_PATH, &certSysBuf, &certSysSize)) {
                CERT_ParseCertificates(certSysBuf, certSysSize, systemCerts);
            }
        }

        if (!certIssue.reasons.empty()) {
            report.issues.push_back(certIssue);
        }
    }

    // 3. Audit uid.sys
    LogProgress("Auditing /sys/uid.sys...");
    {
        SystemScanIssue uidIssue;
        uidIssue.titleName = "/sys/uid.sys";
        uidIssue.isUidSys = true;

        FSStat stat;
        if (FSAGetStat(fsaClient, "/vol/slccmpt01/sys/uid.sys", &stat) != FS_ERROR_OK || stat.size < 12) {
            uidIssue.reasons.push_back("Missing or corrupted");
            report.uidSysDamaged = true;
        } else {
            if (stat.owner != 0 || stat.group != 0 || stat.mode != STOCK_MODE_SYSTEM_FILE) {
                uidIssue.reasons.push_back("Permissions/Ownership incorrect");
                report.uidSysDamaged = true;
            }
        }

        if (!uidIssue.reasons.empty()) {
            report.issues.push_back(uidIssue);
        }
    }

    // 4. Audit all 38 official system titles for target region
    for (size_t i = 0; i < g_numNusTitles; i++) {
        if (!State::AppRunning()) break;
        const auto& t = g_nusTitles[i];
        report.totalTitlesScanned++;

        uint64_t titleId = NUS_ResolveTitleId(&t, targetRegionCode);
        uint32_t idHi = (uint32_t)(titleId >> 32);
        uint32_t idLo = (uint32_t)(titleId & 0xFFFFFFFF);

        std::string titleDir = std::format("/vol/slccmpt01/title/{:08x}/{:08x}", idHi, idLo);
        std::string contentDir = titleDir + "/content";
        std::string dataDir = titleDir + "/data";
        std::string tmdPath = contentDir + "/title.tmd";
        std::string tikPath = std::format("/vol/slccmpt01/ticket/{:08x}/{:08x}.tik", idHi, idLo);

        LogProgress(std::format("Auditing {} ({}/{})...", t.name, i + 1, g_numNusTitles));

        SystemScanIssue issue;
        issue.titleName = t.name;
        issue.titleId = titleId;
        issue.nusTitle = &t;

        FSStat titleStat;
        if (FSAGetStat(fsaClient, titleDir.c_str(), &titleStat) != FS_ERROR_OK) {
            issue.reasons.push_back("Missing title (not installed)");
            report.missingTitlesCount++;
            report.issues.push_back(issue);
            continue;
        }

        // Check directory permissions
        if (titleStat.owner != 0 || titleStat.group != 0 || titleStat.mode != STOCK_MODE_SYSTEM_DIR) {
            issue.reasons.push_back("Title dir permissions incorrect");
            report.permissionErrorsCount++;
        }

        FSStat contentStat;
        if (FSAGetStat(fsaClient, contentDir.c_str(), &contentStat) != FS_ERROR_OK ||
            contentStat.owner != 0 || contentStat.group != 0 || contentStat.mode != STOCK_MODE_CONTENT_DIR) {
            issue.reasons.push_back("Content dir permissions incorrect");
            report.permissionErrorsCount++;
        }

        FSStat tikStat;
        if (FSAGetStat(fsaClient, tikPath.c_str(), &tikStat) != FS_ERROR_OK) {
            issue.reasons.push_back("Missing ticket (.tik)");
            report.modifiedTitlesCount++;
        } else if (tikStat.owner != 0 || tikStat.group != 0 || tikStat.mode != STOCK_MODE_SYSTEM_FILE) {
            issue.reasons.push_back("Ticket permissions incorrect");
            report.permissionErrorsCount++;
        }

        // Read and check TMD
        uint8_t* tmdBuf = nullptr;
        uint32_t tmdSize = 0;
        if (!ReadFileToBuffer(tmdPath, &tmdBuf, &tmdSize) || tmdSize < 0x1E4) {
            issue.reasons.push_back("Missing or unreadable TMD");
            report.modifiedTitlesCount++;
            if (tmdBuf) free(tmdBuf);
            report.issues.push_back(issue);
            continue;
        }

        FSStat tmdStat;
        if (FSAGetStat(fsaClient, tmdPath.c_str(), &tmdStat) == FS_ERROR_OK) {
            if (tmdStat.owner != 0 || tmdStat.group != 0 || tmdStat.mode != STOCK_MODE_SYSTEM_FILE) {
                issue.reasons.push_back("TMD permissions incorrect");
                report.permissionErrorsCount++;
            }
        }

        // Verify Nintendo RSA signature on TMD
        if (!VerifyTmdSignature(tmdBuf, tmdSize, systemCerts)) {
            issue.reasons.push_back("TMD not signed by Nintendo (Modified / Trucha)");
            report.modifiedTitlesCount++;
        }

        uint32_t payloadOffset = GetPayloadOffset(tmdBuf);
        uint16_t numContents = Read16BE(tmdBuf + payloadOffset + 0x9E);
        uint16_t titleVersion = Read16BE(tmdBuf + payloadOffset + 0x9C);
        uint16_t groupId = Read16BE(tmdBuf + payloadOffset + 0x98);

        // Check region-specific System Menu version
        if (t.id == 0x0000000100000002ULL) {
            if ((titleVersion & 3) != targetRegionCode) {
                issue.reasons.push_back(std::format("Wrong region System Menu (v{}, expected {})",
                                                    titleVersion, report.targetRegionStr));
                report.modifiedTitlesCount++;
            }
        }

        // Check /data directory permissions
        FSStat dataStat;
        if (FSAGetStat(fsaClient, dataDir.c_str(), &dataStat) == FS_ERROR_OK) {
            uint32_t expectedUid = (titleId == 0x0000000100000002ULL) ? 4096 : UID_GetOrCreate(fsaClient, titleId);
            uint32_t expectedGid = (titleId == 0x0000000100000002ULL) ? 1 : groupId;
            if (dataStat.owner != expectedUid || dataStat.group != expectedGid || dataStat.mode != STOCK_MODE_DATA_DIR) {
                issue.reasons.push_back("Data dir permissions incorrect");
                report.permissionErrorsCount++;
            }
        }

        // Check all content records in TMD
        bool contentIssueFound = false;
        for (uint16_t c = 0; c < numContents; c++) {
            uint32_t recOff = payloadOffset + 0xA4 + (c * 0x24);
            if (tmdSize < recOff + 0x24) break;

            uint32_t cid = Read32BE(tmdBuf + recOff);
            uint16_t ctype = Read16BE(tmdBuf + recOff + 6);
            uint64_t csize = Read64BE(tmdBuf + recOff + 8);
            const uint8_t* expHash = tmdBuf + recOff + 0x10;

            std::string contentPath;
            if ((ctype & 0x8000) != 0) {
                // Shared content
                int32_t sharedIdx = FindSharedContentIndex(expHash);
                if (sharedIdx >= 0) {
                    contentPath = std::format("/vol/slccmpt01/shared1/{:08x}.app", sharedIdx);
                } else {
                    issue.reasons.push_back(std::format("Shared content missing: {:08x}", cid));
                    contentIssueFound = true;
                    continue;
                }
            } else {
                contentPath = std::format("{}/{:08x}.app", contentDir, cid);
            }

            FSStat cStat;
            if (FSAGetStat(fsaClient, contentPath.c_str(), &cStat) != FS_ERROR_OK) {
                issue.reasons.push_back(std::format("Missing content: {:08x}.app", cid));
                contentIssueFound = true;
            } else {
                if (cStat.owner != 0 || cStat.group != 0 || cStat.mode != STOCK_MODE_SYSTEM_FILE) {
                    issue.reasons.push_back(std::format("Content permissions incorrect: {:08x}.app", cid));
                    report.permissionErrorsCount++;
                }

                if (cStat.size != csize) {
                    issue.reasons.push_back(std::format("Content size mismatch: {:08x}.app", cid));
                    contentIssueFound = true;
                } else if (!FSACheckFileSha1(fsaClient, contentPath, expHash, csize)) {
                    issue.reasons.push_back(std::format("Content modified / corrupted: {:08x}.app", cid));
                    contentIssueFound = true;
                }
            }
        }

        if (contentIssueFound) {
            report.modifiedTitlesCount++;
        }

        free(tmdBuf);

        if (!issue.reasons.empty()) {
            report.issues.push_back(issue);
        }
    }

    // 5. Detect any foreign region system channel variants on disk
    LogProgress("Checking for foreign region titles...");
    {
        auto oldTitles = GetInstalledOldRegionTitles(report.targetRegionStr);
        for (const auto& oldT : oldTitles) {
            SystemScanIssue foreignIssue;
            foreignIssue.titleName = oldT.name;
            foreignIssue.titleId = oldT.titleId;
            foreignIssue.isForeignTitle = true;
            foreignIssue.reasons.push_back(std::format("Foreign region title installed ({} != {})",
                                                       oldT.region, report.targetRegionStr));
            report.issues.push_back(foreignIssue);
        }
    }

    if (certSysBuf) {
        free(certSysBuf);
    }

    return report;
}

bool SCAN_RestoreSelectedIssues(const std::vector<SystemScanIssue>& selectedIssues, int32_t targetRegionCode) {
    if (selectedIssues.empty()) return true;

    std::string targetRegionStr = Setting_GetRegionName(targetRegionCode);

    int total = (int)selectedIssues.size();
    int successCount = 0;
    int failCount = 0;

    WUPI_resetScreen();
    WUPI_Log("=========================================");
    WUPI_Log("      System Restoration in Progress     ");
    WUPI_Log("=========================================\n");

    for (int i = 0; i < total; i++) {
        if (!State::AppRunning()) break;
        const auto& issue = selectedIssues[i];

        WUPI_Log("--- Restoring %s (%d/%d) ---", issue.titleName.c_str(), i + 1, total);

        bool itemOk = false;

        if (issue.isSettingTxt) {
            WUPI_Log("Regenerating setting.txt for %s...\n", targetRegionStr.c_str());
            VwiiSettings newSettings;
            if (!Setting_RegenerateFromMCP(newSettings)) {
                WUPI_Log("Warning: Could not read MCP SysProd, using defaults.\n");
            }
            Setting_ApplyPreset(newSettings, targetRegionStr);
            itemOk = Setting_Write(newSettings);
            if (itemOk) {
                WUPI_Log("setting.txt restored successfully.\n");
            } else {
                WUPI_Log("Error: Failed to write setting.txt.\n");
            }
        } else if (issue.isCertSys) {
            WUPI_Log("Rebuilding /sys/cert.sys from retail certificates...\n");
            itemOk = CERT_ImportCerts(fsaClient, nullptr, 0);
            if (!itemOk) {
                WUPI_Log("Warning: cert.sys will be reconstructed during title installation.\n");
                itemOk = true;
            }
        } else if (issue.isUidSys) {
            WUPI_Log("Repairing /sys/uid.sys...\n");
            EnsureFSADir(fsaClient, "/vol/slccmpt01/sys");
            uint32_t sysMenuUid = UID_GetOrCreate(fsaClient, 0x0000000100000002ULL);
            itemOk = (sysMenuUid == 4096);
            if (itemOk) {
                WUPI_Log("uid.sys initialized successfully.\n");
            }
        } else if (issue.isForeignTitle) {
            WUPI_Log("Removing foreign region title %016llx...\n", (unsigned long long)issue.titleId);
            itemOk = CINS_UninstallTitle(issue.titleId);
            if (itemOk) {
                WUPI_Log("Foreign title removed successfully.\n");
            }
        } else if (issue.nusTitle != nullptr) {
            itemOk = NUS_InstallSystemTitle(issue.nusTitle, targetRegionCode);
            if (itemOk) {
                WUPI_Log("Installation complete!\n");
            }
        } else {
            WUPI_Log("No automatic restore handler for %s.\n", issue.titleName.c_str());
            itemOk = false;
        }

        if (itemOk) {
            successCount++;
        } else {
            failCount++;
            WUPI_putstr("\nOperation failed.\nPress A to continue, B to abort.\n");
            if (!WaitPrompt()) break;
        }
        sleep(1);
    }

    // Ensure stock root directories and permissions are intact
    FSA_InitStockRootDirs(fsaClient);

    WUPI_resetScreen();
    WUPI_Log("=========================================");
    WUPI_Log("          RESTORATION SUMMARY            ");
    WUPI_Log("=========================================\n");
    WUPI_Log("Target Region: %s\n", targetRegionStr.c_str());
    WUPI_Log("Total Items Selected: %d\n", total);
    WUPI_Log("Successfully Restored: %d\n", successCount);
    WUPI_Log("Failed / Skipped: %d\n", failCount);
    WUPI_Log("\nRestoration process finished!");
    WUPI_waitButton();

    return (failCount == 0);
}

void WUPI_ScanAndRestoreMenu() {
    WUPI_resetScreen();
    WUPI_Log("=========================================");
    WUPI_Log("      System Scan & Restore Wizard       ");
    WUPI_Log("=========================================\n");
    WUPI_Log("Analyzing system environment...\n");

    bool isAmbiguous = false;
    int32_t targetRegion = SCAN_DetermineTargetRegion(isAmbiguous);

    // Get console native region from MCP SysProd for recommendation
    if (isAmbiguous || targetRegion < 0 || targetRegion > 2) {
        std::string chosen = Setting_PromptRegionSelection("=== Target Region Ambiguity Detected ===");
        if (chosen.empty()) {
            return;
        }
        targetRegion = Setting_GetRegionIndex(chosen);
    }

    // Run Full System Scan with live on-screen progress
    WUPI_resetScreen();
    WUPI_Log("=========================================");
    WUPI_Log("   Scanning System Environment (%s)   ", Setting_GetRegionName(targetRegion).c_str());
    WUPI_Log("=========================================\n");

    SystemScanReport report = SCAN_RunFullSystemScan(targetRegion, [](const std::string& msg) {
        WUPI_Log_Overwrite("%s\n", msg.c_str());
    });

    if (!State::AppRunning()) return;

    if (report.issues.empty()) {
        WUPI_resetScreen();
        WUPI_Log("=========================================");
        WUPI_Log("           SCAN REPORT: HEALTHY          ");
        WUPI_Log("=========================================\n");
        WUPI_Log("Target Region: %s (Verified)\n", report.targetRegionStr.c_str());
        WUPI_Log("System Titles: 38/38 Verified & Authentic\n");
        WUPI_Log("TMD Signatures: All Nintendo-Signed\n");
        WUPI_Log("Content SHA-1: All Hashes Matched\n");
        WUPI_Log("Permissions: All Stock SFFS Permissions\n");
        WUPI_Log("setting.txt: Valid & Authentic\n");
        WUPI_Log("cert.sys & uid.sys: Intact\n\n");
        WUPI_Log("No issues detected! Your vWii system is clean.\n");
        WUPI_waitButton();
        return;
    }

    // Build multi-select options
    std::vector<std::string> options;
    for (const auto& issue : report.issues) {
        options.push_back(issue.FormatOption());
    }

    std::vector<std::string> header = {
        "=== System Scan: Issues Detected ===",
        std::format("Target Region: {} | Total Deviations: {}", report.targetRegionStr, (int)report.issues.size()),
        "Select items to restore, then press (+) to confirm:"
    };

    std::vector<int> selectedIndices = ShowMultiSelectMenu(header, options, true);
    if (selectedIndices.empty()) {
        return;
    }

    std::vector<SystemScanIssue> selectedIssues;
    for (int idx : selectedIndices) {
        if (idx >= 0 && idx < (int)report.issues.size()) {
            selectedIssues.push_back(report.issues[idx]);
        }
    }

    SCAN_RestoreSelectedIssues(selectedIssues, targetRegion);
}
