#include "system_scanner.h"
#include "settingtxt_manager.h"
#include "region_changer.h"
#include "FSAUtils.h"
#include "cert_sys.h"
#include "uid_sys.h"
#include "downloader.h"
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
    if (!tmdData || tmdSize < sizeof(TitleTmd) || certs.empty()) return false;

    uint32_t sigType = Read32BE(tmdData);
    if (sigType != CERT_SIG_RSA2048) {
        return false;
    }

    uint32_t payloadOffset = GetPayloadOffset(tmdData);
    if (tmdSize <= payloadOffset) return false;

    const auto* tmd = reinterpret_cast<const TitleTmd*>(tmdData);
    char issuerStr[sizeof(tmd->issuer) + 1] = {0};
    memcpy(issuerStr, tmd->issuer, sizeof(tmd->issuer));
    std::string issuer(issuerStr);

    std::string signerCertName = issuer;
    size_t lastDash = issuer.rfind('-');
    if (lastDash != std::string::npos) {
        signerCertName = issuer.substr(lastDash + 1);
    }

    const ParsedCert* matchingCert = nullptr;
    for (const auto& c : certs) {
        if (c.name == signerCertName && c.size >= sizeof(CertRsa2048) && c.sigType == CERT_SIG_RSA2048) {
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

    const auto* cert = reinterpret_cast<const CertRsa2048*>(matchingCert->data.data());
    uint8_t* sig = const_cast<uint8_t*>(tmd->signature);
    uint8_t* key = const_cast<uint8_t*>(cert->modulus);

    return (check_rsa(hash, sig, key, sizeof(cert->modulus)) == 0);
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
    if (ReadFileToBuffer("/vol/slccmpt01/title/00000001/00000002/content/title.tmd", &sysMenuTmd, &sysMenuTmdSize) && sysMenuTmdSize >= sizeof(TitleTmd)) {
        const auto* tmd = reinterpret_cast<const TitleTmd*>(sysMenuTmd);
        uint16_t version = FromBE16(tmd->titleVersion);
        int32_t reg = version & 3;
        if (reg >= 0 && reg <= 2) {
            detectedTitleRegions.push_back(reg);
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

static std::string format_permission_error(FSStat stat, std::string_view path, const ResolvedPathRule& rule) {
    return std::format("Perms {}/{}/{:03x} incorrect on {} (expected {}/{}/{:03x})",
                       (uint32_t)stat.owner, (uint32_t)stat.group,
                       (uint32_t)(stat.mode & 0x777), VwiiCleanPath(path),
                       rule.uid, rule.gid, (uint32_t)rule.mode);
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
            ResolvedPathRule expRule;
            if (!PathRules_CheckPermissions(fsaClient, VWII_SETTING_TXT_PATH, stat, &expRule)) {
                settingIssue.reasons.push_back(format_permission_error(stat, settingIssue.titleName, expRule));
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
    {
        SystemScanIssue certIssue;
        certIssue.titleName = "/sys/cert.sys";
        certIssue.isCertSys = true;

        if (!CERT_VerifyIntegrity(fsaClient, systemCerts, certIssue.reasons)) {
            report.certSysDamaged = true;
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
        if (FSAGetStat(fsaClient, VWII_UID_SYS_PATH, &stat) != FS_ERROR_OK || stat.size < 12 || (stat.size % 12) != 0) {
            uidIssue.reasons.push_back("Missing or corrupted");
            report.uidSysDamaged = true;
        } else {
            ResolvedPathRule expRule;
            if (!PathRules_CheckPermissions(fsaClient, VWII_UID_SYS_PATH, stat, &expRule)) {
                uidIssue.reasons.push_back(format_permission_error(stat, uidIssue.titleName, expRule));
                report.uidSysDamaged = true;
            } else {
                // Check if entry 0 is System Menu (0000000100000002 -> 4096)
                FSAFileHandle fd = 0;
                if (FSAOpenFileEx(fsaClient, VWII_UID_SYS_PATH, "rb", (FSMode)0, FS_OPEN_FLAG_NONE, 0, &fd) == FS_ERROR_OK) {
                    RawUidEntry* entry0 = (RawUidEntry*)memalign(0x40, 0x40);
                    if (entry0) {
                        int readRes = FSAReadFile(fsaClient, entry0, sizeof(RawUidEntry), 1, fd, 0);
                        if (readRes <= 0 || entry0->titleId != VWII_TITLE_ID_SYSTEM_MENU || entry0->uid != VWII_UID_SYSTEM_MENU) {
                            uidIssue.reasons.push_back("Corrupted System Menu entry");
                            report.uidSysDamaged = true;
                        }
                        free(entry0);
                    }
                    FSACloseFile(fsaClient, fd);
                }
            }
        }

        if (!uidIssue.reasons.empty()) {
            report.issues.push_back(uidIssue);
        }
    }

    // 4. Audit root directories and shared permissions
    LogProgress("Auditing root system directories...");
    {
        SystemScanIssue dirIssue;
        dirIssue.titleName = "Root System Directories";
        dirIssue.isStockDirs = true;

        auto rootDirs = PathRules_GetStockRootDirs();
        for (const auto& d : rootDirs) {
            std::string fullPath = VwiiFsaPath(d.pattern);
            FSStat stat;
            if (FSAGetStat(fsaClient, fullPath.c_str(), &stat) != FS_ERROR_OK) {
                dirIssue.reasons.push_back(std::format("Missing: {}", d.pattern));
                report.permissionErrorsCount++;
            } else if (!PathRules_CheckPermissions(fsaClient, fullPath, stat)) {
                dirIssue.reasons.push_back(format_permission_error(stat, d.pattern, d));
                report.permissionErrorsCount++;
            }
        }

        if (!dirIssue.reasons.empty()) {
            report.issues.push_back(dirIssue);
        }
    }

    // 5. Audit all 38 official system titles for target region
    for (size_t i = 0; i < g_numNusTitles; i++) {
        if (!State::AppRunning()) break;
        const auto& t = g_nusTitles[i];
        report.totalTitlesScanned++;

        uint64_t titleId = NUS_ResolveTitleId(&t, targetRegionCode);
        uint32_t idHi = (uint32_t)(titleId >> 32);
        uint32_t idLo = (uint32_t)(titleId & 0xFFFFFFFF);

        std::string relTitleDir = std::format("/title/{:08x}/{:08x}", idHi, idLo);
        std::string relContentDir = relTitleDir + "/content";
        std::string relDataDir = relTitleDir + "/data";
        std::string relTmdPath = relContentDir + "/title.tmd";
        std::string relTikPath = std::format("/ticket/{:08x}/{:08x}.tik", idHi, idLo);

        std::string titleDir = VwiiFsaPath(relTitleDir);
        std::string contentDir = VwiiFsaPath(relContentDir);
        std::string dataDir = VwiiFsaPath(relDataDir);
        std::string tmdPath = VwiiFsaPath(relTmdPath);
        std::string tikPath = VwiiFsaPath(relTikPath);

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
        ResolvedPathRule expTitleDir;
        if (!PathRules_CheckPermissions(fsaClient, titleDir, titleStat, &expTitleDir)) {
            issue.reasons.push_back(format_permission_error(titleStat, relTitleDir, expTitleDir));
            report.permissionErrorsCount++;
        }

        FSStat contentStat;
        ResolvedPathRule expContentDir;
        if (FSAGetStat(fsaClient, contentDir.c_str(), &contentStat) != FS_ERROR_OK ||
            !PathRules_CheckPermissions(fsaClient, contentDir, contentStat, &expContentDir)) {
            issue.reasons.push_back(format_permission_error(contentStat, relContentDir, expContentDir));
            report.permissionErrorsCount++;
        }

        FSStat tikStat;
        ResolvedPathRule expTik;
        if (FSAGetStat(fsaClient, tikPath.c_str(), &tikStat) != FS_ERROR_OK) {
            issue.reasons.push_back("Missing ticket (.tik)");
            report.modifiedTitlesCount++;
        } else if (!PathRules_CheckPermissions(fsaClient, tikPath, tikStat, &expTik)) {
            issue.reasons.push_back(format_permission_error(tikStat, relTikPath, expTik));
            report.permissionErrorsCount++;
        }

        // Read and check TMD
        uint8_t* tmdBuf = nullptr;
        uint32_t tmdSize = 0;
        if (!ReadFileToBuffer(tmdPath, &tmdBuf, &tmdSize) || tmdSize < sizeof(TitleTmd)) {
            issue.reasons.push_back("Missing or unreadable TMD");
            report.modifiedTitlesCount++;
            if (tmdBuf) free(tmdBuf);
            report.issues.push_back(issue);
            continue;
        }

        FSStat tmdStat;
        ResolvedPathRule expTmd;
        if (FSAGetStat(fsaClient, tmdPath.c_str(), &tmdStat) == FS_ERROR_OK) {
            if (!PathRules_CheckPermissions(fsaClient, tmdPath, tmdStat, &expTmd)) {
                issue.reasons.push_back(format_permission_error(tmdStat, relTmdPath, expTmd));
                report.permissionErrorsCount++;
            }
        }

        // Verify Nintendo RSA signature on TMD
        bool tmdIssueFound = false;
        if (!VerifyTmdSignature(tmdBuf, tmdSize, systemCerts)) {
            issue.reasons.push_back("TMD not signed by Nintendo (Modified / Trucha)");
            report.modifiedTitlesCount++;
            tmdIssueFound = true;
        }

        const auto* tmd = reinterpret_cast<const TitleTmd*>(tmdBuf);
        uint16_t numContents = FromBE16(tmd->numContents);
        uint16_t titleVersion = FromBE16(tmd->titleVersion);
        uint16_t groupId = FromBE16(tmd->groupId);
        issue.groupId = groupId;

        // Check region-specific System Menu version
        if (t.id == VWII_TITLE_ID_SYSTEM_MENU) {
            if ((titleVersion & 3) != targetRegionCode) {
                issue.reasons.push_back(std::format("Wrong region System Menu (v{}, expected {})",
                                                    titleVersion, report.targetRegionStr));
                report.modifiedTitlesCount++;
                tmdIssueFound = true;
            }
        }

        // Check /data directory permissions
        FSStat dataStat;
        if (FSAGetStat(fsaClient, dataDir.c_str(), &dataStat) == FS_ERROR_OK) {
            ResolvedPathRule expData;
            if (!PathRules_CheckPermissions(fsaClient, dataDir, dataStat, &expData, issue.groupId)) {
                issue.reasons.push_back(format_permission_error(dataStat, relDataDir, expData));
                report.permissionErrorsCount++;
            }
        }

        // Check all content records in TMD
        bool contentIssueFound = false;
        for (uint16_t c = 0; c < numContents; c++) {
            if (tmdSize < sizeof(TitleTmd) + ((c + 1) * sizeof(TitleContentRecord))) break;

            const TitleContentRecord& rec = tmd->contents[c];
            uint32_t cid = FromBE32(rec.contentId);
            uint16_t ctype = FromBE16(rec.type);
            uint64_t csize = FromBE64(rec.size);
            const uint8_t* expHash = rec.hash.data();

            std::string relContentPath;
            if ((ctype & 0x8000) != 0) {
                // Shared content
                int32_t sharedIdx = FindSharedContentIndex(expHash);
                if (sharedIdx >= 0) {
                    relContentPath = std::format("/shared1/{:08x}.app", sharedIdx);
                } else {
                    issue.reasons.push_back(std::format("Shared content missing: {:08x}", cid));
                    contentIssueFound = true;
                    continue;
                }
            } else {
                relContentPath = std::format("{}/{:08x}.app", relContentDir, cid);
            }
            std::string contentPath = VwiiFsaPath(relContentPath);

            FSStat cStat;
            if (FSAGetStat(fsaClient, contentPath.c_str(), &cStat) != FS_ERROR_OK) {
                issue.reasons.push_back(std::format("Missing content: {:08x}.app", cid));
                contentIssueFound = true;
            } else {
                ResolvedPathRule expContent;
                if (!PathRules_CheckPermissions(fsaClient, contentPath, cStat, &expContent)) {
                    issue.reasons.push_back(format_permission_error(cStat, relContentPath, expContent));
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
            if (!contentIssueFound && !tmdIssueFound) {
                issue.isPermissionOnly = true;
            }
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

    return report;
}

static bool RepairTitlePermissions(FSAClientHandle fsa, const SystemScanIssue& issue, int32_t targetRegionCode) {
    uint32_t idHi = (uint32_t)(issue.titleId >> 32);
    uint32_t idLo = (uint32_t)(issue.titleId & 0xFFFFFFFF);
    std::string titlePath = std::format("/vol/slccmpt01/title/{:08x}/{:08x}", idHi, idLo);
    std::string dataDir = titlePath + "/data";
    std::string contentDir = titlePath + "/content";
    std::string tmdPath = contentDir + "/title.tmd";

    // 1. Ensure title category and title directory exist
    SlcEnsureDir(fsa, titlePath);
    SlcEnsureDir(fsa, contentDir);

    // 2. Fix TMD and content files permissions
    ResolvedPathRule tmdRule = PathRules_Resolve(tmdPath);
    FSAChangeMode(fsa, tmdPath.c_str(), tmdRule.mode);

    FSADirectoryHandle cDir;
    if (FSAOpenDir(fsa, contentDir.c_str(), &cDir) == FS_ERROR_OK) {
        FSADirectoryEntry* entry = (FSADirectoryEntry*)memalign(0x40, sizeof(FSADirectoryEntry));
        if (entry) {
            while (FSAReadDir(fsa, cDir, entry) == FS_ERROR_OK) {
                if (strcmp(entry->name, ".") == 0 || strcmp(entry->name, "..") == 0) continue;
                std::string cFilePath = contentDir + "/" + entry->name;
                ResolvedPathRule cRule = PathRules_Resolve(cFilePath);
                FSAChangeMode(fsa, cFilePath.c_str(), cRule.mode);
            }
            free(entry);
        }
        FSACloseDir(fsa, cDir);
    }

    // 3. Fix /data directory ownership & permissions
    ResolvedPathRule dataRule = PathRules_Resolve(fsa, dataDir, issue.groupId);

    FSStat dstat;
    if (FSAGetStat(fsa, dataDir.c_str(), &dstat) != FS_ERROR_OK) {
        // Data directory doesn't exist, create it with correct ownership & mode
        FSError res = SlcMakeDir(fsa, dataDir, issue.groupId);
        if (res != FS_ERROR_OK) {
            WUPI_Log("Failed to create data dir: %d\n", res);
            return false;
        }
    } else {
        if (!FSA_IsPermissionAcceptable(dstat, dataRule.mode, dataRule.uid, dataRule.gid)) {
            // Ownership is wrong. Check if directory contains files
            bool hasFiles = false;
            FSADirectoryHandle dDir;
            if (FSAOpenDir(fsa, dataDir.c_str(), &dDir) == FS_ERROR_OK) {
                FSADirectoryEntry* entry = (FSADirectoryEntry*)memalign(0x40, sizeof(FSADirectoryEntry));
                if (entry) {
                    while (FSAReadDir(fsa, dDir, entry) == FS_ERROR_OK) {
                        if (strcmp(entry->name, ".") != 0 && strcmp(entry->name, "..") != 0) {
                            hasFiles = true;
                            break;
                        }
                    }
                    free(entry);
                }
                FSACloseDir(fsa, dDir);
            }

            if (hasFiles && issue.titleId != VWII_TITLE_ID_SYSTEM_MENU) {
                std::vector<std::string> warnHeader = {
                    "=== WARNING: DATA DIRECTORY OWNERSHIP ===",
                    "Title: " + issue.titleName,
                    "",
                    "Data directory ownership is incorrect (UID/GID mismatch).",
                    "To fix ownership, the directory must be recreated while empty.",
                    "",
                    "WARNING: This will clear /data (save data) for this title!",
                    "Are you sure you want to proceed?"
                };
                std::vector<std::string> warnOptions = {
                    "No, keep current save data (Skip ownership fix)",
                    "Yes, clear /data and fix ownership"
                };

                if (ShowMenu(warnHeader, warnOptions) != 1) {
                    WUPI_Log("Skipped data directory ownership recreation.\n");
                    return true;
                }
            }

            // Recreate data directory with correct ownership
            FSARemoveTree(fsa, dataDir);
            FSError res = SlcMakeDir(fsa, dataDir, issue.groupId);
            if (res != FS_ERROR_OK) {
                WUPI_Log("Failed to recreate data dir: %d\n", res);
                return false;
            }
        }
    }

    // 4. If System Menu (0000000100000002), ensure setting.txt exists and has correct mode
    if (issue.titleId == VWII_TITLE_ID_SYSTEM_MENU) {
        FSStat sstat;
        if (FSAGetStat(fsa, VWII_SETTING_TXT_PATH, &sstat) == FS_ERROR_OK) {
            ResolvedPathRule settingRule = PathRules_Resolve(VWII_SETTING_TXT_PATH);
            FSAChangeMode(fsa, VWII_SETTING_TXT_PATH, settingRule.mode);
        } else {
            WUPI_Log("Regenerating missing setting.txt for System Menu...\n");
            VwiiSettings newSettings;
            if (!Setting_RegenerateFromMCP(newSettings)) {
                WUPI_Log("Warning: Could not read MCP SysProd, using defaults.\n");
            }
            Setting_ApplyPreset(newSettings, Setting_GetRegionName(targetRegionCode));
            Setting_Write(newSettings);
        }
    }

    return true;
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
            WUPI_Log("Restoring /sys/cert.sys...\n");
            itemOk = CERT_RestoreOrRegenerate(fsaClient);
            if (itemOk) {
                WUPI_Log("/sys/cert.sys restored successfully.\n");
            } else {
                WUPI_Log("Warning: Failed to restore /sys/cert.sys.\n");
            }
        } else if (issue.isUidSys) {
            WUPI_Log("Repairing /sys/uid.sys...\n");
            SlcEnsureDir(fsaClient, "/vol/slccmpt01/sys");
            size_t recovered = 0;
            itemOk = UID_Reconstruct(fsaClient, &recovered);
            if (itemOk) {
                WUPI_Log("uid.sys reconstructed successfully (%zu titles registered).\n", recovered);
            } else {
                WUPI_Log("Error: Failed to reconstruct uid.sys.\n");
            }
        } else if (issue.isStockDirs) {
            WUPI_Log("Repairing root system directories & permissions...\n");
            itemOk = FSA_InitStockRootDirs(fsaClient);
            if (itemOk) {
                WUPI_Log("Root directories repaired successfully.\n");
            }
        } else if (issue.isForeignTitle) {
            WUPI_Log("Removing foreign region title %016llx...\n", (unsigned long long)issue.titleId);
            itemOk = CINS_UninstallTitle(issue.titleId);
            if (itemOk) {
                WUPI_Log("Foreign title removed successfully.\n");
            }
        } else if (issue.isPermissionOnly) {
            WUPI_Log("Repairing permissions for %s in-place...\n", issue.titleName.c_str());
            itemOk = RepairTitlePermissions(fsaClient, issue, targetRegionCode);
            if (itemOk) {
                WUPI_Log("Permissions repaired successfully.\n");
            } else {
                WUPI_Log("Warning: Could not repair all permissions.\n");
            }
        } else if (issue.nusTitle != nullptr) {
            DownloadResult res = NUS_InstallSystemTitle(issue.nusTitle, targetRegionCode);
            if (res == DownloadResult::CANCELLED) {
                failCount++;
                break;
            }
            itemOk = (res == DownloadResult::SUCCESS);
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
            if (!State::AppRunning()) break;
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

    // Upfront check: verify /sys/cert.sys integrity before scanning system titles
    std::vector<ParsedCert> probeCerts;
    std::vector<std::string> certReasons;
    if (!CERT_VerifyIntegrity(fsaClient, probeCerts, certReasons)) {
        WUPI_resetScreen();
        std::vector<std::string> certHeader = {
            "=========================================",
            "       /sys/cert.sys Issue Detected      ",
            "=========================================",
            "/sys/cert.sys is missing or invalid on SLCCMPT!",
            "It is required to verify signatures of all system titles.",
            "",
            "Reason: " + (certReasons.empty() ? "Damaged / Missing" : certReasons[0]),
            "",
            "Would you like to download & regenerate cert.sys from NUS?"
        };
        std::vector<std::string> certOptions = {
            "Yes, download & regenerate cert.sys from NUS (Recommended)",
            "No, proceed with scan anyway"
        };
        int choice = ShowMenu(certHeader, certOptions);
        if (choice == 0) {
            WUPI_resetScreen();
            WUPI_Log("=========================================");
            WUPI_Log("     Restoring /sys/cert.sys             ");
            WUPI_Log("=========================================\n");
            if (CERT_RestoreOrRegenerate(fsaClient)) {
                WUPI_Log("\n/sys/cert.sys restored successfully!\n");
            } else {
                WUPI_Log("\nFailed to restore /sys/cert.sys.\n");
            }
            sleep(2);
        }
    }

    // Run Full System Scan with live on-screen progress
    WUPI_resetScreen();
    WUPI_Log("=========================================");
    WUPI_Log("   Scanning vWii Environment (%s)   ", Setting_GetRegionName(targetRegion).c_str());
    WUPI_Log("=========================================");
    WUPI_Log("Initializing scan...\n");

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
        WUPI_Log("Permissions: OK\n");
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
