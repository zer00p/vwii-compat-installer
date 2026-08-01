/*
 * drive_inquiry_patcher.cpp
 *
 * Dedicated patcher for Drive Inquiry on IOS56, IOS57, IOS58.
 * Original credits go to garyodernichts for the No Disc Drive patch.
 */

#include "drive_inquiry_patcher.h"
#include "ios_common.h"
#include "installer.h"
#include "MenuUtils.h"
#include "EndianUtils.h"
#include "log.h"
#include "wad.h"
#include "downloader.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <vector>
#include <string>

extern FSAClientHandle fsaClient;

static const uint32_t TARGET_IOS[] = {31, 33, 35, 36, 37, 53, 55, 56, 57, 58};
static const int NUM_TARGET_IOS = sizeof(TARGET_IOS) / sizeof(TARGET_IOS[0]);



int HandleDriveInquiryPatch(uint8_t *buf, uint32_t size, bool revert) {
    static const uint8_t orig[] = { 0x49, 0x4C, 0x23, 0x90, 0x68, 0x0A };
    static const uint8_t pat[]  = { 0x20, 0x00, 0xE5, 0x38, 0x68, 0x0A };
    return ReplacePattern(buf, size, orig, pat, sizeof(orig), revert);
}

int HandleDriveInquiryPatchIOS36(uint8_t *buf, uint32_t size, bool revert) {
    static const uint8_t orig[] = { 0x49, 0xB7, 0x23, 0x90, 0x68, 0x0A };
    static const uint8_t pat[]  = { 0x20, 0x00, 0xE6, 0x1A, 0x68, 0x0A };
    return ReplacePattern(buf, size, orig, pat, sizeof(orig), revert);
}

static uint32_t ApplyDrivePatch(uint32_t ios_ver, MemIOS* ios) {
    uint32_t totalPatches = 0;
    for (uint32_t i = 0; i < ios->numContents; i++) {
        if (!ios->contents[i].data || ios->contents[i].size == 0) continue;

        uint32_t count = 0;
        if (ios_ver == 31 || ios_ver == 33 || ios_ver == 35 || ios_ver == 36) {
            count = HandleDriveInquiryPatchIOS36(ios->contents[i].data, ios->contents[i].size, false);
        } else {
            count = HandleDriveInquiryPatch(ios->contents[i].data, ios->contents[i].size, false);
        }

        if (count > 0) {
            totalPatches += count;
            uint32_t cid = ios->contents[i].cid;
            TitleContentRecord* records = ios->tmd->contents;
            for (uint32_t k = 0; k < ios->numContents; k++) {
                if (FromBE32(records[k].contentId) == cid) {
                    uint16_t type = FromBE16(records[k].type);
                    if (type & 0x8000) {
                        records[k].type = ToBE16(type & ~0x8000);
                    }
                    break;
                }
            }
        }
    }
    return totalPatches;
}

static bool PatchAndInstallIOS(uint32_t ios_ver) {
    Patcher_Log("Reading base IOS" + std::to_string(ios_ver) + " from slccmpt...");
    auto ios = ReadBaseIOS(ios_ver);
    if (!ios) {
        Patcher_Log("Error: Failed to read base IOS" + std::to_string(ios_ver) + ".");
        return false;
    }

    bool isOriginal = IsOriginalNintendoSignature(ios->tmd->signature, sizeof(ios->tmd->signature));

    if (isOriginal) {
        FSAFileHandle testFd;
        std::string tmdBackup = GetTmdBackupPath(ios_ver);
        std::string tikBackup = GetTikBackupPath(ios_ver);
        if (FSAOpenFileEx(fsaClient, tmdBackup.c_str(), "r", (FSMode)0, FS_OPEN_FLAG_NONE, 0, &testFd) == FS_ERROR_OK) {
            FSACloseFile(fsaClient, testFd);
        } else {
            WriteBufferToFile(tmdBackup, (uint8_t*)ios->tmd, ios->tmdSize);
            WriteBufferToFile(tikBackup, (uint8_t*)ios->ticket, ios->ticketSize);
        }
    } else {
        Patcher_Log("Note: Installed IOS" + std::to_string(ios_ver) + " is already patched.");
        Patcher_Log("Skipping TMD/Ticket backup.");
    }

    Patcher_Log("Applying Drive Inquiry patch to IOS" + std::to_string(ios_ver) + "...");
    uint32_t totalPatches = ApplyDrivePatch(ios_ver, ios.get());

    if (totalPatches == 0) {
        Patcher_Log("Warning: Could not find patch pattern in IOS" + std::to_string(ios_ver) + ". Skipping.");
        return false;
    }

    Patcher_Log("Applied " + std::to_string(totalPatches) + " patch(es).");
    Patcher_Log("Writing patched IOS" + std::to_string(ios_ver) + "...");

    bool ok = WritePatchedIOS(ios_ver, *ios);
    if (ok) {
        Patcher_Log("Successfully patched and installed IOS" + std::to_string(ios_ver) + "!");
    } else {
        Patcher_Log("Error: Failed to write patched IOS" + std::to_string(ios_ver) + ".");
    }
    return ok;
}

void InstallDrivePatchAll() {
    WUPI_resetScreen();
    std::vector<std::string> header = {
        "Apply Drive Inquiry Patches",
        "------------------------------------",
        "This applies Garys 'No Disc Drive' patch to the selected IOSes.",
        "It modifies the DIP module to ignore missing or bad drives.",
        "",
        "Select which IOSes to patch:"
    };

    std::vector<std::string> options;
    for (int i = 0; i < NUM_TARGET_IOS; i++) {
        options.push_back("IOS" + std::to_string(TARGET_IOS[i]));
    }

    std::vector<int> selected_items = ShowMultiSelectMenu(header, options, true);
    if (selected_items.empty()) {
        WUPI_resetScreen();
        Patcher_Log("Drive patch installation cancelled.");
        sleep(2);
        return;
    }

    WUPI_resetScreen();

    int successCount = 0;
    for (int idx : selected_items) {
        Patcher_Log("=========================================");
        if (PatchAndInstallIOS(TARGET_IOS[idx])) {
            successCount++;
        }
        Patcher_Log("");
    }

    Patcher_Log("Completed. Successfully patched " + std::to_string(successCount) + "/" + std::to_string(selected_items.size()) + " IOSes.");
    Patcher_Log("");
    Patcher_Log("Press A to return.");
    WaitPrompt();
}




void UndoDrivePatchAll() {
    WUPI_resetScreen();

    std::vector<std::string> header = {
        "Undo Drive Inquiry Patches",
        "------------------------------------",
        "Select which IOSes to unpatch:"
    };

    std::vector<std::string> options;
    for (int i = 0; i < NUM_TARGET_IOS; i++) {
        options.push_back("IOS" + std::to_string(TARGET_IOS[i]));
    }

    std::vector<int> selected_items = ShowMultiSelectMenu(header, options, true);
    if (selected_items.empty()) {
        WUPI_resetScreen();
        Patcher_Log("IOS unpatching cancelled.");
        Patcher_Log("");
        Patcher_Log("Press A to return.");
        WaitPrompt();
        return;
    }

    // Now ask HOW to unpatch
    WUPI_resetScreen();
    std::vector<std::string> methodHeader = {
        "Undo Drive Inquiry Patches",
        "------------------------------------",
        "Select how you want to undo the patches."
    };

    // Check if we have backups for all selected
    bool hasAllBackups = true;
    for (int idx : selected_items) {
        FSAFileHandle testFd;
        std::string tmdBackup = GetTmdBackupPath(TARGET_IOS[idx]);
        if (FSAOpenFileEx(fsaClient, tmdBackup.c_str(), "r", (FSMode)0, FS_OPEN_FLAG_NONE, 0, &testFd) == FS_ERROR_OK) {
            FSACloseFile(fsaClient, testFd);
        } else {
            hasAllBackups = false;
        }
    }

    std::vector<std::string> methodOptions;
    if (hasAllBackups) {
        methodOptions.push_back("Restore from local backups (In-Place)");
    }
    methodOptions.push_back("Reinstall original IOSes from NUS");
    methodOptions.push_back("Cancel");

    int choice = ShowMenu(methodHeader, methodOptions);
    if (choice == (int)methodOptions.size() - 1) {
        WUPI_resetScreen();
        Patcher_Log("IOS unpatching cancelled.");
        Patcher_Log("");
        Patcher_Log("Press A to return.");
        WaitPrompt();
        return;
    }

    int action = (hasAllBackups && choice == 0) ? 1 : 2;

    WUPI_resetScreen();

    int successCount = 0;

    for (int idx : selected_items) {
        uint32_t ios_ver = TARGET_IOS[idx];
        Patcher_Log("=========================================");
        Patcher_Log("Restoring IOS" + std::to_string(ios_ver) + "...");

        if (action == 2) {
            if (RestoreIOSFromNUS(ios_ver)) successCount++;
        } else if (action == 1) {
            auto ios = ReadBaseIOS(ios_ver);
            if (!ios) {
                Patcher_Log("Error: Failed to read base IOS" + std::to_string(ios_ver));
                continue;
            }

            uint8_t* origTmdBuf = nullptr;
            uint32_t origTmdSize = 0;
            if (!ReadFileToBuffer(GetTmdBackupPath(ios_ver), &origTmdBuf, &origTmdSize)) {
                Patcher_Log("Error: Failed to read tmd.bak for IOS" + std::to_string(ios_ver));
                continue;
            }

            uint8_t* origTikBuf = nullptr;
            uint32_t origTikSize = 0;
            if (!ReadFileToBuffer(GetTikBackupPath(ios_ver), &origTikBuf, &origTikSize)) {
                Patcher_Log("Error: Failed to read tik.bak for IOS" + std::to_string(ios_ver));
                free(origTmdBuf);
                continue;
            }

            for (uint32_t c = 0; c < ios->numContents; c++) {
                if (!ios->contents[c].data || ios->contents[c].size == 0) continue;
                if (ios_ver == 31 || ios_ver == 33 || ios_ver == 35 || ios_ver == 36) {
                    HandleDriveInquiryPatchIOS36(ios->contents[c].data, ios->contents[c].size, true);
                } else {
                    HandleDriveInquiryPatch(ios->contents[c].data, ios->contents[c].size, true);
                }
            }

            LoadPristineSharedContents(ios.get(), (TitleTmd*)origTmdBuf);

            if (VerifyAndInstallRestoredIOS(ios_ver, ios.get(), origTmdBuf, origTmdSize, origTikBuf, origTikSize)) {
                successCount++;
            }

            free(origTmdBuf);
            free(origTikBuf);
        }
    }

    Patcher_Log("=========================================");
    Patcher_Log("Completed. Successfully restored " + std::to_string(successCount) + "/" + std::to_string(selected_items.size()) + " IOSes.");
    Patcher_Log("");
    Patcher_Log("Press A to return.");
    WaitPrompt();
}

bool UndoDrivePatchAllBatch() {
    bool hasAllBackups = true;
    for (int i = 0; i < NUM_TARGET_IOS; i++) {
        FSAFileHandle testFd;
        std::string tmdBackup = GetTmdBackupPath(TARGET_IOS[i]);
        if (FSAOpenFileEx(fsaClient, tmdBackup.c_str(), "r", (FSMode)0, FS_OPEN_FLAG_NONE, 0, &testFd) == FS_ERROR_OK) {
            FSACloseFile(fsaClient, testFd);
        } else {
            hasAllBackups = false;
        }
    }

    int action = hasAllBackups ? 1 : 2;
    int successCount = 0;

    for (int i = 0; i < NUM_TARGET_IOS; i++) {
        uint32_t ios_ver = TARGET_IOS[i];
        Patcher_Log("Restoring IOS" + std::to_string(ios_ver) + "...");

        if (action == 2) {
            if (RestoreIOSFromNUS(ios_ver)) successCount++;
        } else if (action == 1) {
            auto ios = ReadBaseIOS(ios_ver);
            if (!ios) {
                Patcher_Log("Error: Failed to read base IOS" + std::to_string(ios_ver));
                continue;
            }

            uint8_t* origTmdBuf = nullptr;
            uint32_t origTmdSize = 0;
            if (!ReadFileToBuffer(GetTmdBackupPath(ios_ver), &origTmdBuf, &origTmdSize)) {
                Patcher_Log("Error: Failed to read tmd.bak for IOS" + std::to_string(ios_ver));
                continue;
            }

            uint8_t* origTikBuf = nullptr;
            uint32_t origTikSize = 0;
            if (!ReadFileToBuffer(GetTikBackupPath(ios_ver), &origTikBuf, &origTikSize)) {
                Patcher_Log("Error: Failed to read tik.bak for IOS" + std::to_string(ios_ver));
                free(origTmdBuf);
                continue;
            }

            for (uint32_t c = 0; c < ios->numContents; c++) {
                if (!ios->contents[c].data || ios->contents[c].size == 0) continue;
                if (ios_ver == 31 || ios_ver == 33 || ios_ver == 35 || ios_ver == 36) {
                    HandleDriveInquiryPatchIOS36(ios->contents[c].data, ios->contents[c].size, true);
                } else {
                    HandleDriveInquiryPatch(ios->contents[c].data, ios->contents[c].size, true);
                }
            }

            LoadPristineSharedContents(ios.get(), (TitleTmd*)origTmdBuf);

            if (VerifyAndInstallRestoredIOS(ios_ver, ios.get(), origTmdBuf, origTmdSize, origTikBuf, origTikSize)) {
                successCount++;
            }

            free(origTmdBuf);
            free(origTikBuf);
        }
    }
    
    return successCount == NUM_TARGET_IOS;
}
