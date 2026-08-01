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

static const uint32_t TARGET_IOS[] = {56, 57, 58};
static const int NUM_TARGET_IOS = sizeof(TARGET_IOS) / sizeof(TARGET_IOS[0]);

static bool IsOriginalNintendoSignature(const uint8_t* signature, size_t size) {
    uint32_t zeroCount = 0;
    for (size_t i = 0; i < size; i++) {
        if (signature[i] == 0) zeroCount++;
    }
    return zeroCount < (size / 2);
}

static int ReplacePattern(uint8_t *buf, uint32_t size, const uint8_t* search, const uint8_t* replace, uint32_t len, bool revert = false) {
    int count = 0;
    const uint8_t* p1 = revert ? replace : search;
    const uint8_t* p2 = revert ? search : replace;

    for (uint32_t i = 0; i < size - len; i++) {
        if (memcmp(buf + i, p1, len) == 0) {
            memcpy(buf + i, p2, len);
            count++;
            i += len - 1;
        }
    }
    return count;
}

    int HandleDriveInquiryPatch(uint8_t *buf, uint32_t size, bool revert) {
    static const uint8_t orig[] = { 0x49, 0x4C, 0x23, 0x90, 0x68, 0x0A };
    static const uint8_t pat[]  = { 0x20, 0x00, 0xE5, 0x38, 0x68, 0x0A };
    return ReplacePattern(buf, size, orig, pat, sizeof(orig), revert);
}

static uint32_t ApplyDrivePatch(MemIOS* ios) {
    uint32_t totalPatches = 0;
    for (uint32_t i = 0; i < ios->numContents; i++) {
        if (!ios->contents[i].data || ios->contents[i].size == 0) continue;

        uint32_t count = HandleDriveInquiryPatch(ios->contents[i].data, ios->contents[i].size);

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
    uint32_t totalPatches = ApplyDrivePatch(ios.get());

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

void InstallDrivePatchIOS56_57_58() {
    WUPI_resetScreen();
    std::vector<std::string> header = {
        "Apply Drive Inquiry Patch (IOS56, 57, 58)",
        "------------------------------------",
        "This applies Garys 'No Disc Drive' patch to IOS56, 57 and 58.",
        "It modifies the DIP module to ignore missing or bad drives.",
        "",
        "Are you sure you want to proceed?"
    };
    std::vector<std::string> options = {
        "Yes, patch and install IOS56, 57, 58",
        "No, cancel"
    };

    int choice = ShowMenu(header, options);
    if (choice != 0) {
        WUPI_resetScreen();
        Patcher_Log("Drive patch installation cancelled.");
        sleep(2);
        return;
    }

    WUPI_resetScreen();

    int successCount = 0;
    for (int i = 0; i < NUM_TARGET_IOS; i++) {
        Patcher_Log("=========================================");
        if (PatchAndInstallIOS(TARGET_IOS[i])) {
            successCount++;
        }
        Patcher_Log("");
    }

    Patcher_Log("Completed. Successfully patched " + std::to_string(successCount) + "/" + std::to_string(NUM_TARGET_IOS) + " IOSes.");
    Patcher_Log("");
    Patcher_Log("Press A to return.");
    WaitPrompt();
}




void UndoDrivePatchIOS56_57_58() {
    WUPI_resetScreen();

    std::vector<std::string> header = {
        "Undo Drive Inquiry Patches (IOS56, 57, 58)",
        "------------------------------------",
        "Select how you want to undo the patches."
    };

    // Check if we have backups for all 3
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

    std::vector<std::string> options;
    if (hasAllBackups) {
        options.push_back("Restore from local backups (In-Place)");
    }
    options.push_back("Reinstall original IOSes from NUS");
    options.push_back("Cancel");

    int choice = ShowMenu(header, options);
    if (choice == (int)options.size() - 1) {
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

    for (int i = 0; i < NUM_TARGET_IOS; i++) {
        uint32_t ios_ver = TARGET_IOS[i];
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
                HandleDriveInquiryPatch(ios->contents[c].data, ios->contents[c].size, true);
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
    Patcher_Log("Completed. Successfully restored " + std::to_string(successCount) + "/" + std::to_string(NUM_TARGET_IOS) + " IOSes.");
    Patcher_Log("");
    Patcher_Log("Press A to return.");
    WaitPrompt();
}

bool UndoDrivePatchIOS56_57_58Batch() {
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
                HandleDriveInquiryPatch(ios->contents[c].data, ios->contents[c].size, true);
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
