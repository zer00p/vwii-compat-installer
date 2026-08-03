/*
 * ios80_patcher.cpp
 *
 * Dedicated patcher for vWii System Menu IOS (IOS80).
 * Adapted from the Patched IOS80 Installer for vWii project.
 * Original credits go to Dr Clipper, ZRicky11, damysteryman, FIX94,
 * and contributors.
 *
 * Licensed under GPLv2.
 */

#include "ios80_patcher.h"
#include "ios_common.h"
#include "drive_inquiry_patcher.h"
#include "installer.h"
#include "MenuUtils.h"
#include "EndianUtils.h"
#include "log.h"
#include "wad.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <vector>
#include <string>

extern FSAClientHandle fsaClient;





static int HandleVersionCheckPatch(uint8_t *buf, uint32_t size, bool revert = false) {
    static const uint8_t orig[] = { 0xD2, 0x01, 0x4E, 0x56 };
    static const uint8_t pat[]  = { 0xE0, 0x01, 0x4E, 0x00 };
    return ReplacePattern(buf, size, orig, pat, sizeof(orig), revert);
}

static int HandleHashCheckPatch(uint8_t *buf, uint32_t size, bool revert = false) {
    static const uint8_t old_orig[] = { 0x20, 0x07, 0x23, 0xA2 };
    static const uint8_t old_pat[]= { 0x20, 0x00, 0x23, 0xA2 };
    static const uint8_t new_orig[] = { 0x20, 0x07, 0x4B, 0x0B };
    static const uint8_t new_pat[]= { 0x20, 0x00, 0x4B, 0x0B };
    
    int count = 0;
    count += ReplacePattern(buf, size, old_orig, old_pat, sizeof(old_orig), revert);
    count += ReplacePattern(buf, size, new_orig, new_pat, sizeof(new_orig), revert);
    return count;
}

static int HandleIdentifyCheckPatch(uint8_t *buf, uint32_t size, bool revert = false) {
    static const uint8_t orig[] = { 0x28, 0x03, 0xD1, 0x23 };
    static const uint8_t pat[]  = { 0x28, 0x03, 0x00, 0x00 };
    return ReplacePattern(buf, size, orig, pat, sizeof(orig), revert);
}

static int HandleFsPermsPatch(uint8_t *buf, uint32_t size, bool revert = false) {
    static const uint8_t orig[] = { 0x42, 0x8B, 0xD0, 0x01, 0x25, 0x66 };
    static const uint8_t pat[]  = { 0x42, 0x8B, 0xE0, 0x01, 0x25, 0x66 };
    return ReplacePattern(buf, size, orig, pat, sizeof(orig), revert);
}

static int HandleKillAntiSysTitleInstallPatch(uint8_t *buf, uint32_t size, bool revert = false) {
    static const uint8_t orig1[] = { 0x68, 0x1A, 0x2A, 0x01, 0xD0, 0x05 };
    static const uint8_t pat1[]  = { 0x68, 0x1A, 0x2A, 0x01, 0x46, 0xC0 };
    
    static const uint8_t orig2[] = { 0xD0, 0x02, 0x33, 0x06, 0x42, 0x9A, 0xD1, 0x01 };
    static const uint8_t pat2[]  = { 0x46, 0xC0, 0x33, 0x06, 0x42, 0x9A, 0xE0, 0x01 };
    
    static const uint8_t orig3[] = { 0x68, 0xFB, 0x2B, 0x00, 0xDB, 0x01 };
    static const uint8_t pat3[]  = { 0x68, 0xFB, 0x2B, 0x00, 0xDB, 0x10 };
    
    int count = 0;
    count += ReplacePattern(buf, size, orig1, pat1, sizeof(orig1), revert);
    count += ReplacePattern(buf, size, orig2, pat2, sizeof(orig2), revert);
    count += ReplacePattern(buf, size, orig3, pat3, sizeof(orig3), revert);
    return count;
}



static uint32_t ApplyAllIOS80Patches(MemIOS* ios) {
    uint32_t totalPatches = 0;
    for (uint32_t i = 0; i < ios->numContents; i++) {
        if (!ios->contents[i].data || ios->contents[i].size == 0) continue;

        uint32_t count = 0;
        count += HandleVersionCheckPatch(ios->contents[i].data, ios->contents[i].size);
        count += HandleHashCheckPatch(ios->contents[i].data, ios->contents[i].size);
        count += HandleIdentifyCheckPatch(ios->contents[i].data, ios->contents[i].size);
        count += HandleFsPermsPatch(ios->contents[i].data, ios->contents[i].size);
        count += HandleKillAntiSysTitleInstallPatch(ios->contents[i].data, ios->contents[i].size);
        count += HandleDriveInquiryPatch(ios->contents[i].data, ios->contents[i].size);

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

static bool PatchAndInstallIOS80Internal() {
    Patcher_Log("Reading base IOS80 from slccmpt...");
    auto ios = ReadBaseIOS(80);
    if (!ios) {
        Patcher_Log("Error: Failed to read base IOS80.");
        return false;
    }

    bool isOriginal = IsOriginalNintendoSignature(ios->tmd->signature, sizeof(ios->tmd->signature));
    
    if (isOriginal) {
        BackupPristineTmdAndTicket(80, ios.get());
    } else {
        Patcher_Log("Note: Installed IOS80 is already patched.");
        Patcher_Log("Skipping TMD/Ticket backup.");
    }

    Patcher_Log("Applying patches to IOS80 contents...");
    uint32_t totalPatches = ApplyAllIOS80Patches(ios.get());

    Patcher_Log("Applied " + std::to_string(totalPatches) + " patches across contents.");
    Patcher_Log("Forging ticket/TMD and writing patched IOS80...");

    bool ok = WritePatchedIOS(80, *ios);
    if (ok) {
        Patcher_Log("Successfully patched and installed IOS80!");
    } else {
        Patcher_Log("Error: Failed to write patched IOS80.");
    }
    return ok;
}

void InstallIOS80() {
    WUPI_resetScreen();
    std::vector<std::string> header = {
        "Patch IOS80 (vWii System Menu IOS)",
        "------------------------------------",
        "This patches IOS80 with Trucha, ES/FS, & Drive Inquiry patches",
        "to allow launching custom channels/homebrew directly from",
        "the vWii SD Card Menu and prevent disc drive checks.",
        "",
        "Are you sure you want to proceed?"
    };
    std::vector<std::string> options = {
        "Yes, patch and install IOS80",
        "No, cancel"
    };

    int choice = ShowMenu(header, options);
    if (choice != 0) {
        WUPI_resetScreen();
        Patcher_Log("IOS80 patching cancelled.");
        sleep(2);
        return;
    }

    WUPI_resetScreen();
    PatchAndInstallIOS80Internal();
    
    Patcher_Log("");
    Patcher_Log("Press A to return.");
    WaitPrompt();
}


static bool RestoreIOS80FromBackup() {
    auto ios = ReadBaseIOS(80);
    if (!ios) {
        Patcher_Log("Error: Failed to read base IOS80.");
        return false;
    }

    uint8_t* origTmdBuf = nullptr;
    uint32_t origTmdSize = 0;
    if (!ReadFileToBuffer(GetTmdBackupPath(80), &origTmdBuf, &origTmdSize)) {
        Patcher_Log("Error: Failed to read tmd.bak.");
        return false;
    }

    uint8_t* origTikBuf = nullptr;
    uint32_t origTikSize = 0;
    if (!ReadFileToBuffer(GetTikBackupPath(80), &origTikBuf, &origTikSize)) {
        Patcher_Log("Error: Failed to read tik.bak.");
        free(origTmdBuf);
        return false;
    }

    Patcher_Log("Reverting patches on IOS80 contents...");
    for (uint32_t i = 0; i < ios->numContents; i++) {
        if (!ios->contents[i].data || ios->contents[i].size == 0) continue;
        HandleVersionCheckPatch(ios->contents[i].data, ios->contents[i].size, true);
        HandleHashCheckPatch(ios->contents[i].data, ios->contents[i].size, true);
        HandleIdentifyCheckPatch(ios->contents[i].data, ios->contents[i].size, true);
        HandleFsPermsPatch(ios->contents[i].data, ios->contents[i].size, true);
        HandleKillAntiSysTitleInstallPatch(ios->contents[i].data, ios->contents[i].size, true);
        HandleDriveInquiryPatch(ios->contents[i].data, ios->contents[i].size, true);
    }

    Patcher_Log("Loading pristine shared contents...");
    LoadPristineSharedContents(ios.get(), (TitleTmd*)origTmdBuf);

    bool res = VerifyAndInstallRestoredIOS(80, ios.get(), origTmdBuf, origTmdSize, origTikBuf, origTikSize);

    free(origTmdBuf);
    free(origTikBuf);
    return res;
}

void UndoIOS80Patches() {
    WUPI_resetScreen();

    Patcher_Log("Reading base IOS80 from slccmpt...");
    auto ios = ReadBaseIOS(80);
    if (!ios) {
        WUPI_resetScreen();
        Patcher_Log("Error: Failed to read base IOS80.");
        Patcher_Log("");
        Patcher_Log("Press A to return.");
        WaitPrompt();
        return;
    }

    if (IsOriginalNintendoSignature(ios->tmd->signature, sizeof(ios->tmd->signature))) {
        WUPI_resetScreen();
        Patcher_Log("");
        Patcher_Log("IOS80 is currently stock/original.");
        Patcher_Log("There are no patches to undo.");
        Patcher_Log("");
        Patcher_Log("Press A to return.");
        WaitPrompt();
        return;
    }

    FSAFileHandle testFd;
    bool hasBackup = (FSAOpenFileEx(fsaClient, GetTmdBackupPath(80).c_str(), "r", (FSMode)0, FS_OPEN_FLAG_NONE, 0, &testFd) == FS_ERROR_OK);
    if (hasBackup) FSACloseFile(fsaClient, testFd);

    std::vector<std::string> header = {
        "Undo IOS80 Patches",
        "------------------------------------",
        "Select how you want to undo the patches."
    };
    std::vector<std::string> options;
    if (hasBackup) {
        options.push_back("Restore from local backup (In-Place)");
    }
    options.push_back("Reinstall original IOS80 from NUS");
    options.push_back("Cancel");

    // Clear the console so it doesn't overlap with the menu renderer
    WUPI_resetScreen();

    int choice = ShowMenu(header, options);
    if (choice == (int)options.size() - 1) {
        WUPI_resetScreen();
        Patcher_Log("IOS80 unpatching cancelled.");
        Patcher_Log("");
        Patcher_Log("Press A to return.");
        WaitPrompt();
        return;
    }

    int action = (hasBackup && choice == 0) ? 1 : 2;

    WUPI_resetScreen();
    
    if (action == 2) {
        Patcher_Log("Connecting to NUS...");
        RestoreIOSFromNUS(80);
    } else if (action == 1) {
        RestoreIOS80FromBackup();
    }
    
    Patcher_Log("");
    Patcher_Log("Press A to return.");
    WaitPrompt();
}

bool InstallIOS80Batch() {
    return PatchAndInstallIOS80Internal();
}

bool UndoIOS80PatchesBatch() {
    auto ios = ReadBaseIOS(80);
    if (ios && IsOriginalNintendoSignature(ios->tmd->signature, sizeof(ios->tmd->signature))) {
        Patcher_Log("IOS80 is already stock/original.");
        return true;
    }

    FSAFileHandle testFd;
    bool hasBackup = (FSAOpenFileEx(fsaClient, GetTmdBackupPath(80).c_str(), "r", (FSMode)0, FS_OPEN_FLAG_NONE, 0, &testFd) == FS_ERROR_OK);
    if (hasBackup) {
        FSACloseFile(fsaClient, testFd);
        Patcher_Log("Restoring IOS80 from local backup...");
        if (RestoreIOS80FromBackup()) {
            return true;
        }
        Patcher_Log("Local restore failed. Falling back to NUS download...");
    }

    Patcher_Log("Downloading original IOS80 from NUS...");
    return RestoreIOSFromNUS(80);
}


