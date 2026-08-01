/*
 * ios80_patcher.cpp
 *
 * Dedicated patcher for vWii System Menu IOS (IOS80).
 * Adapted from the Patched IOS80 Installer for vWii project.
 * Original credits go to Dr Clipper, Lazr1026, FIX94, and contributors.
 *
 * Licensed under GPLv2.
 */

#include "ios80_patcher.h"
#include "ios_common.h"
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

static const std::string IOS80_TMD_BACKUP_PATH = "/vol/slccmpt01/title/00000001/00000050/data/tmd.bak";
static const std::string IOS80_TIK_BACKUP_PATH = "/vol/slccmpt01/title/00000001/00000050/data/tik.bak";

static bool IsOriginalNintendoSignature(const uint8_t* signature, size_t size) {
    uint32_t zeroCount = 0;
    for (size_t i = 0; i < size; i++) {
        if (signature[i] == 0) zeroCount++;
    }
    // A 2048-bit RSA signature is random cryptographic data.
    // If it's more than half zeros, it was wiped or forged by a homebrew tool.
    return zeroCount < (size / 2);
}

static int ReplacePattern(uint8_t *buf, uint32_t size, const uint8_t* search, const uint8_t* replace, uint32_t len, bool revert = false) {
    if (size < len) return 0;
    uint32_t match_count = 0;
    const uint8_t* actual_search = revert ? replace : search;
    const uint8_t* actual_replace = revert ? search : replace;
    for (uint32_t i = 0; i <= size - len; i++) {
        if (memcmp(buf + i, actual_search, len) == 0) {
            memcpy(buf + i, actual_replace, len);
            i += len - 1;
            match_count++;
        }
    }
    return match_count;
}

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

void InstallIOS80() {
    WUPI_resetScreen();
    std::vector<std::string> header = {
        "Patch IOS80 (vWii System Menu IOS)",
        "------------------------------------",
        "This patches IOS80 with the Trucha bug & ES/FS patches",
        "to allow launching custom channels/homebrew directly from",
        "the vWii SD Card Menu.",
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

    bool isOriginal = IsOriginalNintendoSignature(ios->tmd->signature, sizeof(ios->tmd->signature));
    
    if (isOriginal) {
        FSAFileHandle testFd;
        if (FSAOpenFileEx(fsaClient, IOS80_TMD_BACKUP_PATH.c_str(), "r", (FSMode)0, FS_OPEN_FLAG_NONE, 0, &testFd) == FS_ERROR_OK) {
            FSACloseFile(fsaClient, testFd);
        } else {
            WriteBufferToFile(IOS80_TMD_BACKUP_PATH, (uint8_t*)ios->tmd, ios->tmdSize);
            WriteBufferToFile(IOS80_TIK_BACKUP_PATH, (uint8_t*)ios->ticket, ios->ticketSize);
        }
    } else {
        Patcher_Log("Note: Installed IOS80 is already patched.");
        Patcher_Log("Skipping TMD/Ticket backup.");
    }

    Patcher_Log("Applying patches to IOS80 contents...");
    uint32_t totalPatches = 0;
    for (uint32_t i = 0; i < ios->numContents; i++) {
        if (!ios->contents[i].data || ios->contents[i].size == 0) continue;

        uint32_t count = 0;
        count += HandleVersionCheckPatch(ios->contents[i].data, ios->contents[i].size);
        count += HandleHashCheckPatch(ios->contents[i].data, ios->contents[i].size);
        count += HandleIdentifyCheckPatch(ios->contents[i].data, ios->contents[i].size);
        count += HandleFsPermsPatch(ios->contents[i].data, ios->contents[i].size);
        count += HandleKillAntiSysTitleInstallPatch(ios->contents[i].data, ios->contents[i].size);

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

    Patcher_Log("Applied " + std::to_string(totalPatches) + " patches across contents.");
    Patcher_Log("Forging ticket/TMD and writing patched IOS80...");

    if (WritePatchedIOS(80, *ios)) {
        Patcher_Log("");
        Patcher_Log("Successfully patched and installed IOS80!");
    } else {
        Patcher_Log("");
        Patcher_Log("Error: Failed to write patched IOS80.");
    }
    
    Patcher_Log("");
        Patcher_Log("Press A to return.");
    WaitPrompt();
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
    bool hasBackup = (FSAOpenFileEx(fsaClient, IOS80_TMD_BACKUP_PATH.c_str(), "r", (FSMode)0, FS_OPEN_FLAG_NONE, 0, &testFd) == FS_ERROR_OK);
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

    int action = 0;
    if (hasBackup && choice == 0) {
        action = 1; // Local
    } else {
        action = 2; // NUS
    }

    WUPI_resetScreen();
    
    if (action == 2) {
        Patcher_Log("Connecting to NUS...");
        uint64_t titleId = 0x0000000100000050ULL; // IOS80
        int32_t latestVersion = NUS_GetLatestVersion(titleId);
        if (latestVersion == -1) {
            Patcher_Log("Error: Failed to fetch latest version from NUS.");
            Patcher_Log("");
        Patcher_Log("Press A to return.");
            WaitPrompt();
            return;
        }

        Patcher_Log("Downloading fresh IOS80 (v" + std::to_string(latestVersion) + ")...");
        WADContext* ctx = NUS_DownloadTitle(titleId, latestVersion);
        if (!ctx) {
            Patcher_Log("Error: Failed to download IOS80.");
            Patcher_Log("");
        Patcher_Log("Press A to return.");
            WaitPrompt();
            return;
        }
        
        if (!WAD_IsSafeTitle(ctx)) {
            Patcher_Log("Error: Downloaded title is unsafe. Aborting.");
            WAD_Free(ctx);
            Patcher_Log("");
        Patcher_Log("Press A to return.");
            WaitPrompt();
            return;
        }

        Patcher_Log("Writing original IOS80 to slccmpt...");
        if (WAD_InstallToVWii(ctx, 0)) {
            Patcher_Log("");
        Patcher_Log("Successfully restored original IOS80 from NUS!");
        } else {
            Patcher_Log("");
        Patcher_Log("Error: Failed to write original IOS80.");
        }
        if (ctx) WAD_Free(ctx);
        
    } else if (action == 1) {
        Patcher_Log("Loading backup TMD and Ticket...");
        uint8_t* origTmdBuf = nullptr;
        uint32_t origTmdSize = 0;
        if (!ReadFileToBuffer(IOS80_TMD_BACKUP_PATH, &origTmdBuf, &origTmdSize)) {
            Patcher_Log("Error: Failed to read tmd.bak.");
            Patcher_Log("");
        Patcher_Log("Press A to return.");
            WaitPrompt();
            return;
        }

        uint8_t* origTikBuf = nullptr;
        uint32_t origTikSize = 0;
        if (!ReadFileToBuffer(IOS80_TIK_BACKUP_PATH, &origTikBuf, &origTikSize)) {
            Patcher_Log("Error: Failed to read tik.bak.");
            free(origTmdBuf);
            Patcher_Log("");
        Patcher_Log("Press A to return.");
            WaitPrompt();
            return;
        }

        TitleTmd* origTmd = (TitleTmd*)origTmdBuf;
        uint16_t origNumContents = FromBE16(origTmd->numContents);
        TitleContentRecord* origRecords = origTmd->contents;

        Patcher_Log("Reverting patches on IOS80 contents...");
        for (uint32_t i = 0; i < ios->numContents; i++) {
            if (!ios->contents[i].data || ios->contents[i].size == 0) continue;

            // If the content was originally a shared content, the pristine original 
            // still perfectly exists in /shared1/. We can just load it directly 
            // and bypass the flawed pattern-matching unpatcher which might corrupt 
            // natural occurrences of the byte sequences in those modules.
            bool isShared = false;
            uint8_t* expectedHash = nullptr;
            for (uint16_t k = 0; k < origNumContents; k++) {
                if (FromBE32(origRecords[k].contentId) == ios->contents[i].cid) {
                    if (FromBE16(origRecords[k].type) & 0x8000) {
                        isShared = true;
                    }
                    expectedHash = origRecords[k].hash;
                    break;
                }
            }

            if (isShared && expectedHash) {
                int32_t sharedIndex = FindSharedContentIndex(expectedHash);
                if (sharedIndex >= 0) {
                    std::string sharedPath = "/vol/slccmpt01/shared1/" + ToHexString(sharedIndex, 8) + ".app";
                    uint8_t* sharedBuf = nullptr;
                    uint32_t sharedSize = 0;
                    if (ReadFileToBuffer(sharedPath, &sharedBuf, &sharedSize)) {
                        free(ios->contents[i].data);
                        ios->contents[i].data = sharedBuf;
                        ios->contents[i].size = sharedSize;
                        continue; // Successfully loaded the pristine original
                    }
                }
            } else {
                // This is a private content that cannot be retrieved from /shared1/.
                // We must manually unpatch it in-memory.
                HandleVersionCheckPatch(ios->contents[i].data, ios->contents[i].size, true);
                HandleHashCheckPatch(ios->contents[i].data, ios->contents[i].size, true);
                HandleIdentifyCheckPatch(ios->contents[i].data, ios->contents[i].size, true);
                HandleFsPermsPatch(ios->contents[i].data, ios->contents[i].size, true);
                HandleKillAntiSysTitleInstallPatch(ios->contents[i].data, ios->contents[i].size, true);
            }
        }
        Patcher_Log("Loaded pristine shared contents successfully.");


        
        std::vector<CINS_Content> cinsContents;
        for (uint32_t i = 0; i < ios->numContents; i++) {
            CINS_Content cc;
            cc.data = ios->contents[i].data;
            cc.length = ios->contents[i].size;
            cinsContents.push_back(cc);
        }

        Patcher_Log("Verifying hashes against original TMD...");
        
        bool hashesMatch = true;
        std::vector<std::string> mismatchErrors;
        for (uint16_t i = 0; i < origNumContents; i++) {
            uint32_t cid = FromBE32(origRecords[i].contentId);
            uint8_t expectedHash[20];
            memcpy(expectedHash, origRecords[i].hash, 20);
            
            bool found = false;
            for (uint32_t j = 0; j < ios->numContents; j++) {
                if (ios->contents[j].cid == cid) {
                    found = true;
                    uint8_t actualHash[20];
                    SHA1(ios->contents[j].data, ios->contents[j].size, actualHash);
                    if (memcmp(expectedHash, actualHash, 20) != 0) {
                        hashesMatch = false;
                        mismatchErrors.push_back("Hash mismatch: " + ToHexString(cid));
                    }
                    break;
                }
            }
            if (!found) {
                hashesMatch = false;
                mismatchErrors.push_back("Missing content: " + ToHexString(cid));
            }
        }
        
        if (!hashesMatch) {
            WUPI_resetScreen();
            Patcher_Log("In-place restore failed:");
            for (const auto& err : mismatchErrors) {
                Patcher_Log(err);
            }
            Patcher_Log("");
            Patcher_Log("The unpatched files do not perfectly match");
            Patcher_Log("the original Nintendo hashes.");
            Patcher_Log("Please use 'Reinstall from NUS' instead.");
            free(origTmdBuf);
            free(origTikBuf);
            Patcher_Log("");
        Patcher_Log("Press A to return.");
            WaitPrompt();
            return;
        }

        Patcher_Log("Restoring original IOS80 configuration...");
        int32_t res = CINS_Install(0x0000000100000050ULL, 
                                   (const TitleTicket*)origTikBuf, origTikSize,
                                   (const TitleTmd*)origTmdBuf, origTmdSize,
                                   cinsContents.data(), cinsContents.size());
                                   
        free(origTmdBuf);
        free(origTikBuf);

        if (res == 0) {
            Patcher_Log("");
        Patcher_Log("Successfully restored IOS80 from backup!");
        } else {
            Patcher_Log("");
        Patcher_Log("Error: Failed to restore backup. Code: " + std::to_string(res) + "");
        }
    }
    
    Patcher_Log("");
        Patcher_Log("Press A to return.");
    WaitPrompt();
}
