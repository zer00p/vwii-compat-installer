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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <vector>
#include <string>

static int PatchVersionCheck(uint8_t *buf, uint32_t size) {
    uint32_t match_count = 0;
    static const uint8_t version_check[] = { 0xD2, 0x01, 0x4E, 0x56 };
    if (size < sizeof(version_check)) return 0;
    for (uint32_t i = 0; i <= size - sizeof(version_check); i++) {
        if (memcmp(buf + i, version_check, sizeof(version_check)) == 0) {
            buf[i] = 0xE0;
            buf[i + 3] = 0x00;
            i += sizeof(version_check) - 1;
            match_count++;
        }
    }
    return match_count;
}

static int PatchHashCheck(uint8_t *buf, uint32_t size) {
    uint32_t match_count = 0;
    static const uint8_t new_hash_check[] = { 0x20, 0x07, 0x4B, 0x0B };
    static const uint8_t old_hash_check[] = { 0x20, 0x07, 0x23, 0xA2 };
    if (size < 4) return 0;
    for (uint32_t i = 0; i <= size - 4; i++) {
        if (memcmp(buf + i, new_hash_check, sizeof(new_hash_check)) == 0 ||
            memcmp(buf + i, old_hash_check, sizeof(old_hash_check)) == 0) {
            buf[i + 1] = 0x00;
            i += 3;
            match_count++;
        }
    }
    return match_count;
}

static int PatchIdentifyCheck(uint8_t *buf, uint32_t size) {
    uint32_t match_count = 0;
    static const uint8_t identify_check[] = { 0x28, 0x03, 0xD1, 0x23 };
    if (size < sizeof(identify_check)) return 0;
    for (uint32_t i = 0; i <= size - sizeof(identify_check); i++) {
        if (memcmp(buf + i, identify_check, sizeof(identify_check)) == 0) {
            buf[i + 2] = 0x00;
            buf[i + 3] = 0x00;
            i += sizeof(identify_check) - 1;
            match_count++;
        }
    }
    return match_count;
}

static int PatchFsPerms(uint8_t *buf, uint32_t size) {
    uint32_t match_count = 0;
    static const uint8_t old_table[] = { 0x42, 0x8B, 0xD0, 0x01, 0x25, 0x66 };
    static const uint8_t new_table[] = { 0x42, 0x8B, 0xE0, 0x01, 0x25, 0x66 };
    if (size < sizeof(old_table)) return 0;
    for (uint32_t i = 0; i <= size - sizeof(old_table); i++) {
        if (memcmp(buf + i, old_table, sizeof(old_table)) == 0) {
            memcpy(buf + i, new_table, sizeof(new_table));
            i += sizeof(new_table) - 1;
            match_count++;
        }
    }
    return match_count;
}

static int PatchKillAntiSysTitleInstall(uint8_t *buf, uint32_t size) {
    uint32_t match_count = 0;
    static const uint8_t pt1[] = { 0x68, 0x1A, 0x2A, 0x01, 0xD0, 0x05 };
    static const uint8_t pt2[] = { 0xD0, 0x02, 0x33, 0x06, 0x42, 0x9A, 0xD1, 0x01 };
    static const uint8_t pt3[] = { 0x68, 0xFB, 0x2B, 0x00, 0xDB, 0x01 };

    if (size >= sizeof(pt1)) {
        for (uint32_t i = 0; i <= size - sizeof(pt1); i++) {
            if (memcmp(buf + i, pt1, sizeof(pt1)) == 0) {
                buf[i + 4] = 0x46;
                buf[i + 5] = 0xC0;
                i += sizeof(pt1) - 1;
                match_count++;
            }
        }
    }

    if (size >= sizeof(pt2)) {
        for (uint32_t i = 0; i <= size - sizeof(pt2); i++) {
            if (memcmp(buf + i, pt2, sizeof(pt2)) == 0) {
                buf[i] = 0x46;
                buf[i + 1] = 0xC0;
                buf[i + 6] = 0xE0;
                i += sizeof(pt2) - 1;
                match_count++;
            }
        }
    }

    if (size >= sizeof(pt3)) {
        for (uint32_t i = 0; i <= size - sizeof(pt3); i++) {
            if (memcmp(buf + i, pt3, sizeof(pt3)) == 0) {
                buf[i + 5] = 0x10;
                i += sizeof(pt3) - 1;
                match_count++;
            }
        }
    }

    return match_count;
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
        Patcher_Log("IOS80 patching cancelled.\n");
        sleep(2);
        return;
    }

    WUPI_resetScreen();
    Patcher_Log("Reading base IOS80 from slccmpt...\n");
    auto ios = ReadBaseIOS(80);
    if (!ios) {
        Patcher_Log("Error: Failed to read base IOS80.\n");
        sleep(2);
        return;
    }

    Patcher_Log("Applying patches to IOS80 contents...\n");
    uint32_t totalPatches = 0;
    for (uint32_t i = 0; i < ios->numContents; i++) {
        if (!ios->contents[i].data || ios->contents[i].size == 0) continue;

        uint32_t count = 0;
        count += PatchVersionCheck(ios->contents[i].data, ios->contents[i].size);
        count += PatchHashCheck(ios->contents[i].data, ios->contents[i].size);
        count += PatchIdentifyCheck(ios->contents[i].data, ios->contents[i].size);
        count += PatchFsPerms(ios->contents[i].data, ios->contents[i].size);
        count += PatchKillAntiSysTitleInstall(ios->contents[i].data, ios->contents[i].size);

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

    Patcher_Log("Applied " + std::to_string(totalPatches) + " patches across contents.\n");
    Patcher_Log("Forging ticket/TMD and writing patched IOS80...\n");

    if (WritePatchedIOS(80, *ios)) {
        Patcher_Log("\nSuccessfully patched and installed IOS80!\n");
    } else {
        Patcher_Log("\nError: Failed to write patched IOS80.\n");
    }
}
