/* Compat Title Installer
 *   Copyright (C) 2026  zer00p
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "wad.h"
#include "installer.h"
#include "cert_sys.h"
#include "MenuUtils.h"
#include "StateUtils.h"
#include "log.h"
#include "EndianUtils.h"
#include <mocha/mocha.h>
#include <coreinit/filesystem_fsa.h>
#include <coreinit/memory.h>
#include <malloc.h>
#include <stdio.h>
#include <string.h>
#include <string>
#include <unistd.h>
#include <format>
#include "downloader.h"
extern "C" {
#include "wad_tools/tools.h"
}

#define WAD_HEADER_SIZE 0x40
#define WAD_ALIGN(x) (((x) + 0x3F) & ~0x3F)

// Forward declarations of FSA helpers
extern FSAClientHandle fsaClient;


extern "C" bool GetCommonKeyFromOTP(uint8_t index, uint8_t outKey[16]) {
    WiiUConsoleOTP otp;
    if (Mocha_ReadOTP(&otp) != MOCHA_RESULT_SUCCESS) {
        WUPI_Log("Failed to read OTP!\n");
        return false;
    }

    if (index == 0) {
        memcpy(outKey, otp.wiiBank.commonKey, 16);
    } else if (index == 1) {
        memcpy(outKey, otp.wiiCertBank.koreanKey, 16);
    } else if (index == 2) {
        memcpy(outKey, otp.wiiUBank.vWiiCommonKey, 16);
    } else {
        WUPI_Log("Unknown common key index %d, falling back to standard common key\n", index);
        memcpy(outKey, otp.wiiBank.commonKey, 16);
    }
    return true;
}

extern "C" int ExtractWadToMemory(const char* filepath, void** ticket, uint32_t* ticket_size, void** tmd, uint32_t* tmd_size, CINS_Content** contents, uint16_t* numContents, uint64_t* titleId, void** cert, uint32_t* cert_size);

WADContext* WAD_LoadAndDecrypt(const char* filepath) {
    void *ticket = NULL, *tmd = NULL, *cert = NULL;
    uint32_t ticket_size = 0, tmd_size = 0, cert_size = 0;
    CINS_Content *contents = NULL;
    uint16_t numContents = 0;
    uint64_t titleId = 0;

    int res = ExtractWadToMemory(filepath, &ticket, &ticket_size, &tmd, &tmd_size, &contents, &numContents, &titleId, &cert, &cert_size);
    if (res != 0) {
        WUPI_Log("ExtractWadToMemory failed for %s\n", filepath);
        return NULL;
    }

    WADContext* ctx = (WADContext*)malloc(sizeof(WADContext));
    if (!ctx) {
        WUPI_Log("WAD_LoadAndDecrypt: Failed to allocate context\n");
        for (int i = 0; i < numContents; i++) {
            free(const_cast<void*>(contents[i].data));
        }
        free(contents);
        free(ticket);
        free(tmd);
        if (cert) free(cert);
        return NULL;
    }
    memset(ctx, 0, sizeof(WADContext));

    ctx->certData = (uint8_t*)cert;
    ctx->certSize = cert_size;
    ctx->ticketData = (uint8_t*)ticket;
    ctx->ticketSize = ticket_size;
    ctx->tmdData = (uint8_t*)tmd;
    ctx->tmdSize = tmd_size;
    ctx->tmdTitleId = titleId;
    ctx->numContents = numContents;
    ctx->contentsArray = contents;

    // Set titleType by parsing TMD
    if (ctx->tmdData && ctx->tmdSize >= sizeof(TitleTmd)) {
        const TitleTmd* tmdStruct = reinterpret_cast<const TitleTmd*>(ctx->tmdData);
        ctx->titleType = FromBE32(tmdStruct->titleType);
    }

    WUPI_Log("WAD decrypted successfully. ID: %08x-%08x\n", (uint32_t)(ctx->tmdTitleId >> 32), (uint32_t)(ctx->tmdTitleId));
    return ctx;
}

void WAD_Free(WADContext* ctx) {
    if (ctx) {
        if (ctx->certData) free(ctx->certData);
        if (ctx->ticketData) free(ctx->ticketData);
        if (ctx->tmdData) free(ctx->tmdData);
        if (ctx->contentsArray) {
            for (int i = 0; i < ctx->numContents; i++) {
                if (ctx->contentsArray[i].data) {
                    free(const_cast<void*>(ctx->contentsArray[i].data));
                }
            }
            free(ctx->contentsArray);
        }
        free(ctx);
    }
}

bool WAD_IsSafeTitle(WADContext* ctx) {
    uint32_t highId = (uint32_t)(ctx->tmdTitleId >> 32);

    // 0x00000001 is System titles (IOS, System Menu, MIOS, BC)
    if (highId == 0x00000001) {
        bool isvWiiTitle = false;

        // Check TMD vwii_title flag (offset 0x43 in TMD payload)
        uint32_t tmdPayloadOffset = GetPayloadOffset(ctx->tmdData);
        if (ctx->tmdData && ctx->tmdSize > tmdPayloadOffset + 0x43) {
            if (ctx->tmdData[tmdPayloadOffset + 0x43] != 0) {
                isvWiiTitle = true;
            }
        }

        // Check ticket common key index to see if it's a vWii title
        if (ctx->ticketData && ctx->ticketSize >= sizeof(TitleTicket)) {
            const auto* tik = reinterpret_cast<const TitleTicket*>(ctx->ticketData);
            if (tik->commonKeyIndex == 2) {
                isvWiiTitle = true;
            }
        }

        // Installing original Wii system titles to vWii will brick it.
        if (!isvWiiTitle) {
            return false;
        }
    }
    return true;
}


bool WAD_InstallToVWii(WADContext* ctx, int fsaFd) {
    (void)fsaFd;
    if (!ctx) return false;

    if (ctx->certData && ctx->certSize > 0) {
        CERT_ImportCerts(fsaClient, ctx->certData, ctx->certSize);
    }

    return CINS_Install(ctx->tmdTitleId, (const TitleTicket *)ctx->ticketData, ctx->ticketSize,
                        (const TitleTmd *)ctx->tmdData, ctx->tmdSize, ctx->contentsArray,
                        ctx->numContents) == 0;
}

bool WAD_InstallSafe(WADContext* ctx) {
    if (!ctx) {
        WUPI_Log("Error: Invalid WAD context.\n");
        return false;
    }
    if (!WAD_IsSafeTitle(ctx)) {
        WUPI_Log("Error: Unsafe title. Aborting installation.\n");
        return false;
    }
    return WAD_InstallToVWii(ctx, 0);
}

bool NUS_DownloadAndInstall(uint64_t titleId, int32_t version) {
    WADContext* ctx = NUS_DownloadTitle(titleId, version);
    if (!ctx) {
        WUPI_Log("Error: Failed to download title from NUS.\n");
        return false;
    }
    bool result = WAD_InstallSafe(ctx);
    WAD_Free(ctx);
    return result;
}

int32_t NUS_GetLatestVersion(uint64_t titleId) {
    uint64_t fetchTitleId = titleId;

    // Shenanigans: Use 00000007 prefix for vWii system titles and 0007xxxx for vWii channels on NUS
    uint32_t highId = (fetchTitleId >> 32);
    if (highId == 1) {
        fetchTitleId = (fetchTitleId & 0xFFFFFFFF) | (0x00000007ULL << 32);
    } else if ((highId >> 16) == 1) {
        fetchTitleId = (fetchTitleId & 0xFFFFFFFF) | (((uint64_t)(highId & 0xFFFF) | 0x00070000ULL) << 32);
    }

    std::string url = std::format("http://nus.cdn.shop.wii.com/ccs/download/{:016x}/tmd", fetchTitleId);

    uint8_t* tmdData = NULL;
    size_t tmdSize = 0;
    if (!DownloadToMemory(url, &tmdData, &tmdSize)) {
        return -1;
    }

    if (tmdSize < sizeof(TitleTmd)) {
        free(tmdData);
        return -1;
    }

    const auto* tmd = reinterpret_cast<const TitleTmd*>(tmdData);
    uint16_t version = FromBE16(tmd->titleVersion);
    free(tmdData);
    return version;
}

WADContext* NUS_DownloadTitle(uint64_t titleId, int32_t version) {
    uint64_t fetchTitleId = titleId;

    // Shenanigans: Use 00000007 prefix for vWii system titles and 0007xxxx for vWii channels on NUS
    uint32_t highId = (fetchTitleId >> 32);
    if (highId == 1) {
        fetchTitleId = (fetchTitleId & 0xFFFFFFFF) | (0x00000007ULL << 32);
    } else if ((highId >> 16) == 1) {
        fetchTitleId = (fetchTitleId & 0xFFFFFFFF) | (((uint64_t)(highId & 0xFFFF) | 0x00070000ULL) << 32);
    }

    std::string url;
    if (version > 0) {
        url = std::format("http://nus.cdn.shop.wii.com/ccs/download/{:016x}/tmd.{}", fetchTitleId, version);
    } else {
        url = std::format("http://nus.cdn.shop.wii.com/ccs/download/{:016x}/tmd", fetchTitleId);
    }

    uint8_t* tmdData = NULL;
    size_t tmdSize = 0;
    WUPI_Log("Fetching TMD from NUS...\n");
    if (!DownloadToMemory(url, &tmdData, &tmdSize)) {
        WUPI_Log("Failed to download TMD.\n");
        return NULL;
    }

    if (tmdSize < 4) {
        WUPI_Log("TMD too small.\n");
        free(tmdData);
        return NULL;
    }

    url = std::format("http://nus.cdn.shop.wii.com/ccs/download/{:016x}/cetk", fetchTitleId);
    uint8_t* tikData = NULL;
    size_t tikSize = 0;
    WUPI_Log("Fetching Ticket from NUS...\n");
    if (!DownloadToMemory(url, &tikData, &tikSize)) {
        WUPI_Log("Failed to download Ticket.\n");
        free(tmdData);
        return NULL;
    }

    if (tikSize < 4) {
        WUPI_Log("Ticket too small.\n");
        free(tmdData);
        free(tikData);
        return NULL;
    }

    // Do NOT patch the Title ID in the TMD or Ticket back to 00000001!
    // Doing so breaks the signature. The vWii System Menu is signed by Nintendo with
    // the 00000007 prefix on NUS. We install it into the 00000001 directory via CINS_Install,
    // but we leave the actual file contents exactly as Nintendo signed them.

    if (tmdSize < sizeof(TitleTmd)) {
        WUPI_Log("TMD truncated.\n");
        free(tmdData); free(tikData);
        return NULL;
    }

    const auto* tmd = reinterpret_cast<const TitleTmd*>(tmdData);
    uint16_t numContents = FromBE16(tmd->numContents);

    // Validate and strip certificate chain from TMD and Ticket
    size_t requiredTmdSize = sizeof(TitleTmd) + (numContents * sizeof(TitleContentRecord));
    if (tmdSize < requiredTmdSize) {
        WUPI_Log("TMD truncated (content records).\n");
        free(tmdData); free(tikData);
        return NULL;
    }

    size_t requiredTikSize = sizeof(TitleTicket);
    if (tikSize < requiredTikSize) {
        WUPI_Log("Ticket truncated.\n");
        free(tmdData); free(tikData);
        return NULL;
    }

    uint8_t* certData = NULL;
    size_t certSize = 0;
    size_t tikCertLen = (tikSize > requiredTikSize) ? (tikSize - requiredTikSize) : 0;
    size_t tmdCertLen = (tmdSize > requiredTmdSize) ? (tmdSize - requiredTmdSize) : 0;
    if (tikCertLen > 0 || tmdCertLen > 0) {
        certSize = tikCertLen + tmdCertLen;
        certData = (uint8_t*)malloc(certSize);
        if (certData) {
            size_t off = 0;
            if (tikCertLen > 0) {
                memcpy(certData + off, tikData + requiredTikSize, tikCertLen);
                off += tikCertLen;
            }
            if (tmdCertLen > 0) {
                memcpy(certData + off, tmdData + requiredTmdSize, tmdCertLen);
                off += tmdCertLen;
            }
        } else {
            certSize = 0;
        }
    }

    tmdSize = requiredTmdSize;
    tikSize = requiredTikSize;

    // Decrypt Title Key
    const auto* tik = reinterpret_cast<const TitleTicket*>(tikData);
    uint8_t ckey_idx = tik->commonKeyIndex;

    uint8_t dynamic_common_key[16];
    if (GetCommonKeyFromOTP(ckey_idx, dynamic_common_key)) {
        set_common_key(dynamic_common_key);
    } else {
        WUPI_Log("Failed to get common key (idx %d)\n", ckey_idx);
        if (certData) free(certData);
        free(tmdData); free(tikData);
        return NULL;
    }

    uint8_t title_key[16];
    decrypt_title_key(tikData, title_key);

    CINS_Content* c_arr = (CINS_Content*)calloc(numContents, sizeof(CINS_Content));
    if (!c_arr) {
        if (certData) free(certData);
        free(tmdData); free(tikData);
        return NULL;
    }

    for (int i = 0; i < numContents; i++) {
        const TitleContentRecord& rec = tmd->contents[i];
        uint32_t cid = FromBE32(rec.contentId);
        uint16_t ctype = FromBE16(rec.type);
        uint64_t expectedLen = FromBE64(rec.size);
        const uint8_t* expected_hash = rec.hash.data();

        if ((ctype & 0x8000) != 0) {
            int32_t sharedIndex = FindSharedContentIndex(expected_hash);
            if (sharedIndex >= 0) {
                std::string sharedPath = std::format("/vol/slccmpt01/shared1/{:08x}.app", sharedIndex);
                if (FSACheckFileSha1(fsaClient, sharedPath, expected_hash, expectedLen)) {
                    WUPI_Log_Overwrite("Fetching Content %d/%d (Shared: on NAND, skipped)\n", i + 1, numContents);
                    c_arr[i].data = nullptr;
                    c_arr[i].length = expectedLen;
                    continue;
                }
            }
        }

        WUPI_Log_Overwrite("Fetching Content %d/%d from NUS...\n", i + 1, numContents);
        url = std::format("http://nus.cdn.shop.wii.com/ccs/download/{:016x}/{:08x}", fetchTitleId, cid);

        uint8_t* encData = NULL;
        size_t encSize = 0;
        if (!DownloadToMemory(url, &encData, &encSize)) {
            WUPI_Log("Failed to download content %d.\n", i);
            goto error;
        }

        if (expectedLen > encSize) {
            WUPI_Log("Content %d: expected size exceeds download.\n", i);
            free(encData);
            goto error;
        }

        uint8_t* decData = (uint8_t*)memalign(0x40, encSize);
        if (!decData) {
            free(encData);
            goto error;
        }

        uint8_t iv[16] = {0};
        memcpy(iv, &rec.index, sizeof(rec.index));

        aes_cbc_dec(title_key, iv, encData, encSize, decData);
        free(encData);

        uint8_t actual_hash[20];
        sha(decData, expectedLen, actual_hash);

        if (memcmp(expected_hash, actual_hash, 20) != 0) {
            WUPI_Log("Hash mismatch for content %d\n", i);
            free(decData);
            goto error;
        }

        c_arr[i].data = decData;
        c_arr[i].length = expectedLen;
    }

    {
        WADContext* ctx = (WADContext*)calloc(1, sizeof(WADContext));
        if (!ctx) goto error;

        ctx->certData = certData;
        ctx->certSize = certSize;
        ctx->ticketData = tikData;
        ctx->ticketSize = tikSize;
        ctx->tmdData = tmdData;
        ctx->tmdSize = tmdSize;
        ctx->tmdTitleId = titleId;
        ctx->titleType = FromBE32(tmd->titleType);
        ctx->numContents = numContents;
        ctx->contentsArray = c_arr;

        return ctx;
    }

error:
    if (certData) free(certData);
    if (c_arr) {
        for (int i = 0; i < numContents; i++) {
            if (c_arr[i].data) free((void*)c_arr[i].data);
        }
        free(c_arr);
    }
    if (tmdData) free(tmdData);
    if (tikData) free(tikData);
    return NULL;
}

const NusTitle g_nusTitles[38] = {
    // 1. System Menu (always UID 4096 / 0x1000)
    {0x0000000100000002ULL, "System Menu (vWii)", false, true},
    // 2. Base System Menu IOS (UID 4097)
    {0x0000000100000050ULL, "IOS80", false, false},
    // 3-7. System Channels (UID 4098..4102)
    {0x0001000248435500ULL, "Wii Menu Electronic Manual", true, false},
    {0x0001000248414341ULL, "Mii Channel", false, false},
    {0x0001000848414c00ULL, "EULA", true, false},
    {0x0001000248435641ULL, "Wii U Menu Channel", false, false},
    {0x0001000248414241ULL, "Disc Channel", false, false},
    // 8-9. Backward Compatibility IOSes (UID 4103..4104)
    {0x0000000100000200ULL, "BC-NAND", false, false},
    {0x0000000100000201ULL, "BC-WFS", false, false},
    // 10-36. System IOSes (UID 4105..4131)
    {0x000000010000000cULL, "IOS12", false, false},
    {0x000000010000000dULL, "IOS13", false, false},
    {0x000000010000000eULL, "IOS14", false, false},
    {0x000000010000000fULL, "IOS15", false, false},
    {0x0000000100000011ULL, "IOS17", false, false},
    {0x0000000100000015ULL, "IOS21", false, false},
    {0x0000000100000016ULL, "IOS22", false, false},
    {0x000000010000001cULL, "IOS28", false, false},
    {0x000000010000001fULL, "IOS31", false, false},
    {0x0000000100000021ULL, "IOS33", false, false},
    {0x0000000100000022ULL, "IOS34", false, false},
    {0x0000000100000023ULL, "IOS35", false, false},
    {0x0000000100000024ULL, "IOS36", false, false},
    {0x0000000100000025ULL, "IOS37", false, false},
    {0x0000000100000026ULL, "IOS38", false, false},
    {0x0000000100000029ULL, "IOS41", false, false},
    {0x000000010000002bULL, "IOS43", false, false},
    {0x000000010000002dULL, "IOS45", false, false},
    {0x000000010000002eULL, "IOS46", false, false},
    {0x0000000100000030ULL, "IOS48", false, false},
    {0x0000000100000035ULL, "IOS53", false, false},
    {0x0000000100000037ULL, "IOS55", false, false},
    {0x0000000100000038ULL, "IOS56", false, false},
    {0x0000000100000039ULL, "IOS57", false, false},
    {0x000000010000003aULL, "IOS58", false, false},
    {0x000000010000003bULL, "IOS59", false, false},
    {0x000000010000003eULL, "IOS62", false, false},
    // 37. IOS9 (UID 4132)
    {0x0000000100000009ULL, "IOS9", false, false},
    // 38. Region Select Hidden Channel (UID 4133/4134)
    {0x0001000848435a00ULL, "Region Select", true, false},
};

const size_t g_numNusTitles = sizeof(g_nusTitles) / sizeof(g_nusTitles[0]);

uint64_t NUS_ResolveTitleId(const NusTitle* title, int32_t regionCode) {
    if (!title) return 0;
    uint64_t titleId = title->id;
    if (title->regionSpecificId) {
        uint8_t regionChar = 0;
        switch (regionCode) {
            case 0: regionChar = 'J'; break;
            case 1: regionChar = 'E'; break;
            case 2: regionChar = 'P'; break;
        }
        if (regionChar != 0) {
            titleId |= regionChar;
        }
    }
    return titleId;
}

int32_t NUS_ResolveTitleVersion(const NusTitle* title, uint64_t resolvedTitleId, int32_t regionCode) {
    if (!title) return -1;
    int32_t latestVersion = NUS_GetLatestVersion(resolvedTitleId);
    if (latestVersion < 0) {
        return -1;
    }
    if (title->regionSpecificVersion) {
        return (latestVersion & ~3) | regionCode;
    }
    return latestVersion;
}

bool NUS_InstallSystemTitle(const NusTitle* title, int32_t regionCode) {
    if (!title) return false;
    uint64_t titleId = NUS_ResolveTitleId(title, regionCode);
    int32_t version = NUS_ResolveTitleVersion(title, titleId, regionCode);
    if (version < 0) {
        WUPI_Log("Error: Failed to fetch latest version from NUS for %s.\n", title->name);
        return false;
    }
    WUPI_Log("Version: %d\n", version);
    return NUS_DownloadAndInstall(titleId, version);
}

bool NUS_InstallTitlesBatch(const std::vector<const NusTitle*>& titles, int32_t regionCode, int& outSuccess, int& outFailed) {
    outSuccess = 0;
    outFailed = 0;
    int total = (int)titles.size();

    for (int i = 0; i < total; i++) {
        if (!State::AppRunning()) break;
        const auto* t = titles[i];
        if (!t) continue;

        WUPI_Log("--- Processing %s (%d/%d) ---", t->name, i + 1, total);

        if (NUS_InstallSystemTitle(t, regionCode)) {
            WUPI_Log("Installation complete!\n");
            outSuccess++;
            sleep(1);
        } else {
            outFailed++;
            WUPI_putstr("Press A to continue with next title, B to abort.");
            if (!WaitPrompt()) {
                return false;
            }
        }
    }
    return (outFailed == 0);
}
