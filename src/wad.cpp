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
#include "log.h"
#include "EndianUtils.h"
#include <mocha/mocha.h>
#include <coreinit/filesystem_fsa.h>
#include <coreinit/memory.h>
#include <malloc.h>
#include <stdio.h>
#include <string.h>
#include <string>
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

extern "C" int ExtractWadToMemory(const char* filepath, void** ticket, uint32_t* ticket_size, void** tmd, uint32_t* tmd_size, CINS_Content** contents, uint16_t* numContents, uint64_t* titleId);

WADContext* WAD_LoadAndDecrypt(const char* filepath) {
    void *ticket = NULL, *tmd = NULL;
    uint32_t ticket_size = 0, tmd_size = 0;
    CINS_Content *contents = NULL;
    uint16_t numContents = 0;
    uint64_t titleId = 0;

    int res = ExtractWadToMemory(filepath, &ticket, &ticket_size, &tmd, &tmd_size, &contents, &numContents, &titleId);
    if (res != 0) {
        WUPI_Log("ExtractWadToMemory failed for %s\n", filepath);
        return NULL;
    }

    WADContext* ctx = (WADContext*)malloc(sizeof(WADContext));
    if (!ctx) {
        WUPI_Log("WAD_LoadAndDecrypt: Failed to allocate context\n");
        return NULL;
    }
    memset(ctx, 0, sizeof(WADContext));

    ctx->ticketData = (uint8_t*)ticket;
    ctx->ticketSize = ticket_size;
    ctx->tmdData = (uint8_t*)tmd;
    ctx->tmdSize = tmd_size;
    ctx->tmdTitleId = titleId;
    ctx->numContents = numContents;
    ctx->contentsArray = contents;

    // Set titleType by parsing TMD
    uint32_t tmdPayloadOffset = GetPayloadOffset(ctx->tmdData);
    ctx->titleType = Read32BE(ctx->tmdData + tmdPayloadOffset + 0x48);

    WUPI_Log("WAD decrypted successfully. ID: %08x-%08x\n", (uint32_t)(ctx->tmdTitleId >> 32), (uint32_t)(ctx->tmdTitleId));
    return ctx;
}

void WAD_Free(WADContext* ctx) {
    if (ctx) {
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
        if (ctx->ticketData && ctx->ticketSize >= 4) {
            uint32_t tikPayloadOffset = GetPayloadOffset(ctx->ticketData);
            if (tikPayloadOffset > 0 && ctx->ticketSize >= tikPayloadOffset + 0xB2) {
                uint8_t ckey = ctx->ticketData[tikPayloadOffset + 0xB1];
                if (ckey == 2) {
                    isvWiiTitle = true;
                }
            }
        }
        
        // Installing original Wii system titles to vWii will brick it.
        if (!isvWiiTitle) {
            return false;
        }
    }
    return true;
}

#define WAD_TRY(c) \
    if (!(c)) \
        do { \
            WUPI_Log("Install failed\n"); \
            goto error; \
    } while (0)

bool WAD_InstallToVWii(WADContext* ctx, int fsaFd) {
    (void)fsaFd;
    if (!ctx) return false;

    return CINS_Install(ctx->tmdTitleId, (const TitleTicket *)ctx->ticketData, ctx->ticketSize,
                        (const TitleTmd *)ctx->tmdData, ctx->tmdSize, ctx->contentsArray,
                        ctx->numContents) == 0;
}

WADContext* NUS_DownloadTitle(uint64_t titleId, int32_t version) {
    uint64_t fetchTitleId = titleId;
    
    // Shenanigans: Use 00000007 prefix for vWii titles on NUS
    if ((fetchTitleId >> 32) == 1) {
        fetchTitleId = (fetchTitleId & 0xFFFFFFFF) | (0x00000007ULL << 32);
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
    
    url = std::format("http://nus.cdn.shop.wii.com/ccs/download/{:016x}/cetk", fetchTitleId);
    uint8_t* tikData = NULL;
    size_t tikSize = 0;
    WUPI_Log("Fetching Ticket from NUS...\n");
    if (!DownloadToMemory(url, &tikData, &tikSize)) {
        WUPI_Log("Failed to download Ticket.\n");
        free(tmdData);
        return NULL;
    }
    
    // Do NOT patch the Title ID in the TMD or Ticket back to 00000001!
    // Doing so breaks the signature. The vWii System Menu is signed by Nintendo with 
    // the 00000007 prefix on NUS. We install it into the 00000001 directory via CINS_Install,
    // but we leave the actual file contents exactly as Nintendo signed them.
    
    uint32_t tmdPayloadOffset = get_payload_offset(tmdData);
    uint32_t tikPayloadOffset = get_payload_offset(tikData);
    
    uint16_t numContents = be16(tmdData + tmdPayloadOffset + 0x9E);

    // Strip certificate chain from TMD and Ticket so they match WAD contents
    tmdSize = tmdPayloadOffset + 0x9E + 6 + (numContents * 0x24);
    tikSize = tikPayloadOffset + 0x164;
    
    // Decrypt Title Key
    uint8_t ckey_idx = 0;
    if (tikPayloadOffset > 0 && tikSize >= tikPayloadOffset + 0xB2) {
        ckey_idx = tikData[tikPayloadOffset + 0xB1];
    }
    
    uint8_t dynamic_common_key[16];
    if (GetCommonKeyFromOTP(ckey_idx, dynamic_common_key)) {
        set_common_key(dynamic_common_key);
    } else {
        WUPI_Log("Failed to get common key (idx %d)\n", ckey_idx);
        free(tmdData); free(tikData);
        return NULL;
    }
    
    uint8_t title_key[16];
    decrypt_title_key(tikData, title_key);
    
    CINS_Content* c_arr = (CINS_Content*)calloc(numContents, sizeof(CINS_Content));
    if (!c_arr) {
        free(tmdData); free(tikData);
        return NULL;
    }
    
    for (int i = 0; i < numContents; i++) {
        WUPI_Log_Overwrite("Fetching Content %d/%d...\n", i + 1, numContents);
        uint32_t cid = be32(tmdData + tmdPayloadOffset + 0xA4 + 0x24*i);
        url = std::format("http://nus.cdn.shop.wii.com/ccs/download/{:016x}/{:08x}", fetchTitleId, cid);
        
        uint8_t* encData = NULL;
        size_t encSize = 0;
        if (!DownloadToMemory(url, &encData, &encSize)) {
            WUPI_Log("Failed to download content %d.\n", i);
            goto error;
        }
        
        uint64_t expectedLen = be64(tmdData + tmdPayloadOffset + 0xac + 0x24*i);
        
        uint8_t* decData = (uint8_t*)memalign(0x40, encSize);
        if (!decData) {
            free(encData);
            goto error;
        }
        
        uint8_t iv[16] = {0};
        memcpy(iv, tmdData + tmdPayloadOffset + 0xa8 + 0x24*i, 2);
        
        aes_cbc_dec(title_key, iv, encData, encSize, decData);
        free(encData);
        
        uint8_t actual_hash[20];
        sha(decData, expectedLen, actual_hash);
        
        uint8_t expected_hash[20];
        memcpy(expected_hash, tmdData + tmdPayloadOffset + 0xb4 + 0x24*i, 20);
        
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
        
        ctx->ticketData = tikData;
        ctx->ticketSize = tikSize;
        ctx->tmdData = tmdData;
        ctx->tmdSize = tmdSize;
        ctx->tmdTitleId = titleId;
        ctx->titleType = be32(tmdData + tmdPayloadOffset + 0x48);
        ctx->numContents = numContents;
        ctx->contentsArray = c_arr;
        
        return ctx;
    }
    
error:
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
