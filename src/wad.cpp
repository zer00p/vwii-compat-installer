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
#include "installer.h" // For CINS_Log, WUPI_putstr, etc.
#include "EndianUtils.h"
#include <mocha/mocha.h>
#include <coreinit/filesystem_fsa.h>
#include <coreinit/memory.h>
#include <malloc.h>
#include <stdio.h>
#include <string.h>

#define WAD_HEADER_SIZE 0x40
#define WAD_ALIGN(x) (((x) + 0x3F) & ~0x3F)

// Forward declarations of FSA helpers
extern FSAClientHandle fsaClient;
void WUPI_putstr(const char *);
#define WAD_Log(...) \
    do { \
        char _wupi_print_str[256]; \
        snprintf(_wupi_print_str, 255, __VA_ARGS__); \
        WUPI_putstr(_wupi_print_str); \
    } while (0)


extern "C" bool GetCommonKeyFromOTP(uint8_t index, uint8_t outKey[16]) {
    WiiUConsoleOTP otp;
    if (Mocha_ReadOTP(&otp) != MOCHA_RESULT_SUCCESS) {
        WAD_Log("Failed to read OTP!\n");
        return false;
    }
    
    if (index == 0) {
        memcpy(outKey, otp.wiiBank.commonKey, 16);
    } else if (index == 1) {
        memcpy(outKey, otp.wiiCertBank.koreanKey, 16);
    } else if (index == 2) {
        memcpy(outKey, otp.wiiUBank.vWiiCommonKey, 16);
    } else {
        WAD_Log("Unknown common key index %d\n", index);
        return false;
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
        WAD_Log("ExtractWadToMemory failed for %s\n", filepath);
        return NULL;
    }

    WADContext* ctx = (WADContext*)memalign(0x40, sizeof(WADContext));
    if (!ctx) {
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

    WAD_Log("WAD decrypted successfully. ID: %08x-%08x\n", (uint32_t)(ctx->tmdTitleId >> 32), (uint32_t)(ctx->tmdTitleId));
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
            WAD_Log("Install failed\n"); \
            goto error; \
    } while (0)

bool WAD_InstallToVWii(WADContext* ctx, int fsaFd) {
    (void)fsaFd;
    if (!ctx) return false;

    return CINS_Install(ctx->tmdTitleId, ctx->ticketData, ctx->ticketSize,
                        ctx->tmdData, ctx->tmdSize, ctx->contentsArray,
                        ctx->numContents) == 0;
}
