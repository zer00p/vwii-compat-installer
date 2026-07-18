/* WAD Installer integration
 *   Copyright (C) 2026
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

static inline uint16_t Read16BE(const uint8_t* p) {
    return (p[0] << 8) | p[1];
}

static inline uint32_t Read32BE(const uint8_t* p) {
    return (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
}

static inline uint64_t Read64BE(const uint8_t* p) {
    return ((uint64_t)p[0] << 56) | ((uint64_t)p[1] << 48) |
           ((uint64_t)p[2] << 40) | ((uint64_t)p[3] << 32) |
           ((uint64_t)p[4] << 24) | ((uint64_t)p[5] << 16) |
           ((uint64_t)p[6] << 8)  | ((uint64_t)p[7]);
}

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
    ctx->titleType = Read32BE(ctx->tmdData + 0x188);

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
        
        // Check TMD vwii_title flag (offset 0x183 in TMD)
        if (ctx->tmdData && ctx->tmdSize > 0x183) {
            if (ctx->tmdData[0x183] != 0) {
                isvWiiTitle = true;
            }
        }
        
        // Check ticket common key index to see if it's a vWii title
        if (ctx->ticketData && ctx->ticketSize >= 0x1F2) {
            uint32_t sigType = Read32BE(ctx->ticketData);
            uint32_t payloadOffset = 0;
            if (sigType == 0x00010000) payloadOffset = 0x240;
            else if (sigType == 0x00010001) payloadOffset = 0x140;
            else if (sigType == 0x00010002) payloadOffset = 0x80;
            
            if (payloadOffset > 0 && ctx->ticketSize >= payloadOffset + 0x1F2) {
                uint8_t ckey = ctx->ticketData[payloadOffset + 0x1F1];
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

    FSError ret;
    FSAFileHandle fd;
    char path[256], pathd[256];
    char titlePath[256], ticketPath[256], ticketFolder[256];

    uint32_t idHi = (uint32_t)(ctx->tmdTitleId >> 32);
    uint32_t idLo = (uint32_t)(ctx->tmdTitleId & 0xFFFFFFFF);

    snprintf(titlePath, sizeof(titlePath), "/vol/slccmpt01/title/%08x/%08x", idHi, idLo);
    snprintf(path, sizeof(path), "/vol/slccmpt01/title/%08x", idHi);
    snprintf(ticketPath, sizeof(ticketPath), "/vol/slccmpt01/ticket/%08x/%08x.tik", idHi, idLo);
    snprintf(ticketFolder, sizeof(ticketFolder), "/vol/slccmpt01/ticket/%08x", idHi);

    WAD_Log("Writing ticket...\n");
    FSARemove(fsaClient, ticketPath);
    ret = FSAMakeDir(fsaClient, ticketFolder, (FSMode) 0x666);
    if (ret == FS_ERROR_OK || ret == FS_ERROR_ALREADY_EXISTS) {
        WAD_TRY(FSAOpenFileEx(fsaClient, ticketPath, "wb", (FSMode) 0x666, FS_OPEN_FLAG_NONE, 0, &fd) == FS_ERROR_OK);
        WAD_TRY(FSAWriteFile(fsaClient, ctx->ticketData, ctx->ticketSize, 1, fd, FSA_WRITE_FLAG_NONE) == 1);
        FSACloseFile(fsaClient, fd);
        ret = FS_ERROR_OK;
    }
    WAD_TRY(ret == FS_ERROR_OK);

    WAD_Log("Creating title directory...\n");
    ret = FSAMakeDir(fsaClient, path, (FSMode) 0x666);
    if (ret == FS_ERROR_OK || ret == FS_ERROR_ALREADY_EXISTS) {
        ret = FSAMakeDir(fsaClient, titlePath, (FSMode) 0x666);
        if (ret == FS_ERROR_ALREADY_EXISTS) {
            WAD_Log("Title directory exists, deleting content...\n");
            snprintf(path, sizeof(path), "/vol/slccmpt01/title/%08x/%08x/content", idHi, idLo);
            ret = FSARemove(fsaClient, path);
            if (ret == FS_ERROR_OK || ret == FS_ERROR_NOT_FOUND) ret = FS_ERROR_OK;
        }
    }
    WAD_TRY(ret == FS_ERROR_OK);

    strncpy(pathd, titlePath, sizeof(pathd));
    strncat(pathd, "/data", sizeof(pathd) - 1);
    ret = FSAMakeDir(fsaClient, pathd, (FSMode) 0x666);
    if (ret != FS_ERROR_OK && ret != FS_ERROR_ALREADY_EXISTS) {
        WAD_Log("Failed to create data directory\n");
        goto error;
    }

    strncpy(pathd, titlePath, sizeof(pathd));
    strncat(pathd, "/content", sizeof(pathd) - 1);
    WAD_TRY(FSAMakeDir(fsaClient, pathd, (FSMode) 0x666) == FS_ERROR_OK);

    WAD_Log("Writing TMD...\n");
    strncpy(path, pathd, sizeof(path));
    strncat(path, "/title.tmd", sizeof(path) - 1);
    WAD_TRY(FSAOpenFileEx(fsaClient, path, "wb", (FSMode) 0x666, FS_OPEN_FLAG_NONE, 0, &fd) == FS_ERROR_OK);
    WAD_TRY(FSAWriteFile(fsaClient, ctx->tmdData, ctx->tmdSize, 1, fd, FSA_WRITE_FLAG_NONE) == 1);
    FSACloseFile(fsaClient, fd);

    WAD_Log("Writing contents...\n");
    for (uint16_t i = 0; i < ctx->numContents; i++) {
        uint32_t recordOffset = 0x1E4 + (i * 36);
        uint32_t cId = Read32BE(ctx->tmdData + recordOffset);
        uint64_t cSize = Read64BE(ctx->tmdData + recordOffset + 8);
        
        snprintf(path, sizeof(path), "/vol/slccmpt01/title/%08x/%08x/content/%08x.app", idHi, idLo, cId);
        WAD_TRY(FSAOpenFileEx(fsaClient, path, "wb", (FSMode) 0x666, FS_OPEN_FLAG_NONE, 0, &fd) == FS_ERROR_OK);
        
        // Write exactly the unaligned size of the content (not padded to 0x40 like the WAD container)
        WAD_TRY(FSAWriteFile(fsaClient, const_cast<void*>(ctx->contentsArray[i].data), cSize, 1, fd, FSA_WRITE_FLAG_NONE) == 1);
        FSACloseFile(fsaClient, fd);
    }

    WAD_Log("WAD install succeeded!\n");
    return true;

error:
    FSACloseFile(fsaClient, fd);
    WAD_Log("Install failed, cleaning up...\n");
    FSARemove(fsaClient, titlePath);
    FSARemove(fsaClient, ticketPath);
    return false;
}
