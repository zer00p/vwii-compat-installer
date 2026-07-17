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
#include "aes.h"
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

static bool GetWiiCommonKey(uint8_t outKey[16]) {
    WiiUConsoleOTP otp;
    if (Mocha_ReadOTP(&otp) != MOCHA_RESULT_SUCCESS) {
        WAD_Log("Failed to read OTP!\n");
        return false;
    }
    // Wii common key is at OTP offset 0x014
    memcpy(outKey, ((uint8_t*)&otp) + 0x14, 16);
    return true;
}

WADContext* WAD_LoadAndDecrypt(const char* filepath) {
    FSAFileHandle fd;
    if (FSAOpenFileEx(fsaClient, filepath, "rb", (FSMode) 0x666, FS_OPEN_FLAG_NONE, 0, &fd) != FS_ERROR_OK) {
        WAD_Log("Could not open WAD file: %s\n", filepath);
        return NULL;
    }

    // Get file size
    FSAStat stat;
    FSAGetStatFile(fsaClient, fd, &stat);
    size_t fileSize = stat.size;

    WADContext* ctx = (WADContext*)memalign(0x40, sizeof(WADContext));
    if (!ctx) {
        FSACloseFile(fsaClient, fd);
        return NULL;
    }
    memset(ctx, 0, sizeof(WADContext));
    
    ctx->rawData = (uint8_t*)memalign(0x40, fileSize);
    if (!ctx->rawData) {
        WAD_Log("Out of memory reading WAD.\n");
        free(ctx);
        FSACloseFile(fsaClient, fd);
        return NULL;
    }
    ctx->size = fileSize;

    size_t bytesRead = 0;
    while (bytesRead < fileSize) {
        size_t readSize = fileSize - bytesRead;
        // FSA limits read size, loop if needed
        int res = FSAReadFile(fsaClient, ctx->rawData + bytesRead, 1, readSize, fd, 0);
        if (res <= 0) break;
        bytesRead += res;
    }
    FSACloseFile(fsaClient, fd);

    if (bytesRead < 0x40) {
        WAD_Log("WAD file is too small.\n");
        WAD_Free(ctx);
        return NULL;
    }

    uint8_t* p = ctx->rawData;
    uint32_t headerSize = Read32BE(p);
    if (headerSize != 0x20) {
        WAD_Log("Invalid WAD header size.\n");
        WAD_Free(ctx);
        return NULL;
    }

    ctx->certSize    = Read32BE(p + 0x08);
    ctx->crlSize     = Read32BE(p + 0x0C);
    ctx->ticketSize  = Read32BE(p + 0x10);
    ctx->tmdSize     = Read32BE(p + 0x14);
    ctx->contentSize = Read32BE(p + 0x18);
    ctx->metaSize    = Read32BE(p + 0x1C);

    size_t offset = WAD_HEADER_SIZE;
    ctx->certData = p + offset; offset += WAD_ALIGN(ctx->certSize);
    ctx->crlData = p + offset; offset += WAD_ALIGN(ctx->crlSize);
    ctx->ticketData = p + offset; offset += WAD_ALIGN(ctx->ticketSize);
    ctx->tmdData = p + offset; offset += WAD_ALIGN(ctx->tmdSize);
    ctx->contentData = p + offset; offset += WAD_ALIGN(ctx->contentSize);
    ctx->metaData = p + offset; offset += WAD_ALIGN(ctx->metaSize);

    if (offset > ctx->size) {
        WAD_Log("WAD file is truncated.\n");
        WAD_Free(ctx);
        return NULL;
    }

    // Parse Ticket for Title Key
    ctx->ticketTitleId = Read64BE(ctx->ticketData + 0x1DC);
    
    uint8_t wiiCommonKey[16];
    if (!GetWiiCommonKey(wiiCommonKey)) {
        WAD_Free(ctx);
        return NULL;
    }

    uint8_t titleKeyIV[16];
    memset(titleKeyIV, 0, 16);
    memcpy(titleKeyIV, &ctx->ticketData[0x1DC], 8);

    uint8_t encryptedTitleKey[16];
    memcpy(encryptedTitleKey, &ctx->ticketData[0x1BF], 16);

    struct AES_ctx aes;
    AES_init_ctx_iv(&aes, wiiCommonKey, titleKeyIV);
    memcpy(ctx->titleKey, encryptedTitleKey, 16);
    AES_CBC_decrypt_buffer(&aes, ctx->titleKey, 16);

    // Parse TMD
    ctx->tmdTitleId = Read64BE(ctx->tmdData + 0x18C);
    ctx->titleType = Read32BE(ctx->tmdData + 0x188);
    ctx->numContents = Read16BE(ctx->tmdData + 0x1DE);

    if (ctx->ticketTitleId != ctx->tmdTitleId) {
        WAD_Log("Title ID mismatch between Ticket and TMD.\n");
        WAD_Free(ctx);
        return NULL;
    }

    // Allocate buffer for decrypted contents
    ctx->decryptedContentData = (uint8_t*)memalign(0x40, ctx->contentSize);
    if (!ctx->decryptedContentData) {
        WAD_Log("Out of memory for decrypted content.\n");
        WAD_Free(ctx);
        return NULL;
    }

    // Decrypt contents
    uint32_t currentContentOffset = 0;
    for (uint16_t i = 0; i < ctx->numContents; i++) {
        uint32_t recordOffset = 0x1E4 + (i * 36); // 36 bytes per content record
        uint16_t cIndex = Read16BE(ctx->tmdData + recordOffset + 4);
        uint64_t cSize = Read64BE(ctx->tmdData + recordOffset + 8);
        
        uint64_t alignedSize = WAD_ALIGN(cSize);
        if (currentContentOffset + alignedSize > ctx->contentSize) {
            WAD_Log("Content size exceeds WAD boundaries.\n");
            WAD_Free(ctx);
            return NULL;
        }

        uint8_t* encPtr = ctx->contentData + currentContentOffset;
        uint8_t* decPtr = ctx->decryptedContentData + currentContentOffset;
        memcpy(decPtr, encPtr, alignedSize);

        uint8_t contentIV[16];
        memset(contentIV, 0, 16);
        contentIV[0] = (cIndex >> 8) & 0xFF;
        contentIV[1] = cIndex & 0xFF;

        AES_init_ctx_iv(&aes, ctx->titleKey, contentIV);
        AES_CBC_decrypt_buffer(&aes, decPtr, alignedSize);

        currentContentOffset += alignedSize;
    }

    WAD_Log("WAD decrypted successfully. ID: %08x-%08x\n", (uint32_t)(ctx->tmdTitleId >> 32), (uint32_t)(ctx->tmdTitleId));
    return ctx;
}

void WAD_Free(WADContext* ctx) {
    if (ctx) {
        if (ctx->rawData) free(ctx->rawData);
        if (ctx->decryptedContentData) free(ctx->decryptedContentData);
        free(ctx);
    }
}

bool WAD_IsSafeTitle(WADContext* ctx) {
    uint32_t highId = (uint32_t)(ctx->tmdTitleId >> 32);
    // 0x00000001 is System titles (IOS, System Menu, MIOS, BC)
    // Installing these to vWii from a WAD is extremely dangerous.
    if (highId == 0x00000001) {
        return false;
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
    uint32_t currentContentOffset = 0;

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
        WAD_TRY(FSAWriteFile(fsaClient, ctx->decryptedContentData + currentContentOffset, cSize, 1, fd, FSA_WRITE_FLAG_NONE) == 1);
        FSACloseFile(fsaClient, fd);

        currentContentOffset += WAD_ALIGN(cSize);
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
