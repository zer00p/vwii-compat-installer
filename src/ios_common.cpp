#include "ios_common.h"
#include "installer.h"
#include "log.h"
#include "EndianUtils.h"
#include <mbedtls/sha1.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include <sstream>
#include <iomanip>

extern "C" {
#include "wad_tools/tools.h"
}

#include "wad.h"

extern FSAClientHandle fsaClient;

MemIOS::~MemIOS() {
    if (tmd) free(tmd);
    if (ticket) free(ticket);
    if (contents) {
        for (uint32_t i = 0; i < numContents; i++) {
            if (contents[i].data) free(contents[i].data);
        }
        free(contents);
    }
}

void Patcher_Log(const std::string& msg) {
    WUPI_putstr(msg.c_str());
}

std::string ToHexString(uint32_t val, int width) {
    std::stringstream ss;
    ss << std::setfill('0') << std::setw(width) << std::hex << val;
    return ss.str();
}

void Write16BE(uint8_t* p, uint16_t v) {
    p[0] = (v >> 8) & 0xFF;
    p[1] = v & 0xFF;
}

void Write32BE(uint8_t* p, uint32_t v) {
    p[0] = (v >> 24) & 0xFF;
    p[1] = (v >> 16) & 0xFF;
    p[2] = (v >> 8) & 0xFF;
    p[3] = v & 0xFF;
}

void Write64BE(uint8_t* p, uint64_t v) {
    p[0] = (v >> 56) & 0xFF;
    p[1] = (v >> 48) & 0xFF;
    p[2] = (v >> 40) & 0xFF;
    p[3] = (v >> 32) & 0xFF;
    p[4] = (v >> 24) & 0xFF;
    p[5] = (v >> 16) & 0xFF;
    p[6] = (v >> 8) & 0xFF;
    p[7] = v & 0xFF;
}

void SHA1(const uint8_t* data, size_t len, uint8_t hash[20]) {
    mbedtls_sha1_context ctx;
    mbedtls_sha1_init(&ctx);
    mbedtls_sha1_starts_ret(&ctx);
    mbedtls_sha1_update_ret(&ctx, data, len);
    mbedtls_sha1_finish_ret(&ctx, hash);
    mbedtls_sha1_free(&ctx);
}

bool ReadFileToBuffer(const std::string& path, uint8_t** outBuf, uint32_t* outSize) {
    FSAFileHandle fd;
    if (FSAOpenFileEx(fsaClient, path.c_str(), "rb", (FSMode)0, FS_OPEN_FLAG_NONE, 0, &fd) != FS_ERROR_OK) {
        return false;
    }
    
    FSStat stat;
    FSAGetStatFile(fsaClient, fd, &stat);
    uint32_t size = stat.size;
    
    uint8_t* buf = (uint8_t*)memalign(0x40, (size + 0x3F) & ~0x3F);
    if (!buf) {
        FSACloseFile(fsaClient, fd);
        return false;
    }
    
    if (FSAReadFile(fsaClient, buf, 1, size, fd, FSA_READ_FLAG_NONE) != (int32_t)size) {
        free(buf);
        FSACloseFile(fsaClient, fd);
        return false;
    }
    
    FSACloseFile(fsaClient, fd);
    *outBuf = buf;
    *outSize = size;
    return true;
}

std::unique_ptr<MemIOS> ReadBaseIOS(uint32_t baseIos) {
    auto outIos = std::unique_ptr<MemIOS>(new MemIOS());
    // Read Ticket
    std::string path = "/vol/slccmpt01/ticket/00000001/" + ToHexString(baseIos, 8) + ".tik";
    uint8_t* tikBuf = nullptr;
    if (!ReadFileToBuffer(path, &tikBuf, &outIos->ticketSize)) {
        Patcher_Log("Failed to read ticket for base IOS " + std::to_string(baseIos) + "\n");
        return nullptr;
    }
    outIos->ticket = (TitleTicket*)tikBuf;
    
    // Read TMD
    path = "/vol/slccmpt01/title/00000001/" + ToHexString(baseIos, 8) + "/content/title.tmd";
    uint8_t* tmdBuf = nullptr;
    if (!ReadFileToBuffer(path, &tmdBuf, &outIos->tmdSize)) {
        Patcher_Log("Failed to read TMD for base IOS " + std::to_string(baseIos) + "\n");
        return nullptr;
    }
    outIos->tmd = (TitleTmd*)tmdBuf;
    
    // Parse TMD contents
    uint16_t numContents = FromBE16(outIos->tmd->numContents);
    outIos->numContents = numContents;
    outIos->maxContents = numContents + 10; // Extra space for modules
    outIos->contents = (MemContent*)calloc(outIos->maxContents, sizeof(MemContent));
    
    // Reallocate TMD buffer to have space for maxContents
    uint32_t maxTmdSize = outIos->tmdSize + (10 * sizeof(TitleContentRecord));
    uint8_t* newTmd = (uint8_t*)memalign(0x40, (maxTmdSize + 0x3F) & ~0x3F);
    if (!newTmd) {
        Patcher_Log("Failed to reallocate TMD buffer\n");
        return nullptr;
    }
    memset(newTmd, 0, (maxTmdSize + 0x3F) & ~0x3F);
    memcpy(newTmd, outIos->tmd, outIos->tmdSize);
    free(outIos->tmd);
    outIos->tmd = (TitleTmd*)newTmd;
    
    for (uint16_t i = 0; i < numContents; i++) {
        uint32_t cid = FromBE32(outIos->tmd->contents[i].contentId);
        outIos->contents[i].cid = cid;
        
        uint16_t cType = FromBE16(outIos->tmd->contents[i].type);
        if ((cType & 0x8000) != 0) {
            int32_t sharedIndex = FindSharedContentIndex(outIos->tmd->contents[i].hash);
            if (sharedIndex < 0) {
                Patcher_Log("Failed to find shared content for cid " + ToHexString(cid, 8) + "\n");
                return nullptr;
            }
            path = "/vol/slccmpt01/shared1/" + ToHexString(sharedIndex, 8) + ".app";
        } else {
            path = "/vol/slccmpt01/title/00000001/" + ToHexString(baseIos, 8) + "/content/" + ToHexString(cid, 8) + ".app";
        }

        if (!ReadFileToBuffer(path, &outIos->contents[i].data, &outIos->contents[i].size)) {
            Patcher_Log("Failed to read content " + ToHexString(cid, 8) + ".app\n");
            return nullptr;
        }
    }
    
    return outIos;
}

static void BruteTmd(TitleTmd* tmd, uint32_t size) {
    uint8_t hash[20];
    for (uint32_t fill = 0; fill < 65535; fill++) {
        tmd->fakeBootIndex = fill;
        SHA1((uint8_t*)tmd + offsetof(TitleTmd, issuer), size - offsetof(TitleTmd, issuer), hash);
        if (hash[0] == 0) return;
    }
}

static void BruteTicket(TitleTicket* ticket, uint32_t size) {
    uint8_t hash[20];
    for (uint32_t fill = 0; fill < 65535; fill++) {
        ticket->padding2 = fill;
        SHA1((uint8_t*)ticket + offsetof(TitleTicket, issuer), size - offsetof(TitleTicket, issuer), hash);
        if (hash[0] == 0) return;
    }
}

bool WritePatchedIOS(uint32_t titleIdLow, MemIOS& ios) {
    if (ios.ticketSize >= sizeof(TitleTicket)) {
        memset(ios.ticket->signature, 0, sizeof(ios.ticket->signature));
        
        uint8_t common_key[16];
        if (!GetCommonKeyFromOTP(ios.ticket->commonKeyIndex, common_key)) {
            Patcher_Log("Failed to read common key from OTP\n");
            return false;
        }

        uint8_t titleKey[16];
        uint8_t iv[16] = {0};
        memcpy(iv, &ios.ticket->titleId, 8);
        aes_cbc_dec(common_key, iv, ios.ticket->titleKey, 16, titleKey);
        
        ios.ticket->titleId = ToBE64(((uint64_t)1 << 32) | titleIdLow);
        
        memset(iv, 0, 16);
        memcpy(iv, &ios.ticket->titleId, 8);
        aes_cbc_enc(common_key, iv, titleKey, 16, ios.ticket->titleKey);
        
        BruteTicket(ios.ticket, ios.ticketSize);
    } else {
        Patcher_Log("Ticket size too small\n");
        return false;
    }
    
    if (ios.tmdSize >= offsetof(TitleTmd, contents) && ios.numContents > 0) {
        memset(ios.tmd->signature, 0, sizeof(ios.tmd->signature));
        ios.tmd->titleId = ToBE64(((uint64_t)1 << 32) | titleIdLow);
        ios.tmd->titleVersion = ToBE16(0xFFFF);
    } else {
        Patcher_Log("TMD size too small\n");
        return false;
    }
    
    TitleContentRecord* records = ios.tmd->contents;
    for (uint32_t i = 0; i < ios.numContents; i++) {
        uint32_t cid = FromBE32(records[i].contentId);
        for (uint32_t j = 0; j < ios.numContents; j++) {
            if (ios.contents[j].cid == cid) {
                uint8_t hash[20];
                SHA1(ios.contents[j].data, ios.contents[j].size, hash);
                memcpy(records[i].hash, hash, 20);
                break;
            }
        }
    }
    
    BruteTmd(ios.tmd, ios.tmdSize);
    
    CINS_Content* cins_contents = (CINS_Content*)malloc(sizeof(CINS_Content) * ios.numContents);
    if (!cins_contents) return false;
    
    for (uint32_t i = 0; i < ios.numContents; i++) {
        cins_contents[i].data = ios.contents[i].data;
        cins_contents[i].length = ios.contents[i].size;
    }
    
    uint64_t fullTitleId = 0x0000000100000000ULL | titleIdLow;
    int32_t ret = CINS_Install(fullTitleId, ios.ticket, ios.ticketSize, ios.tmd, ios.tmdSize, cins_contents, ios.numContents);
    
    free(cins_contents);
    
    return ret >= 0;
}
