/*
 * d2x_patcher.cpp
 * 
 * The cIOS patching logic (TMD/Ticket forging and dynamic module injection) 
 * in this file is adapted from the d2x-cios-installer project.
 * Original credits go to davebaol, xperia64, blackb0x / wiidev, 
 * and other contributors to the d2x cIOS and patchmii projects.
 *
 * Licensed under the GPLv2.
 */

#include "d2x_patcher.h"
#include "installer.h"
#include "tinyxml2.h"
#include "wad.h"
#include "InputUtils.h"
#include "StateUtils.h"
#include <coreinit/filesystem_fsa.h>
#include <coreinit/screen.h>
#include <mbedtls/sha1.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include <unistd.h>

extern FSAClientHandle fsaClient;
extern void WUPI_resetScreen();
extern void WUPI_putstr(const char *);

#define D2X_Log(...) \
    do { \
        char _wupi_print_str[256]; \
        snprintf(_wupi_print_str, 255, __VA_ARGS__); \
        WUPI_putstr(_wupi_print_str); \
    } while (0)


static inline void Write16BE(uint8_t* p, uint16_t v) {
    p[0] = (v >> 8) & 0xFF;
    p[1] = v & 0xFF;
}

static inline void Write32BE(uint8_t* p, uint32_t v) {
    p[0] = (v >> 24) & 0xFF;
    p[1] = (v >> 16) & 0xFF;
    p[2] = (v >> 8) & 0xFF;
    p[3] = v & 0xFF;
}

static inline void Write64BE(uint8_t* p, uint64_t v) {
    p[0] = (v >> 56) & 0xFF;
    p[1] = (v >> 48) & 0xFF;
    p[2] = (v >> 40) & 0xFF;
    p[3] = (v >> 32) & 0xFF;
    p[4] = (v >> 24) & 0xFF;
    p[5] = (v >> 16) & 0xFF;
    p[6] = (v >> 8) & 0xFF;
    p[7] = v & 0xFF;
}

static void SHA1(const uint8_t* data, size_t len, uint8_t hash[20]) {
    mbedtls_sha1_context ctx;
    mbedtls_sha1_init(&ctx);
    mbedtls_sha1_starts_ret(&ctx);
    mbedtls_sha1_update_ret(&ctx, data, len);
    mbedtls_sha1_finish_ret(&ctx, hash);
    mbedtls_sha1_free(&ctx);
}

struct MemContent {
    uint32_t cid;
    uint32_t size;
    uint8_t* data;
};

struct MemIOS {
    uint8_t* tmd;
    uint32_t tmdSize;
    uint8_t* ticket;
    uint32_t ticketSize;
    MemContent* contents;
    uint32_t numContents;
    uint32_t maxContents;
};

static void FreeIOS(MemIOS* ios) {
    if (!ios) return;
    if (ios->tmd) free(ios->tmd);
    if (ios->ticket) free(ios->ticket);
    if (ios->contents) {
        for (uint32_t i = 0; i < ios->numContents; i++) {
            if (ios->contents[i].data) free(ios->contents[i].data);
        }
        free(ios->contents);
    }
}

static bool ReadFileToBuffer(const char* path, uint8_t** outBuf, uint32_t* outSize) {
    FSAFileHandle fd;
    if (FSAOpenFileEx(fsaClient, path, "rb", (FSMode)0, FS_OPEN_FLAG_NONE, 0, &fd) != FS_ERROR_OK) {
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

static bool ReadBaseIOS(uint32_t baseIos, MemIOS* outIos) {
    memset(outIos, 0, sizeof(MemIOS));
    char path[256];
    
    // Read Ticket
    snprintf(path, sizeof(path), "/vol/slccmpt01/ticket/00000001/%08x.tik", baseIos);
    if (!ReadFileToBuffer(path, &outIos->ticket, &outIos->ticketSize)) {
        D2X_Log("Failed to read ticket for base IOS %u\n", baseIos);
        return false;
    }
    
    // Read TMD
    snprintf(path, sizeof(path), "/vol/slccmpt01/title/00000001/%08x/content/title.tmd", baseIos);
    if (!ReadFileToBuffer(path, &outIos->tmd, &outIos->tmdSize)) {
        D2X_Log("Failed to read TMD for base IOS %u\n", baseIos);
        FreeIOS(outIos);
        return false;
    }
    
    // Parse TMD contents
    uint16_t numContents = Read16BE(outIos->tmd + 0x1DE);
    outIos->numContents = numContents;
    outIos->maxContents = numContents + 10; // Extra space for modules
    outIos->contents = (MemContent*)calloc(outIos->maxContents, sizeof(MemContent));
    
    for (uint16_t i = 0; i < numContents; i++) {
        uint32_t recordOffset = 0x1E4 + (i * 36);
        uint32_t cid = Read32BE(outIos->tmd + recordOffset);
        outIos->contents[i].cid = cid;
        
        snprintf(path, sizeof(path), "/vol/slccmpt01/title/00000001/%08x/content/%08x.app", baseIos, cid);
        if (!ReadFileToBuffer(path, &outIos->contents[i].data, &outIos->contents[i].size)) {
            D2X_Log("Failed to read content %08x.app\n", cid);
            FreeIOS(outIos);
            return false;
        }
    }
    
    return true;
}

#include <vector>
#include <string>

static std::vector<uint8_t> ParseHexBytes(const char* str) {
    std::vector<uint8_t> bytes;
    if (!str) return bytes;
    std::string s(str);
    size_t pos = 0;
    while ((pos = s.find(',')) != std::string::npos) {
        bytes.push_back((uint8_t)strtoul(s.substr(0, pos).c_str(), NULL, 16));
        s.erase(0, pos + 1);
    }
    if (!s.empty()) {
        bytes.push_back((uint8_t)strtoul(s.c_str(), NULL, 16));
    }
    return bytes;
}

static bool ApplyBinaryPatch(MemContent* content, uint32_t offset, const std::vector<uint8_t>& origBytes, const std::vector<uint8_t>& newBytes) {
    if (origBytes.empty() || newBytes.empty()) return false;
    
    bool patched = false;
    for (uint32_t i = 0; i <= content->size - origBytes.size(); i++) {
        if (memcmp(content->data + i, origBytes.data(), origBytes.size()) == 0) {
            // Found a match
            if (i + offset + newBytes.size() <= content->size) {
                memcpy(content->data + i + offset, newBytes.data(), newBytes.size());
                patched = true;
            }
        }
    }
    return patched;
}

static bool AppendModule(MemIOS* ios, const char* versionFolder, const char* moduleName, int tmdModuleId) {
    char path[512];
    snprintf(path, sizeof(path), "%s/%s.app", versionFolder, moduleName);
    
    uint8_t* moduleData = NULL;
    uint32_t moduleSize = 0;
    
    if (!ReadFileToBuffer(path, &moduleData, &moduleSize)) {
        D2X_Log("Failed to read module %s\n", path);
        return false;
    }
    
    // Align size to 32 bytes
    uint32_t alignedSize = (moduleSize + 31) & ~31;
    uint8_t* alignedData = (uint8_t*)memalign(32, alignedSize);
    memset(alignedData, 0, alignedSize);
    memcpy(alignedData, moduleData, moduleSize);
    free(moduleData);
    
    uint32_t newContentId = 0;
    for (uint32_t i = 0; i < ios->numContents; i++) {
        if (ios->contents[i].cid > newContentId) newContentId = ios->contents[i].cid;
    }
    newContentId++;
    
    if (ios->numContents >= ios->maxContents) {
        D2X_Log("Too many contents to append!\n");
        free(alignedData);
        return false;
    }
    
    // Setup new content entry
    uint32_t idx = ios->numContents++;
    ios->contents[idx].cid = newContentId;
    ios->contents[idx].size = alignedSize;
    ios->contents[idx].data = alignedData;
    
    // Update TMD record
    uint8_t* tmdContentRecords = ios->tmd + 0x1E4;
    // Copy record from tmdModuleId to new index
    memcpy(tmdContentRecords + (idx * 36), tmdContentRecords + (tmdModuleId * 36), 36);
    
    // Update the copied record
    Write32BE(tmdContentRecords + (idx * 36), newContentId); // CID
    Write16BE(tmdContentRecords + (idx * 36) + 4, idx); // Index
    Write16BE(tmdContentRecords + (idx * 36) + 6, 1); // Type = normal
    Write64BE(tmdContentRecords + (idx * 36) + 8, alignedSize); // Size
    
    // Hash
    uint8_t hash[20];
    SHA1(alignedData, alignedSize, hash);
    memcpy(tmdContentRecords + (idx * 36) + 16, hash, 20);
    
    // Update numContents in TMD header
    Write16BE(ios->tmd + 0x1DE, ios->numContents);
    
    return true;
}

static void BruteTmd(uint8_t* tmd, uint32_t size) {
    uint8_t hash[20];
    for (uint32_t fill = 0; fill < 65535; fill++) {
        Write16BE(tmd + 0x1E0, fill); // fill3
        SHA1(tmd + 0x140, size - 0x140, hash);
        if (hash[0] == 0) return;
    }
}

static void BruteTicket(uint8_t* tik) {
    uint8_t hash[20];
    for (uint32_t fill = 0; fill < 65535; fill++) {
        Write16BE(tik + 0x1F8, fill); // padding
        SHA1(tik + 0x140, 0x150, hash);
        if (hash[0] == 0) return;
    }
}

#define D2X_TRY(c) \
    if (!(c)) \
        do { \
            D2X_Log("Install failed\n"); \
            goto error; \
    } while (0)

static bool WritePatchedIOS(uint32_t titleIdLow, MemIOS* ios) {
    FSError ret;
    FSAFileHandle fd;
    char path[256], pathd[256];
    char titlePath[256], ticketPath[256], ticketFolder[256];
    
    // Forge Ticket
    memset(ios->ticket + 4, 0, 256); // Zero out signature
    Write32BE(ios->ticket + 0x1DC, titleIdLow);
    BruteTicket(ios->ticket);
    
    // Forge TMD
    memset(ios->tmd + 4, 0, 256); // Zero out signature
    Write32BE(ios->tmd + 0x18C, titleIdLow);
    
    // Recalculate content hashes
    uint8_t* tmdContentRecords = ios->tmd + 0x1E4;
    for (uint32_t i = 0; i < ios->numContents; i++) {
        uint32_t cid = Read32BE(tmdContentRecords + (i * 36));
        for (uint32_t j = 0; j < ios->numContents; j++) {
            if (ios->contents[j].cid == cid) {
                uint8_t hash[20];
                SHA1(ios->contents[j].data, ios->contents[j].size, hash);
                memcpy(tmdContentRecords + (i * 36) + 16, hash, 20);
                break;
            }
        }
    }
    
    BruteTmd(ios->tmd, ios->tmdSize);
    
    snprintf(titlePath, sizeof(titlePath), "/vol/slccmpt01/title/00000001/%08x", titleIdLow);
    snprintf(ticketPath, sizeof(ticketPath), "/vol/slccmpt01/ticket/00000001/%08x.tik", titleIdLow);
    snprintf(ticketFolder, sizeof(ticketFolder), "/vol/slccmpt01/ticket/00000001");
    
    D2X_Log("Writing ticket for %u...\n", titleIdLow);
    FSARemove(fsaClient, ticketPath);
    ret = FSAMakeDir(fsaClient, ticketFolder, (FSMode)0x666);
    if (ret == FS_ERROR_OK || ret == FS_ERROR_ALREADY_EXISTS) {
        D2X_TRY(FSAOpenFileEx(fsaClient, ticketPath, "wb", (FSMode)0x666, FS_OPEN_FLAG_NONE, 0, &fd) == FS_ERROR_OK);
        D2X_TRY(FSAWriteFile(fsaClient, ios->ticket, ios->ticketSize, 1, fd, FSA_WRITE_FLAG_NONE) == 1);
        FSACloseFile(fsaClient, fd);
        ret = FS_ERROR_OK;
    }
    D2X_TRY(ret == FS_ERROR_OK);
    
    D2X_Log("Creating title directory...\n");
    ret = FSAMakeDir(fsaClient, titlePath, (FSMode)0x666);
    if (ret == FS_ERROR_ALREADY_EXISTS) {
        snprintf(path, sizeof(path), "/vol/slccmpt01/title/00000001/%08x/content", titleIdLow);
        FSARemove(fsaClient, path);
        ret = FS_ERROR_OK;
    }
    D2X_TRY(ret == FS_ERROR_OK);
    
    strncpy(pathd, titlePath, sizeof(pathd));
    strncat(pathd, "/data", sizeof(pathd) - 1);
    ret = FSAMakeDir(fsaClient, pathd, (FSMode)0x666);
    if (ret != FS_ERROR_OK && ret != FS_ERROR_ALREADY_EXISTS) goto error;
    
    strncpy(pathd, titlePath, sizeof(pathd));
    strncat(pathd, "/content", sizeof(pathd) - 1);
    D2X_TRY(FSAMakeDir(fsaClient, pathd, (FSMode)0x666) == FS_ERROR_OK);
    
    D2X_Log("Writing TMD...\n");
    snprintf(path, sizeof(path), "%s/title.tmd", pathd);
    D2X_TRY(FSAOpenFileEx(fsaClient, path, "wb", (FSMode)0x666, FS_OPEN_FLAG_NONE, 0, &fd) == FS_ERROR_OK);
    D2X_TRY(FSAWriteFile(fsaClient, ios->tmd, ios->tmdSize, 1, fd, FSA_WRITE_FLAG_NONE) == 1);
    FSACloseFile(fsaClient, fd);
    
    D2X_Log("Writing contents...\n");
    for (uint32_t i = 0; i < ios->numContents; i++) {
        snprintf(path, sizeof(path), "%s/%08x.app", pathd, ios->contents[i].cid);
        D2X_TRY(FSAOpenFileEx(fsaClient, path, "wb", (FSMode)0x666, FS_OPEN_FLAG_NONE, 0, &fd) == FS_ERROR_OK);
        D2X_TRY(FSAWriteFile(fsaClient, ios->contents[i].data, ios->contents[i].size, 1, fd, FSA_WRITE_FLAG_NONE) == 1);
        FSACloseFile(fsaClient, fd);
    }
    
    return true;
error:
    FSACloseFile(fsaClient, fd);
    FSARemove(fsaClient, titlePath);
    FSARemove(fsaClient, ticketPath);
    return false;
}

void InstallD2X(const char* versionFolder) {
    char xmlPath[512];
    snprintf(xmlPath, sizeof(xmlPath), "%s/CIOSMAPS.xml", versionFolder);
    
    uint8_t* xmlData = NULL;
    uint32_t xmlSize = 0;
    if (!ReadFileToBuffer(xmlPath, &xmlData, &xmlSize)) {
        D2X_Log("Failed to read CIOSMAPS.xml\n");
        return;
    }
    
    tinyxml2::XMLDocument doc;
    if (doc.Parse((const char*)xmlData, xmlSize) != tinyxml2::XML_SUCCESS) {
        D2X_Log("Failed to parse CIOSMAPS.xml\n");
        free(xmlData);
        return;
    }
    
    WUPI_resetScreen();
    WUPI_putstr("d2x cIOS Installation");
    WUPI_putstr("---------------------");
    WUPI_putstr("The following standard configuration will be installed:");
    WUPI_putstr(" - Slot 249: Base IOS 56");
    WUPI_putstr(" - Slot 250: Base IOS 57");
    WUPI_putstr(" - Slot 251: Base IOS 58");
    WUPI_putstr("");
    WUPI_putstr("Press A to confirm and start installation.");
    WUPI_putstr("Press B to cancel.");
    
    Input input;
    bool confirmed = false;
    while (State::AppRunning()) {
        input.read();
        if (input.get(TRIGGER, PAD_BUTTON_A)) { confirmed = true; break; }
        if (input.get(TRIGGER, PAD_BUTTON_B)) { break; }
        usleep(16000);
    }
    
    if (!confirmed) {
        free(xmlData);
        return;
    }
    
    struct Config { int slot; int base; };
    Config configs[] = { {249, 56}, {250, 57}, {251, 58} };
    
    for (int i = 0; i < 3; i++) {
        WUPI_resetScreen();
        D2X_Log("Installing cIOS slot %d (base %d)...\n", configs[i].slot, configs[i].base);
        
        tinyxml2::XMLElement* root = doc.RootElement();
        tinyxml2::XMLElement* group = root ? root->FirstChildElement("ciosgroup") : NULL;
        tinyxml2::XMLElement* baseEl = NULL;
        if (group) {
            for (tinyxml2::XMLElement* el = group->FirstChildElement("base"); el != NULL; el = el->NextSiblingElement("base")) {
                if (el->IntAttribute("ios") == configs[i].base) {
                    baseEl = el;
                    break;
                }
            }
        }
        
        if (!baseEl) {
            D2X_Log("Could not find configuration in XML.\n");
            sleep(2);
            continue;
        }
        
        MemIOS ios;
        if (!ReadBaseIOS(configs[i].base, &ios)) {
            sleep(2);
            continue;
        }
        
        for (tinyxml2::XMLElement* cEl = baseEl->FirstChildElement("content"); cEl != NULL; cEl = cEl->NextSiblingElement("content")) {
            int tmdModuleId = cEl->IntAttribute("tmdmoduleid", -1);
            int id = cEl->IntAttribute("id", -1);
            const char* moduleAttr = cEl->Attribute("module");
            
            if (moduleAttr && tmdModuleId != -1) {
                AppendModule(&ios, versionFolder, moduleAttr, tmdModuleId);
            } else if (id != -1) {
                MemContent* content = NULL;
                for (uint32_t j = 0; j < ios.numContents; j++) {
                    if (ios.contents[j].cid == (uint32_t)id) {
                        content = &ios.contents[j];
                        break;
                    }
                }
                if (content) {
                    for (tinyxml2::XMLElement* pEl = cEl->FirstChildElement("patch"); pEl != NULL; pEl = pEl->NextSiblingElement("patch")) {
                        int offset = pEl->IntAttribute("offset", 0);
                        const char* orig = pEl->Attribute("originalbytes");
                        const char* newb = pEl->Attribute("newbytes");
                        ApplyBinaryPatch(content, offset, ParseHexBytes(orig), ParseHexBytes(newb));
                    }
                }
            }
        }
        
        if (WritePatchedIOS(configs[i].slot, &ios)) {
            D2X_Log("Successfully installed slot %d.\n", configs[i].slot);
        }
        FreeIOS(&ios);
        sleep(2);
    }
    
    free(xmlData);
    D2X_Log("\nInstallation complete. Press A to return to menu.\n");
    while (State::AppRunning()) {
        input.read();
        if (input.get(TRIGGER, PAD_BUTTON_A)) break;
        usleep(16000);
    }
}
