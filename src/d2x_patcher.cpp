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
#include "log.h"
#include "MenuUtils.h"
#include "StateUtils.h"
#include <coreinit/filesystem_fsa.h>
#include <coreinit/screen.h>
#include <mbedtls/sha1.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include "EndianUtils.h"
#include <unistd.h>
#include <vector>
#include <string>
#include <memory>

extern "C" {
#include "wad_tools/tools.h"
}

static uint8_t common_key[16] = {
    0xeb, 0xe4, 0x2a, 0x22, 0x5e, 0x85, 0x93, 0xe4,
    0x48, 0xd9, 0xc5, 0x45, 0x73, 0x81, 0xaa, 0xf7
};

extern FSAClientHandle fsaClient;
#include "log.h"
#include <sstream>
#include <iomanip>

static inline void D2X_Log(const std::string& msg) {
    WUPI_putstr(msg.c_str());
}

static inline std::string ToHexString(uint32_t val, int width = 8) {
    std::stringstream ss;
    ss << std::setfill('0') << std::setw(width) << std::hex << val;
    return ss.str();
}


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
    TitleTmd* tmd = nullptr;
    uint32_t tmdSize = 0;
    TitleTicket* ticket = nullptr;
    uint32_t ticketSize = 0;
    MemContent* contents = nullptr;
    uint32_t numContents = 0;
    uint32_t maxContents = 0;

    ~MemIOS() {
        if (tmd) free(tmd);
        if (ticket) free(ticket);
        if (contents) {
            for (uint32_t i = 0; i < numContents; i++) {
                if (contents[i].data) free(contents[i].data);
            }
            free(contents);
        }
    }

    MemIOS() = default;
    MemIOS(const MemIOS&) = delete;
    MemIOS& operator=(const MemIOS&) = delete;
};

static bool ReadFileToBuffer(const std::string& path, uint8_t** outBuf, uint32_t* outSize) {
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

static std::unique_ptr<MemIOS> ReadBaseIOS(uint32_t baseIos) {
    auto outIos = std::unique_ptr<MemIOS>(new MemIOS());
    // Read Ticket
    std::string path = "/vol/slccmpt01/ticket/00000001/" + ToHexString(baseIos, 8) + ".tik";
    uint8_t* tikBuf = nullptr;
    if (!ReadFileToBuffer(path, &tikBuf, &outIos->ticketSize)) {
        D2X_Log("Failed to read ticket for base IOS " + std::to_string(baseIos) + "\n");
        return nullptr;
    }
    outIos->ticket = (TitleTicket*)tikBuf;
    
    // Read TMD
    path = "/vol/slccmpt01/title/00000001/" + ToHexString(baseIos, 8) + "/content/title.tmd";
    uint8_t* tmdBuf = nullptr;
    if (!ReadFileToBuffer(path, &tmdBuf, &outIos->tmdSize)) {
        D2X_Log("Failed to read TMD for base IOS " + std::to_string(baseIos) + "\n");
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
        D2X_Log("Failed to reallocate TMD buffer\n");
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
                D2X_Log("Failed to find shared content for cid " + ToHexString(cid, 8) + "\n");
                return nullptr;
            }
            path = "/vol/slccmpt01/shared1/" + ToHexString(sharedIndex, 8) + ".app";
        } else {
            path = "/vol/slccmpt01/title/00000001/" + ToHexString(baseIos, 8) + "/content/" + ToHexString(cid, 8) + ".app";
        }

        if (!ReadFileToBuffer(path, &outIos->contents[i].data, &outIos->contents[i].size)) {
            D2X_Log("Failed to read content " + ToHexString(cid, 8) + ".app\n");
            return nullptr;
        }
    }
    
    return outIos;
}

#include <vector>
#include <string>

static std::vector<uint8_t> ParseHexBytes(const std::string& str) {
    std::vector<uint8_t> bytes;
    if (str.empty()) return bytes;
    std::string s = str;
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

static bool ApplyBinaryPatch(MemContent* content, int32_t offset, const std::vector<uint8_t>& origBytes, const std::vector<uint8_t>& newBytes) {
    if (origBytes.empty() || newBytes.empty()) return false;
    if (offset < 0 || (uint32_t)offset + origBytes.size() > content->size) return false;
    if ((uint32_t)offset + newBytes.size() > content->size) return false;
    
    if (memcmp(content->data + offset, origBytes.data(), origBytes.size()) == 0) {
        memcpy(content->data + offset, newBytes.data(), newBytes.size());
        return true;
    }
    
    return false;
}

static bool AppendModule(MemIOS& ios, const std::string& versionFolder, const std::string& moduleName, int tmdModuleId) {

    if (ios.numContents >= ios.maxContents) {
        D2X_Log("Too many contents to append!\n");
        return false;
    }

    std::string path = versionFolder + "/" + moduleName + ".app";

    uint8_t* moduleData = NULL;
    uint32_t moduleSize = 0;

    if (!ReadFileToBuffer(path, &moduleData, &moduleSize)) {
        D2X_Log("Failed to read module " + path + "\n");
        return false;
    }

    uint32_t maxCid = 0;
    for (uint32_t i = 0; i < ios.numContents; i++) {
        if (ios.contents[i].cid > maxCid) {
            maxCid = ios.contents[i].cid;
        }
    }
    uint32_t newContentId = maxCid + 1;

    // Update TMD record
    TitleContentRecord* records = ios.tmd->contents;

    if (tmdModuleId != -1) {
        // Move original content to end
        uint32_t oldIdx = ios.numContents++;
        ios.contents[oldIdx] = ios.contents[tmdModuleId];

        // Put new module at tmdModuleId
        uint32_t idx = tmdModuleId;
        ios.contents[idx].cid = newContentId;
        ios.contents[idx].size = moduleSize;
        ios.contents[idx].data = moduleData;

        // Copy original TMD record to end and update its index
        records[oldIdx] = records[tmdModuleId];
        records[oldIdx].index = ToBE16(oldIdx);

        // Overwrite tmdModuleId TMD record for the new module
        memset(&records[idx], 0, sizeof(TitleContentRecord));
        records[idx].contentId = ToBE32(newContentId); // CID
        records[idx].index = ToBE16(idx); // Index
        records[idx].type = ToBE16(1); // Type = normal
        records[idx].size = ToBE64(moduleSize); // Exact Size

        uint8_t hash[20];
        SHA1(moduleData, moduleSize, hash);
        memcpy(records[idx].hash, hash, 20);
    } else {
        // Just append new content
        uint32_t idx = ios.numContents++;
        ios.contents[idx].cid = newContentId;
        ios.contents[idx].size = moduleSize;
        ios.contents[idx].data = moduleData;

        memset(&records[idx], 0, sizeof(TitleContentRecord));
        records[idx].contentId = ToBE32(newContentId); // CID
        records[idx].index = ToBE16(idx); // Index
        records[idx].type = ToBE16(1); // Type = normal
        records[idx].size = ToBE64(moduleSize); // Exact Size

        uint8_t hash[20];
        SHA1(moduleData, moduleSize, hash);
        memcpy(records[idx].hash, hash, 20);
    }

    // Update numContents in TMD header
    ios.tmd->numContents = ToBE16(ios.numContents);
    ios.tmdSize += sizeof(TitleContentRecord);

    return true;
}

static void BruteTmd(TitleTmd* tmd, uint32_t size) {
    uint8_t hash[20];
    for (uint32_t fill = 0; fill < 65535; fill++) {
        tmd->fakeBootIndex = fill; // Reserved field instead of boot_index
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


static bool WritePatchedIOS(uint32_t titleIdLow, MemIOS& ios) {
    // No local path or fd variables needed anymore
    
    // Forge Ticket
    if (ios.ticketSize >= sizeof(TitleTicket)) {
        memset(ios.ticket->signature, 0, sizeof(ios.ticket->signature)); // Zero out signature
        
        // Decrypt Title Key using old Title ID as IV
        uint8_t titleKey[16];
        uint8_t iv[16] = {0};
        memcpy(iv, &ios.ticket->titleId, 8); // Old Title ID
        aes_cbc_dec(common_key, iv, ios.ticket->titleKey, 16, titleKey);
        
        // Write new Title ID
        ios.ticket->titleId = ToBE64(((uint64_t)1 << 32) | titleIdLow);
        
        // Re-encrypt Title Key using new Title ID as IV
        memset(iv, 0, 16);
        memcpy(iv, &ios.ticket->titleId, 8); // New Title ID
        aes_cbc_enc(common_key, iv, titleKey, 16, ios.ticket->titleKey);
        
        BruteTicket(ios.ticket, ios.ticketSize);
    } else {
        D2X_Log("Ticket size too small\n");
        return false;
    }
    
    // Forge TMD
    if (ios.tmdSize >= offsetof(TitleTmd, contents) && ios.numContents > 0) {
        memset(ios.tmd->signature, 0, sizeof(ios.tmd->signature)); // Zero out signature
        ios.tmd->titleId = ToBE64(((uint64_t)1 << 32) | titleIdLow); // System Title High & Low
        ios.tmd->titleVersion = ToBE16(0xFFFF); // Patch Title Version
    } else {
        D2X_Log("TMD size too small\n");
        return false;
    }
    
    // Recalculate content hashes
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

void InstallD2X(const std::string& versionFolder) {
    std::string parentDir = versionFolder;
    size_t lastSlash = parentDir.find_last_of('/');
    if (lastSlash != std::string::npos) {
        parentDir = parentDir.substr(0, lastSlash);
    }
    
    std::string xmlPath = parentDir + "/ciosmaps.xml";
    
    uint8_t* xmlData = NULL;
    uint32_t xmlSize = 0;
    if (!ReadFileToBuffer(xmlPath, &xmlData, &xmlSize)) {
        D2X_Log("Failed to read ciosmaps.xml\n");
        return;
    }
    
    tinyxml2::XMLDocument doc;
    tinyxml2::XMLError parseResult = doc.Parse((const char*)xmlData, xmlSize);
    free(xmlData);
    if (parseResult != tinyxml2::XML_SUCCESS) {
        D2X_Log("Failed to parse ciosmaps.xml\n");
        return;
    }
    
    struct Config { int slot; int base; };
    std::vector<Config> configs = {
        {248, 38},
        {249, 56},
        {250, 57},
        {251, 58}
    };
    
    std::vector<std::string> header = {
        "Select d2x cIOS configurations to install:"
    };
    std::vector<std::string> options;
    for (const auto& config : configs) {
        options.push_back("Slot " + std::to_string(config.slot) + " (Base IOS " + std::to_string(config.base) + ")");
    }
    
    std::vector<int> selected = ShowMultiSelectMenu(header, options, true);
    if (selected.empty()) {
        return;
    }
    
    std::vector<bool> failures(selected.size(), false);
    
    for (size_t selIdx = 0; selIdx < selected.size(); selIdx++) {
        int i = selected[selIdx];
        if (!State::AppRunning()) break;
        WUPI_resetScreen();
        D2X_Log("Installing cIOS slot " + std::to_string(configs[i].slot) + " (base " + std::to_string(configs[i].base) + ")...\n");
        
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
            failures[selIdx] = true;
            sleep(2);
            continue;
        }
        
        auto ios = ReadBaseIOS(configs[i].base);
        if (!ios) {
            failures[selIdx] = true;
            sleep(2);
            continue;
        }
        
        for (tinyxml2::XMLElement* cEl = baseEl->FirstChildElement("content"); cEl != NULL; cEl = cEl->NextSiblingElement("content")) {
            int tmdModuleId = cEl->IntAttribute("tmdmoduleid", -1);
            int id = cEl->IntAttribute("id", -1);
            const char* moduleAttr = cEl->Attribute("module");
            
            if (moduleAttr) {
                AppendModule(*ios, versionFolder, moduleAttr, tmdModuleId);
            } else {
                if (id == -1) {
                    D2X_Log("Missing id attribute for content patch in CIOSMAPS.xml\n");
                    failures[selIdx] = true;
                    break;
                }
                MemContent* content = NULL;
                for (uint32_t j = 0; j < ios->numContents; j++) {
                    if (ios->contents[j].cid == (uint32_t)id) {
                        content = &ios->contents[j];
                        break;
                    }
                }
                if (content) {
                    bool patched = false;
                    for (tinyxml2::XMLElement* pEl = cEl->FirstChildElement("patch"); pEl != NULL; pEl = pEl->NextSiblingElement("patch")) {
                        int offset = pEl->IntAttribute("offset", 0);
                        const char* orig = pEl->Attribute("originalbytes");
                        const char* newb = pEl->Attribute("newbytes");
                        if (orig && newb) {
                            if (ApplyBinaryPatch(content, offset, ParseHexBytes(orig), ParseHexBytes(newb)))
                                patched = true;
                        }
                    }
                    // If we patched a shared content, change its type to normal
                    // so the IOS kernel loads it from the title directory
                    // instead of the (unpatched) shared content store.
                    if (patched) {
                        TitleContentRecord* records = ios->tmd->contents;
                        for (uint32_t k = 0; k < ios->numContents; k++) {
                            if (FromBE32(records[k].contentId) == (uint32_t)id) {
                                uint16_t type = FromBE16(records[k].type);
                                if (type & 0x8000) {
                                    records[k].type = ToBE16(type & ~0x8000);
                                }
                                break;
                            }
                        }
                    }
                }
            }
        }
        
        if (!failures[selIdx]) {
            failures[selIdx] = !WritePatchedIOS(configs[i].slot, *ios);
            if(!failures[selIdx])
                D2X_Log("Successfully installed slot " + std::to_string(configs[i].slot) + ".\n");
        } 
        sleep(2);
    }
    
    WUPI_resetScreen();
    D2X_Log("Installation process finished.\n\n");
    bool anyFailures = false;
    for (size_t selIdx = 0; selIdx < selected.size(); selIdx++) {
        anyFailures |= failures[selIdx];
    }
    
    if (anyFailures) {
        D2X_Log("Summary of failures:\n");
        for (size_t selIdx = 0; selIdx < selected.size(); selIdx++) {
            if (failures[selIdx]) {
                int i = selected[selIdx];
                D2X_Log(" - Failed to install cIOS to slot " + std::to_string(configs[i].slot) + " (base " + std::to_string(configs[i].base) + ")\n");
            }
        }
    } else {
        D2X_Log("All selected cIOS installed successfully!\n");
    }
}
