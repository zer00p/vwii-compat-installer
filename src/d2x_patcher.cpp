/*
 * d2x_patcher.cpp
 * 
 * The cIOS patching logic (dynamic module injection & XML mapping)
 * in this file is adapted from the d2x-cios-installer project.
 * Original credits go to davebaol, xperia64, blackb0x / wiidev, 
 * and other contributors to the d2x cIOS and patchmii projects.
 *
 * Licensed under the GPLv2.
 */

#include "d2x_patcher.h"
#include "ios_common.h"
#include "installer.h"
#include "tinyxml2.h"
#include "wad.h"
#include "InputUtils.h"
#include "log.h"
#include "MenuUtils.h"
#include "StateUtils.h"
#include "EndianUtils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include <unistd.h>
#include <vector>
#include <string>
#include <memory>

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
        Patcher_Log("Too many contents to append!\n");
        return false;
    }

    std::string path = versionFolder + "/" + moduleName + ".app";

    uint8_t* moduleData = NULL;
    uint32_t moduleSize = 0;

    if (!ReadFileToBuffer(path, &moduleData, &moduleSize)) {
        Patcher_Log("Failed to read module " + path + "\n");
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
        records[idx].contentId = ToBE32(newContentId);
        records[idx].index = ToBE16(idx);
        records[idx].type = ToBE16(1);
        records[idx].size = ToBE64(moduleSize);

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
        records[idx].contentId = ToBE32(newContentId);
        records[idx].index = ToBE16(idx);
        records[idx].type = ToBE16(1);
        records[idx].size = ToBE64(moduleSize);

        uint8_t hash[20];
        SHA1(moduleData, moduleSize, hash);
        memcpy(records[idx].hash, hash, 20);
    }

    // Update numContents in TMD header
    ios.tmd->numContents = ToBE16(ios.numContents);
    ios.tmdSize += sizeof(TitleContentRecord);

    return true;
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
        Patcher_Log("Failed to read ciosmaps.xml\n");
        return;
    }
    
    tinyxml2::XMLDocument doc;
    tinyxml2::XMLError parseResult = doc.Parse((const char*)xmlData, xmlSize);
    free(xmlData);
    if (parseResult != tinyxml2::XML_SUCCESS) {
        Patcher_Log("Failed to parse ciosmaps.xml\n");
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
        Patcher_Log("Installing cIOS slot " + std::to_string(configs[i].slot) + " (base " + std::to_string(configs[i].base) + ")...\n");
        
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
            Patcher_Log("Could not find configuration in XML.\n");
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
                    Patcher_Log("Missing id attribute for content patch in CIOSMAPS.xml\n");
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
                if (!content) {
                    Patcher_Log("Failed to find content ID " + std::to_string(id) + " for patching.\n");
                    failures[selIdx] = true;
                    break;
                }
                
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
                if (patched) {
                    TitleContentRecord* records = ios->tmd->contents;
                    for (uint32_t k = 0; k < ios->numContents; k++) {
                        if (FromBE32(records[k].contentId) == (uint32_t)id) {
                            uint16_t type = FromBE16(records[k].type);
                            if (type & 0x8000) {
                                records[k].type = ToBE16(type & ~0x8000);
                            }
                            uint8_t hash[20];
                            SHA1(content->data, content->size, hash);
                            memcpy(records[k].hash, hash, 20);
                            break;
                        }
                    }
                }
            }
        }
        
        if (!failures[selIdx]) {
            failures[selIdx] = !WritePatchedIOS(configs[i].slot, *ios);
            if(!failures[selIdx])
                Patcher_Log("Successfully installed slot " + std::to_string(configs[i].slot) + ".\n");
        } 
        sleep(2);
    }
    
    WUPI_resetScreen();
    Patcher_Log("Installation process finished.\n\n");
    bool anyFailures = false;
    for (size_t selIdx = 0; selIdx < selected.size(); selIdx++) {
        anyFailures |= failures[selIdx];
    }
    
    if (anyFailures) {
        Patcher_Log("Summary of failures:\n");
        for (size_t selIdx = 0; selIdx < selected.size(); selIdx++) {
            if (failures[selIdx]) {
                int i = selected[selIdx];
                Patcher_Log(" - Failed to install cIOS to slot " + std::to_string(configs[i].slot) + " (base " + std::to_string(configs[i].base) + ")\n");
            }
        }
    } else {
        Patcher_Log("All selected cIOS installed successfully!\n");
    }
}
