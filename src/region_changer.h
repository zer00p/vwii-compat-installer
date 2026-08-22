/* region_changer.h
 *   vWii Region Change Wizard & Shared Content Management
 */

#pragma once

#include <stdint.h>
#include <array>
#include <string>
#include <vector>
#include <coreinit/filesystem_fsa.h>

using Sha1Hash = std::array<uint8_t, 20>;

struct KnownRegionSharedContent {
    const char* region;      // "USA", "EUR", "JPN"
    const char* description; // e.g. "System Menu USA Font Table"
    Sha1Hash hash;
    uint32_t expectedSize;
};

struct OrphanSharedContent {
    int32_t mapIndex;
    std::string name;
    std::string filePath;
    std::string description;
    std::string region;
    Sha1Hash hash;
    uint64_t fileSize;
};

struct OldRegionTitle {
    uint64_t titleId;
    std::string name;
    std::string region;
};

// Scans for installed foreign/old region system titles (Manual, Region Select, System Transfer)
std::vector<OldRegionTitle> GetInstalledOldRegionTitles(const std::string& targetRegion);

// Interactive Wizard entry point
void RegionChange_RunWizard();

// Scans all installed title TMDs and checks content.map for unreferenced known region-specific shared content
std::vector<OrphanSharedContent> SharedContent_ScanRegionOrphans(FSAClientHandle fsaClient, const std::string& targetRegion);

// Deletes orphaned shared .app files and zeroes their entries in content.map
bool SharedContent_CleanRegionOrphans(FSAClientHandle fsaClient, const std::vector<OrphanSharedContent>& orphans);
