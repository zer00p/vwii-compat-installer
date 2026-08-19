#pragma once

#include <coreinit/filesystem_fsa.h>
#include <stdint.h>
#include <stddef.h>

inline constexpr const char* VWII_UID_SYS_PATH = "/vol/slccmpt01/sys/uid.sys";

// System Menu (0000000100000002) constants
inline constexpr uint64_t VWII_TITLE_ID_SYSTEM_MENU = 0x0000000100000002ULL;
inline constexpr uint32_t VWII_UID_SYSTEM_MENU      = 0x1000; // 4096
inline constexpr uint32_t VWII_UID_FIRST_USER       = 0x1001; // 4097
inline constexpr uint16_t VWII_GID_SYSTEM_MENU      = 1;
inline constexpr uint16_t VWII_GID_SYSTEM_TITLE     = 1;
inline constexpr uint16_t VWII_GID_CHANNEL          = 12337; // 0x3031 ('01')
inline constexpr uint16_t VWII_GID_HCVA             = 23130; // 0x5a5a ('ZZ') - Return to Wii U Menu

// Returns the expected Group ID (GID) for a vWii title:
// - 0x0001000248435641 (HCVA - Return to Wii U Menu): 23130 (0x5a5a, 'ZZ')
// - 0x00000001xxxxxxxx (System Menu, IOSes, BC, MIOS): 1
// - All other channels, hidden channels, and disc titles: 12337 (0x3031, '01')
inline constexpr uint16_t UID_GetTitleGid(uint64_t titleId) {
    if (titleId == 0x0001000248435641ULL) {
        return VWII_GID_HCVA;
    }
    uint32_t idHi = (uint32_t)(titleId >> 32);
    if (idHi == 0x00000001) {
        return VWII_GID_SYSTEM_TITLE;
    }
    return VWII_GID_CHANNEL;
}

struct __attribute__((packed)) RawUidEntry {
    uint64_t titleId;
    uint32_t uid;
};
static_assert(sizeof(RawUidEntry) == 12, "RawUidEntry must be exactly 12 bytes");

// Checks if a UID is within the valid range for a vWii title.
// Valid vWii UIDs are >= 0x1000 (4096), < 0x10000000, and != 0x10050000 (Cafe OS default).
inline bool UID_IsValidVwiiUid(uint32_t uid) {
    return (uid >= VWII_UID_SYSTEM_MENU && uid < 0x10000000 && uid != 0x10050000);
}

// Reconstructs /sys/uid.sys by scanning all existing title directories on SLCCMPT
// for /data directory ownership (stat.owner), merging with any existing readable uid.sys entries.
// outRecoveredCount receives the number of title mappings registered.
bool UID_Reconstruct(FSAClientHandle fsaClient, size_t* outRecoveredCount = nullptr);

// Looks up the UID for a title ID in /sys/uid.sys.
// If not found, attempts to recover an existing valid UID from /data directory ownership,
// or allocates a new UID, registers it in /sys/uid.sys, and returns it.
// Guaranteed to reserve UID 0x1000 (4096) for System Menu (00000001/00000002).
uint32_t UID_GetOrCreate(FSAClientHandle fsaClient, uint64_t titleId);
