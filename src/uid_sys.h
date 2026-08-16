#pragma once

#include <coreinit/filesystem_fsa.h>
#include <stdint.h>

inline constexpr const char* VWII_UID_SYS_PATH = "/vol/slccmpt01/sys/uid.sys";

// Looks up the UID for a title ID in /sys/uid.sys.
// If not found, allocates a new UID, registers it in /sys/uid.sys, and returns it.
// Guaranteed to reserve UID 0x1000 (4096) for System Menu (00000001/00000002).
uint32_t UID_GetOrCreate(FSAClientHandle fsaClient, uint64_t titleId);
