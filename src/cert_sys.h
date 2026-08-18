#pragma once

#include "FSAUtils.h"
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

inline constexpr const char* VWII_CERT_SYS_PATH = "/vol/slccmpt01/sys/cert.sys";

#ifdef __cplusplus
extern "C" {
#endif

// Inspects certificate data (from WAD or NUS download).
// If /vol/slccmpt01/sys/cert.sys already exists, assumes it is valid and returns true immediately.
// If /vol/slccmpt01/sys/cert.sys is missing, extracts and validates only official retail certificates
// (XS00000003, CA00000001, CP00000004), writes the reconstructed cert.sys with stock ownership/mode,
// and returns true on success.
bool CERT_ImportCerts(FSAClientHandle fsaClient, const void* certData, size_t certSize);

#ifdef __cplusplus
}
#endif
