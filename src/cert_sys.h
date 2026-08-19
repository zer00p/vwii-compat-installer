#pragma once

#include "FSAUtils.h"
#include "title.h"
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

inline constexpr const char* VWII_CERT_SYS_PATH = "/vol/slccmpt01/sys/cert.sys";

#ifdef __cplusplus
#include <string>
#include <vector>

struct ParsedCert {
    std::string name;
    std::string issuer;
    uint32_t sigType;
    std::vector<uint8_t> data;
    size_t size;
};

void CERT_ParseCertificates(const uint8_t* data, size_t size, std::vector<ParsedCert>& outCerts);
bool CERT_IsRetailCertificate(const ParsedCert& cert);
bool CERT_VerifyIntegrity(FSAClientHandle fsaClient, std::vector<ParsedCert>& outCerts, std::vector<std::string>& outReasons);
bool CERT_WriteCertificates(FSAClientHandle fsaClient, const void* certData, size_t certSize);
bool CERT_DownloadAndRegenerate(FSAClientHandle fsaClient);

extern "C" {
#endif

// Inspects certificate data (from WAD or NUS download).
// If /vol/slccmpt01/sys/cert.sys already exists and is valid, returns true immediately.
// If /vol/slccmpt01/sys/cert.sys is missing or invalid, extracts and validates official retail certificates
// (XS00000003, CA00000001, CP00000004), writes the reconstructed cert.sys with stock ownership/mode,
// and returns true on success.
bool CERT_ImportCerts(FSAClientHandle fsaClient, const void* certData, size_t certSize);

#ifdef __cplusplus
}
#endif
