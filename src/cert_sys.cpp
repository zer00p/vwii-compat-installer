#include "cert_sys.h"
#include "EndianUtils.h"
#include "log.h"
#include <malloc.h>
#include <string.h>
#include <string>
#include <vector>

struct ParsedCert {
    std::string name;
    std::string issuer;
    uint32_t sigType;
    const uint8_t* data;
    size_t size;
};

static bool IsRetailCertificate(const ParsedCert& cert) {
    if (cert.name == "XS00000003" && cert.issuer == "Root-CA00000001" &&
        cert.sigType == 0x00010001 && cert.size == 0x300) {
        return true;
    }
    if (cert.name == "CA00000001" && cert.issuer == "Root" &&
        cert.sigType == 0x00010000 && cert.size == 0x400) {
        return true;
    }
    if (cert.name == "CP00000004" && cert.issuer == "Root-CA00000001" &&
        cert.sigType == 0x00010001 && cert.size == 0x300) {
        return true;
    }
    return false;
}

static void ParseCertificates(const uint8_t* data, size_t size, std::vector<ParsedCert>& outCerts) {
    if (!data || size < 4) return;

    size_t pos = 0;
    while (pos + 4 <= size) {
        uint32_t sigType = Read32BE(data + pos);
        size_t certLen = 0;
        size_t issuerOffset = 0;
        size_t nameOffset = 0;

        if (sigType == 0x00010000) {
            // RSA-4096 signature: 0x200 sig + 0x3c fill = 0x23c
            certLen = 0x400;
            issuerOffset = pos + 4 + 0x200 + 0x3c; // 0x240
            nameOffset = issuerOffset + 0x40 + 4;  // 0x284
        } else if (sigType == 0x00010001) {
            // RSA-2048 signature: 0x100 sig + 0x3c fill = 0x13c
            certLen = 0x300;
            issuerOffset = pos + 4 + 0x100 + 0x3c; // 0x140
            nameOffset = issuerOffset + 0x40 + 4;  // 0x184
        } else {
            // Unknown or unsupported signature type
            break;
        }

        if (pos + certLen > size) {
            break;
        }

        char issuerBuf[65] = {0};
        char nameBuf[65] = {0};
        memcpy(issuerBuf, data + issuerOffset, 64);
        memcpy(nameBuf, data + nameOffset, 64);

        ParsedCert cert;
        cert.name = std::string(nameBuf);
        cert.issuer = std::string(issuerBuf);
        cert.sigType = sigType;
        cert.data = data + pos;
        cert.size = certLen;

        outCerts.push_back(cert);
        pos += certLen;
    }
}

bool CERT_ImportCerts(FSAClientHandle fsaClient, const void* certData, size_t certSize) {
    if (!certData || certSize == 0) {
        return true;
    }

    // Check if /vol/slccmpt01/sys/cert.sys already exists.
    // If it exists, assume it is correct and skip.
    FSStat stat;
    if (FSAGetStat(fsaClient, VWII_CERT_SYS_PATH, &stat) == FS_ERROR_OK && stat.size > 0) {
        return true;
    }

    WUPI_Log("CERT: %s missing, recovering from title certificates...\n", VWII_CERT_SYS_PATH);

    std::vector<ParsedCert> incomingCerts;
    ParseCertificates((const uint8_t*)certData, certSize, incomingCerts);

    const ParsedCert* xsCert = nullptr;
    const ParsedCert* caCert = nullptr;
    const ParsedCert* cpCert = nullptr;

    for (const auto& cert : incomingCerts) {
        if (!IsRetailCertificate(cert)) {
            WUPI_Log("CERT: Ignoring non-retail cert '%s' (issuer '%s')\n",
                     cert.name.c_str(), cert.issuer.c_str());
            continue;
        }

        if (cert.name == "XS00000003" && !xsCert) {
            xsCert = &cert;
        } else if (cert.name == "CA00000001" && !caCert) {
            caCert = &cert;
        } else if (cert.name == "CP00000004" && !cpCert) {
            cpCert = &cert;
        }
    }

    size_t totalSize = 0;
    if (xsCert) totalSize += xsCert->size;
    if (caCert) totalSize += caCert->size;
    if (cpCert) totalSize += cpCert->size;

    if (totalSize == 0) {
        WUPI_Log("CERT: No valid retail certificates found in input\n");
        return false;
    }

    uint8_t* alignBuf = (uint8_t*)memalign(0x40, totalSize);
    if (!alignBuf) {
        WUPI_Log("CERT: Failed to allocate aligned buffer\n");
        return false;
    }

    size_t outPos = 0;
    if (xsCert) {
        memcpy(alignBuf + outPos, xsCert->data, xsCert->size);
        outPos += xsCert->size;
    }
    if (caCert) {
        memcpy(alignBuf + outPos, caCert->data, caCert->size);
        outPos += caCert->size;
    }
    if (cpCert) {
        memcpy(alignBuf + outPos, cpCert->data, cpCert->size);
        outPos += cpCert->size;
    }

    EnsureFSADir(fsaClient, "/vol/slccmpt01/sys");

    bool ok = FSACreateFileWithOwner(fsaClient, VWII_CERT_SYS_PATH, alignBuf, totalSize,
                                     STOCK_MODE_SYSTEM_FILE, 0, 0);
    free(alignBuf);

    if (ok) {
        WUPI_Log("CERT: Successfully reconstructed %s (%zu bytes)\n", VWII_CERT_SYS_PATH, totalSize);
    } else {
        WUPI_Log("CERT: Failed to create %s\n", VWII_CERT_SYS_PATH);
    }

    return ok;
}
