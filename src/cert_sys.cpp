#include "cert_sys.h"
#include "EndianUtils.h"
#include "downloader.h"
#include "log.h"
#include <malloc.h>
#include <string.h>
#include <string>
#include <vector>
#include <format>

bool CERT_IsRetailCertificate(const ParsedCert& cert) {
    if (cert.name == "XS00000003" && cert.issuer == "Root-CA00000001" &&
        cert.sigType == CERT_SIG_RSA2048 && cert.size == sizeof(CertRsa2048)) {
        return true;
    }
    if (cert.name == "CA00000001" && cert.issuer == "Root" &&
        cert.sigType == CERT_SIG_RSA4096 && cert.size == sizeof(CertRsa4096Rsa2048)) {
        return true;
    }
    if (cert.name == "CP00000004" && cert.issuer == "Root-CA00000001" &&
        cert.sigType == CERT_SIG_RSA2048 && cert.size == sizeof(CertRsa2048)) {
        return true;
    }
    return false;
}

void CERT_ParseCertificates(const uint8_t* data, size_t size, std::vector<ParsedCert>& outCerts) {
    if (!data || size < 4) return;

    size_t pos = 0;
    while (pos + 4 <= size) {
        uint32_t sigType = Read32BE(data + pos);
        size_t certLen = 0;
        std::string issuer;
        std::string name;

        if (sigType == CERT_SIG_RSA4096) {
            certLen = sizeof(CertRsa4096Rsa2048);
            if (pos + certLen > size) {
                break;
            }
            const auto* cert = reinterpret_cast<const CertRsa4096Rsa2048*>(data + pos);
            char issuerBuf[sizeof(cert->issuer) + 1] = {0};
            char nameBuf[sizeof(cert->name) + 1] = {0};
            memcpy(issuerBuf, cert->issuer, sizeof(cert->issuer));
            memcpy(nameBuf, cert->name, sizeof(cert->name));
            issuer = issuerBuf;
            name = nameBuf;
        } else if (sigType == CERT_SIG_RSA2048) {
            certLen = sizeof(CertRsa2048);
            if (pos + certLen > size) {
                break;
            }
            const auto* cert = reinterpret_cast<const CertRsa2048*>(data + pos);
            char issuerBuf[sizeof(cert->issuer) + 1] = {0};
            char nameBuf[sizeof(cert->name) + 1] = {0};
            memcpy(issuerBuf, cert->issuer, sizeof(cert->issuer));
            memcpy(nameBuf, cert->name, sizeof(cert->name));
            issuer = issuerBuf;
            name = nameBuf;
        } else {
            // Unknown or unsupported signature type
            break;
        }

        ParsedCert cert;
        cert.name = std::move(name);
        cert.issuer = std::move(issuer);
        cert.sigType = sigType;
        cert.data.assign(data + pos, data + pos + certLen);
        cert.size = certLen;

        outCerts.push_back(std::move(cert));
        pos += certLen;
    }
}

bool CERT_VerifyIntegrity(FSAClientHandle fsaClient, std::vector<ParsedCert>& outCerts, std::vector<std::string>& outReasons) {
    outCerts.clear();
    outReasons.clear();

    FSStat stat;
    if (FSAGetStat(fsaClient, VWII_CERT_SYS_PATH, &stat) != FS_ERROR_OK) {
        outReasons.push_back("File /sys/cert.sys is missing");
        return false;
    }

    if (!FSA_IsPermissionAcceptable(stat, STOCK_MODE_CERT_SYS, 0, 0)) {
        outReasons.push_back(std::format("Perms {}/{}/{:x} incorrect on /sys/cert.sys",
                                         (uint32_t)stat.owner, (uint32_t)stat.group, (uint32_t)(stat.mode & 0x666)));
    }

    constexpr size_t minCertSysSize = sizeof(CertRsa4096Rsa2048) + (2 * sizeof(CertRsa2048)); // 0x400 + 2 * 0x300 = 2560 bytes
    if (stat.size < minCertSysSize) {
        outReasons.push_back(std::format("File truncated (size {} < {} bytes)", (uint32_t)stat.size, minCertSysSize));
        return false;
    }

    uint8_t* buf = nullptr;
    uint32_t size = 0;
    if (!ReadFileToBuffer(VWII_CERT_SYS_PATH, &buf, &size) || !buf) {
        outReasons.push_back("Failed to read file contents");
        return false;
    }

    std::vector<ParsedCert> parsed;
    CERT_ParseCertificates(buf, size, parsed);

    bool hasXS = false;
    bool hasCA = false;
    bool hasCP = false;

    for (const auto& c : parsed) {
        if (CERT_IsRetailCertificate(c)) {
            if (c.name == "XS00000003") hasXS = true;
            else if (c.name == "CA00000001") hasCA = true;
            else if (c.name == "CP00000004") hasCP = true;
        }
    }

    if (!hasXS) outReasons.push_back("Missing XS00000003 ticket signer certificate");
    if (!hasCA) outReasons.push_back("Missing CA00000001 certification authority");
    if (!hasCP) outReasons.push_back("Missing CP00000004 content provider certificate");

    if (hasXS && hasCA && hasCP) {
        outCerts = std::move(parsed);
    }

    free(buf);
    return outReasons.empty();
}

bool CERT_WriteCertificates(FSAClientHandle fsaClient, const void* certData, size_t certSize) {
    if (!certData || certSize == 0) {
        return false;
    }

    std::vector<ParsedCert> incomingCerts;
    CERT_ParseCertificates((const uint8_t*)certData, certSize, incomingCerts);

    const ParsedCert* xsCert = nullptr;
    const ParsedCert* caCert = nullptr;
    const ParsedCert* cpCert = nullptr;

    for (const auto& cert : incomingCerts) {
        if (!CERT_IsRetailCertificate(cert)) {
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

    if (!xsCert || !caCert || !cpCert) {
        WUPI_Log("CERT: Incomplete retail certificates in input (XS:%d CA:%d CP:%d)\n",
                 xsCert != nullptr, caCert != nullptr, cpCert != nullptr);
        return false;
    }

    size_t totalSize = xsCert->size + caCert->size + cpCert->size;
    uint8_t* alignBuf = (uint8_t*)memalign(0x40, totalSize);
    if (!alignBuf) {
        WUPI_Log("CERT: Failed to allocate aligned buffer\n");
        return false;
    }

    size_t outPos = 0;
    memcpy(alignBuf + outPos, xsCert->data.data(), xsCert->size);
    outPos += xsCert->size;
    memcpy(alignBuf + outPos, caCert->data.data(), caCert->size);
    outPos += caCert->size;
    memcpy(alignBuf + outPos, cpCert->data.data(), cpCert->size);
    outPos += cpCert->size;

    EnsureFSADir(fsaClient, "/vol/slccmpt01/sys");

    bool ok = FSACreateFileWithOwner(fsaClient, VWII_CERT_SYS_PATH, alignBuf, totalSize,
                                     STOCK_MODE_CERT_SYS, 0, 0);
    free(alignBuf);

    if (ok) {
        WUPI_Log("CERT: Successfully wrote %s (%zu bytes)\n", VWII_CERT_SYS_PATH, totalSize);
    } else {
        WUPI_Log("CERT: Failed to write %s\n", VWII_CERT_SYS_PATH);
    }

    return ok;
}

bool CERT_DownloadAndRegenerate(FSAClientHandle fsaClient) {
    WUPI_Log("Downloading certificate chain from NUS...\n");

    uint8_t* cetkData = nullptr;
    size_t cetkSize = 0;
    std::string cetkUrl = "http://nus.cdn.shop.wii.com/ccs/download/0000000700000002/cetk";
    if (DownloadToMemory(cetkUrl, &cetkData, &cetkSize) != DownloadResult::SUCCESS || !cetkData || cetkSize < sizeof(TitleTicket)) {
        WUPI_Log("Failed to download cetk from NUS.\n");
        if (cetkData) free(cetkData);
        return false;
    }

    uint8_t* tmdData = nullptr;
    size_t tmdSize = 0;
    std::string tmdUrl = "http://nus.cdn.shop.wii.com/ccs/download/0000000700000002/tmd";
    if (DownloadToMemory(tmdUrl, &tmdData, &tmdSize) != DownloadResult::SUCCESS || !tmdData || tmdSize < sizeof(TitleTmd)) {
        WUPI_Log("Failed to download tmd from NUS.\n");
        free(cetkData);
        if (tmdData) free(tmdData);
        return false;
    }

    std::vector<uint8_t> combinedCerts;

    // Extract certs from cetk
    size_t requiredTikSize = sizeof(TitleTicket);
    if (cetkSize > requiredTikSize) {
        combinedCerts.insert(combinedCerts.end(), cetkData + requiredTikSize, cetkData + cetkSize);
    }

    // Extract certs from tmd
    const auto* tmd = reinterpret_cast<const TitleTmd*>(tmdData);
    uint16_t numContents = FromBE16(tmd->numContents);
    size_t requiredTmdSize = sizeof(TitleTmd) + (numContents * sizeof(TitleContentRecord));
    if (tmdSize > requiredTmdSize) {
        combinedCerts.insert(combinedCerts.end(), tmdData + requiredTmdSize, tmdData + tmdSize);
    }

    free(cetkData);
    free(tmdData);

    if (combinedCerts.empty()) {
        WUPI_Log("Failed to extract certificate stream from NUS files.\n");
        return false;
    }

    return CERT_WriteCertificates(fsaClient, combinedCerts.data(), combinedCerts.size());
}

bool CERT_RestoreOrRegenerate(FSAClientHandle fsaClient) {
    // 1. Try local repair: if valid certificates exist on disk, rewrite with correct ownership and permissions
    uint8_t* existingBuf = nullptr;
    uint32_t existingSize = 0;
    if (ReadFileToBuffer(VWII_CERT_SYS_PATH, &existingBuf, &existingSize) && existingBuf) {
        bool ok = CERT_WriteCertificates(fsaClient, existingBuf, existingSize);
        free(existingBuf);
        if (ok) {
            return true;
        }
    }

    // 2. Fall back to downloading and regenerating from NUS
    return CERT_DownloadAndRegenerate(fsaClient);
}

bool CERT_ImportCerts(FSAClientHandle fsaClient, const void* certData, size_t certSize) {
    if (!certData || certSize == 0) {
        return true;
    }

    // Check if /vol/slccmpt01/sys/cert.sys already exists and is healthy
    std::vector<ParsedCert> existingCerts;
    std::vector<std::string> reasons;
    if (CERT_VerifyIntegrity(fsaClient, existingCerts, reasons)) {
        return true;
    }

    WUPI_Log("CERT: %s missing/invalid, recovering from title certificates...\n", VWII_CERT_SYS_PATH);
    return CERT_WriteCertificates(fsaClient, certData, certSize);
}

