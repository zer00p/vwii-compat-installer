#ifndef TITLE_H
#define TITLE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Content record in TMD
typedef struct __attribute__((packed)) TitleContentRecord {
    uint32_t contentId;
    uint16_t index;
    uint16_t type;
    uint64_t size;
    uint8_t hash[20];
} TitleContentRecord;

// Complete TMD structure mapping
typedef struct __attribute__((packed)) TitleTmd {
    uint32_t signatureType;      // 0x000
    uint8_t  signature[256];     // 0x004
    uint8_t  padding1[60];       // 0x104
    uint8_t  issuer[64];         // 0x140
    uint8_t  version;            // 0x180
    uint8_t  caCrlVersion;       // 0x181
    uint8_t  signerCrlVersion;   // 0x182
    uint8_t  padding2;           // 0x183
    uint64_t sysVersion;         // 0x184
    uint64_t titleId;            // 0x18C
    uint32_t titleType;          // 0x194
    uint16_t groupId;            // 0x198
    uint8_t  reserved1[58];      // 0x19A
    uint16_t fakeBootIndex;      // 0x1D4 (used for brute forcing)
    uint16_t reserved2;          // 0x1D6
    uint32_t accessRights;       // 0x1D8
    uint16_t titleVersion;       // 0x1DC
    uint16_t numContents;        // 0x1DE
    uint16_t bootIndex;          // 0x1E0
    uint16_t padding3;           // 0x1E2
    TitleContentRecord contents[]; // 0x1E4
} TitleTmd;

// Complete Ticket structure mapping
typedef struct __attribute__((packed)) TitleTicket {
    uint32_t signatureType;      // 0x000
    uint8_t  signature[256];     // 0x004
    uint8_t  padding1[60];       // 0x104
    uint8_t  issuer[64];         // 0x140
    uint8_t  ecdhData[60];       // 0x180
    uint8_t  formatVersion;      // 0x1BC
    uint16_t reserved1;          // 0x1BD
    uint8_t  titleKey[16];       // 0x1BF
    uint8_t  unknown1;           // 0x1CF
    uint64_t ticketId;           // 0x1D0
    uint32_t consoleId;          // 0x1D8
    uint64_t titleId;            // 0x1DC
    uint16_t unknown2;           // 0x1E4
    uint16_t ticketTitleVersion; // 0x1E6
    uint32_t permittedTitlesMask;// 0x1E8
    uint32_t permitMask;         // 0x1EC
    uint8_t  titleExportAllowed; // 0x1F0
    uint8_t  commonKeyIndex;     // 0x1F1
    uint8_t  unknown3[6];        // 0x1F2
    uint16_t padding2;           // 0x1F8 (used for brute forcing)
    uint8_t  unknown4[40];       // 0x1FA
    uint8_t  contentAccess[64];  // 0x222
    uint16_t padding3;           // 0x262
} TitleTicket;

#ifdef __cplusplus
}
#endif

#endif // TITLE_H
