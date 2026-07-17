/* WAD Installer integration
 *   Copyright (C) 2026
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef WAD_H
#define WAD_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Represents a loaded WAD file and its parsed components
typedef struct {
    uint8_t* rawData;
    size_t size;

    // Header info
    uint32_t certSize;
    uint32_t crlSize;
    uint32_t ticketSize;
    uint32_t tmdSize;
    uint32_t contentSize;
    uint32_t metaSize;

    // Pointers into rawData
    uint8_t* certData;
    uint8_t* crlData;
    uint8_t* ticketData;
    uint8_t* tmdData;
    uint8_t* contentData;
    uint8_t* metaData;

    // Parsed from Ticket
    uint8_t titleKey[16];     // Decrypted title key
    uint64_t ticketTitleId;

    // Parsed from TMD
    uint64_t tmdTitleId;
    uint32_t titleType;       // e.g., 0x00000001 (system), 0x00010001 (channel)
    uint16_t numContents;

    // Decrypted contents buffer (dynamically allocated, must be freed)
    // We decrypt all contents at once into this buffer to simplify writing
    uint8_t* decryptedContentData;

} WADContext;

// Content record in TMD
typedef struct {
    uint32_t contentId;
    uint16_t index;
    uint16_t type;
    uint64_t size;
    uint8_t hash[20];
} WADContentRecord;

// Load a WAD file from SD card, parse it, and decrypt its contents.
// Returns a WADContext if successful, or NULL on failure.
WADContext* WAD_LoadAndDecrypt(const char* filepath);

// Free a WADContext and its associated memory.
void WAD_Free(WADContext* ctx);

// Write the decrypted WAD contents and metadata (TMD/Ticket/Cert) to the slccmpt filesystem.
// Returns true on success, false on failure.
bool WAD_InstallToVWii(WADContext* ctx, int fsaFd);

// Check if the given Title ID is a safe title type (blocks System Menu and critical IOS).
bool WAD_IsSafeTitle(WADContext* ctx);

#ifdef __cplusplus
}
#endif

#endif // WAD_H
