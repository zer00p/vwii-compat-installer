#include "uid_sys.h"
#include "FSAUtils.h"
#include "log.h"

#include <stdlib.h>
#include <string.h>
#include <malloc.h>

struct __attribute__((packed)) RawUidEntry {
    uint64_t titleId;
    uint32_t uid;
};
static_assert(sizeof(RawUidEntry) == 12, "RawUidEntry must be exactly 12 bytes");

uint32_t UID_GetOrCreate(FSAClientHandle fsaClient, uint64_t titleId) {
    FSAFileHandle fd = 0;
    int openRes = FSAOpenFileEx(fsaClient, VWII_UID_SYS_PATH, "r+", STOCK_MODE_SYSTEM_FILE, FS_OPEN_FLAG_NONE, 0, &fd);

    // If uid.sys doesn't exist, create it with System Menu (UID 0x1000) and stock ownership
    if (openRes == FS_ERROR_NOT_FOUND) {
        EnsureFSADir(fsaClient, "/vol/slccmpt01/sys");

        RawUidEntry* writeBuf = (RawUidEntry*)memalign(0x40, 0x40);
        if (!writeBuf) return 0;
        memset(writeBuf, 0, 0x40);

        // Entry 0: System Menu (0000000100000002, UID 0x1000)
        writeBuf[0] = { 0x0000000100000002ULL, 0x1000 };

        if (titleId == 0x0000000100000002ULL) {
            FSACreateFileWithOwner(fsaClient, VWII_UID_SYS_PATH, writeBuf, sizeof(RawUidEntry), STOCK_MODE_SYSTEM_FILE, 0, 0);
            free(writeBuf);
            return 0x1000;
        }

        // Entry 1: New Title (UID 0x1001)
        writeBuf[1] = { titleId, 0x1001 };
        bool ok = FSACreateFileWithOwner(fsaClient, VWII_UID_SYS_PATH, writeBuf, 2 * sizeof(RawUidEntry), STOCK_MODE_SYSTEM_FILE, 0, 0);
        free(writeBuf);

        WUPI_Log("UID (created): %08x/%08x -> 4097 (%s)\n",
                 (uint32_t)(titleId >> 32), (uint32_t)(titleId & 0xFFFFFFFF), ok ? "OK" : "FAIL");
        return 0x1001;
    }

    if (openRes != FS_ERROR_OK) {
        WUPI_Log("UID: Failed to open %s (%d)\n", VWII_UID_SYS_PATH, openRes);
        return 0;
    }

    // uid.sys exists and is open in "r+"
    uint32_t maxUid = 0x1000;
    bool found = false;
    uint32_t foundUid = 0;
    size_t entryCount = 0;

    RawUidEntry* entry = (RawUidEntry*)memalign(0x40, 0x40);
    if (!entry) {
        FSACloseFile(fsaClient, fd);
        return 0;
    }

    while (true) {
        int readRes = FSAReadFile(fsaClient, entry, sizeof(RawUidEntry), 1, fd, 0);
        if (readRes <= 0) {
            break;
        }

        if (entry->titleId == titleId) {
            found = true;
            foundUid = entry->uid;
            break;
        }

        if (entry->uid > maxUid) {
            maxUid = entry->uid;
        }
        entryCount++;
    }

    if (found) {
        free(entry);
        FSACloseFile(fsaClient, fd);
        return foundUid;
    }

    if (entryCount == 0) {
        // File was 0-bytes, write System Menu first
        *entry = { 0x0000000100000002ULL, 0x1000 };
        FSASetPosFile(fsaClient, fd, 0);
        FSAWriteFile(fsaClient, entry, sizeof(RawUidEntry), 1, fd, 0);
        if (titleId == 0x0000000100000002ULL) {
            free(entry);
            FSACloseFile(fsaClient, fd);
            return 0x1000;
        }
        entryCount = 1;
    }

    uint32_t newUid = maxUid + 1;
    *entry = { titleId, newUid };

    FSASetPosFile(fsaClient, fd, entryCount * sizeof(RawUidEntry));
    int writeRes = FSAWriteFile(fsaClient, entry, sizeof(RawUidEntry), 1, fd, 0);
    free(entry);
    FSACloseFile(fsaClient, fd);

    WUPI_Log("UID (appended): %08x/%08x -> %d (%s)\n",
             (uint32_t)(titleId >> 32), (uint32_t)(titleId & 0xFFFFFFFF),
             newUid, writeRes > 0 ? "OK" : "FAIL");

    return newUid;
}
