#pragma once

#include "title.h"
#include <coreinit/filesystem_fsa.h>
#include <memory>
#include <string>
#include <vector>
#include <stdint.h>

struct MemContent {
    uint32_t cid;
    uint32_t size;
    uint8_t* data;
};

struct MemIOS {
    TitleTmd* tmd = nullptr;
    uint32_t tmdSize = 0;
    TitleTicket* ticket = nullptr;
    uint32_t ticketSize = 0;
    MemContent* contents = nullptr;
    uint32_t numContents = 0;
    uint32_t maxContents = 0;

    ~MemIOS();
    MemIOS() = default;
    MemIOS(const MemIOS&) = delete;
    MemIOS& operator=(const MemIOS&) = delete;
};

void Patcher_Log(const std::string& msg);
std::string ToHexString(uint32_t val, int width = 8);

void Write16BE(uint8_t* p, uint16_t v);
void Write32BE(uint8_t* p, uint32_t v);
void Write64BE(uint8_t* p, uint64_t v);

void SHA1(const uint8_t* data, size_t len, uint8_t hash[20]);
bool ReadFileToBuffer(const std::string& path, uint8_t** outBuf, uint32_t* outSize);
bool WriteBufferToFile(const std::string& path, uint8_t* buf, uint32_t size);
std::unique_ptr<MemIOS> ReadBaseIOS(uint32_t baseIos);
bool WritePatchedIOS(uint32_t titleIdLow, MemIOS& ios);
