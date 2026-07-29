#pragma once

#include <coreinit/filesystem_fsa.h>
#include <stddef.h>

// Writes a buffer to an FSA file handle using a 0x40 aligned internal buffer
bool FSAWriteAligned(FSAClientHandle fsa, FSAFileHandle fd, const void* buffer, size_t size);

// Recursively creates a directory path using FSA
void EnsureFSADirectory(FSAClientHandle fsaClient, const char* path);
