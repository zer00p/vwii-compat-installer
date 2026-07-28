#pragma once

#include <string>

// Downloads an app from Open Shop Channel and extracts it to the root of the SD card.
// appId is the internal name, e.g. "d2x-cios-installer".
// Returns true on success, false on failure.
bool DownloadAndExtractApp(const std::string& appId);

// Downloads a file from the given url to the given outPath on the filesystem.
// Returns true on success, false on failure.
bool DownloadFile(const std::string& url, const std::string& outPath);
