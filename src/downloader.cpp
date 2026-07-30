#include "downloader.h"
#include "FSAUtils.h"
#include <curl/curl.h>
#include <stdlib.h>
#include <malloc.h>
#include <string.h>
#include "miniz.h"
#include "ScreenUtils.h"
#include "log.h"
#include <coreinit/filesystem_fsa.h>
#include "cacert_pem.h"

static void SetCurlCACert(CURL *curl_handle) {
    curl_blob blob;
    blob.data  = (void *) cacert_pem;
    blob.len   = cacert_pem_size;
    blob.flags = CURL_BLOB_COPY;
    curl_easy_setopt(curl_handle, CURLOPT_CAINFO_BLOB, &blob);
}

extern FSAClientHandle fsaClient;

struct MemoryStruct {
    char *memory;
    size_t size;
};

static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct MemoryStruct *mem = (struct MemoryStruct *)userp;

    char *ptr = (char*)realloc(mem->memory, mem->size + realsize + 1);
    if (!ptr) {
        return 0; // out of memory
    }

    mem->memory = ptr;
    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;

    return realsize;
}

static void ShowDownloadStatus(const char* message) {
    WUPI_Log("%s\n", message);
}


static bool curl_initialized = false;

static void InitCurl() {
    if (!curl_initialized) {
        curl_global_init(CURL_GLOBAL_DEFAULT);
        curl_initialized = true;
    }
}

void DeinitCurl() {
    if (curl_initialized) {
        curl_global_cleanup();
        curl_initialized = false;
    }
}

bool DownloadAndExtractApp(const std::string& appId) {
    InitCurl();

    ShowDownloadStatus("Initializing connection...");
    
    CURL *curl_handle = curl_easy_init();
    if(!curl_handle) {
        WUPI_Log("Download failed: Could not initialize cURL.\n");
        return false;
    }

    std::string url = "https://hbb1.oscwii.org/api/contents/" + appId + "/" + appId + ".zip";

    struct MemoryStruct chunk;
    chunk.memory = (char*)malloc(1);
    chunk.size = 0;

    curl_easy_setopt(curl_handle, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)&chunk);
    curl_easy_setopt(curl_handle, CURLOPT_USERAGENT, "vWii-Compat-Installer/1.0");
    curl_easy_setopt(curl_handle, CURLOPT_FOLLOWLOCATION, 1L);
    SetCurlCACert(curl_handle);

    std::string fetchMsg = "Fetching " + appId + ".zip...";
    ShowDownloadStatus(fetchMsg.c_str());

    CURLcode res = curl_easy_perform(curl_handle);
    long httpCode = 0;
    curl_easy_getinfo(curl_handle, CURLINFO_RESPONSE_CODE, &httpCode);
    curl_easy_cleanup(curl_handle);

    if (res != CURLE_OK) {
        WUPI_Log("Download failed: %s (%d)\n", curl_easy_strerror(res), res);
        free(chunk.memory);
        return false;
    }

    if (httpCode >= 400) {
        WUPI_Log("Download failed: HTTP Error %ld\n", httpCode);
        free(chunk.memory);
        return false;
    }

    if (chunk.size == 0) {
        WUPI_Log("Download failed: Empty response received.\n");
        free(chunk.memory);
        return false;
    }

    ShowDownloadStatus("Extracting ZIP archive...");

    mz_zip_archive zip_archive;
    memset(&zip_archive, 0, sizeof(zip_archive));

    if (!mz_zip_reader_init_mem(&zip_archive, chunk.memory, chunk.size, 0)) {
        WUPI_Log("Download failed: Invalid ZIP archive.\n");
        free(chunk.memory);
        return false;
    }

    bool success = true;
    for (int i = 0; i < (int)mz_zip_reader_get_num_files(&zip_archive); i++) {
        mz_zip_archive_file_stat file_stat;
        if (!mz_zip_reader_file_stat(&zip_archive, i, &file_stat)) {
            continue;
        }

        std::string outPath = std::string("/vol/external01/") + file_stat.m_filename;
        
        if (mz_zip_reader_is_file_a_directory(&zip_archive, i)) {
            EnsureFSADirectory(fsaClient, outPath.c_str());
            FSAMakeDir(fsaClient, outPath.c_str(), (FSMode)(FS_MODE_READ_OWNER | FS_MODE_WRITE_OWNER | FS_MODE_EXEC_OWNER));
        } else {
            EnsureFSADirectory(fsaClient, outPath.c_str());
            
            size_t uncomp_size;
            void* p = mz_zip_reader_extract_file_to_heap(&zip_archive, file_stat.m_filename, &uncomp_size, 0);
            if (p) {
                FSAFileHandle fd = 0;
                if (FSAOpenFileEx(fsaClient, outPath.c_str(), "w", (FSMode)(FS_MODE_READ_OWNER | FS_MODE_WRITE_OWNER), (FSOpenFileFlags)0, 0, &fd) == 0) {
                    if (!FSAWriteAligned(fsaClient, fd, p, uncomp_size)) {
                        WUPI_Log("Failed to write to file: %s\n", outPath.c_str());
                        success = false;
                    }
                    FSACloseFile(fsaClient, fd);
                } else {
                    WUPI_Log("Failed to open file for writing: %s\n", outPath.c_str());
                    success = false;
                }
                free(p);
            } else {
                WUPI_Log("Failed to extract file from zip: %s\n", file_stat.m_filename);
                success = false;
            }
        }
    }

    mz_zip_reader_end(&zip_archive);
    free(chunk.memory);
    if (!success) {
        WUPI_Log("Download failed: File extraction failed.\n");
    }
    return success;
}

bool DownloadToMemory(const std::string& url, uint8_t** outData, size_t* outSize) {
    InitCurl();

    CURL *curl_handle = curl_easy_init();
    if(!curl_handle) {
        WUPI_Log("Download failed: Could not initialize cURL.\n");
        return false;
    }

    struct MemoryStruct chunk;
    chunk.memory = (char*)malloc(1);
    chunk.size = 0;

    curl_easy_setopt(curl_handle, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)&chunk);
    curl_easy_setopt(curl_handle, CURLOPT_USERAGENT, "vWii-Compat-Installer/1.0");
    curl_easy_setopt(curl_handle, CURLOPT_FOLLOWLOCATION, 1L);
    SetCurlCACert(curl_handle);

    CURLcode res = curl_easy_perform(curl_handle);
    long httpCode = 0;
    curl_easy_getinfo(curl_handle, CURLINFO_RESPONSE_CODE, &httpCode);
    curl_easy_cleanup(curl_handle);

    if (res != CURLE_OK) {
        WUPI_Log("Download failed: %s (%d)\n", curl_easy_strerror(res), res);
        free(chunk.memory);
        return false;
    }

    if (httpCode >= 400) {
        WUPI_Log("Download failed: HTTP Error %ld\n", httpCode);
        free(chunk.memory);
        return false;
    }

    if (chunk.size == 0) {
        WUPI_Log("Download failed: Empty response received.\n");
        free(chunk.memory);
        return false;
    }

    *outData = (uint8_t*)chunk.memory;
    *outSize = chunk.size;
    return true;
}

bool DownloadFile(const std::string& url, const std::string& outPath) {
    InitCurl();

    std::string msg = "Downloading to " + outPath;
    ShowDownloadStatus(msg.c_str());

    CURL *curl_handle = curl_easy_init();
    if(!curl_handle) {
        WUPI_Log("Download failed: Could not initialize cURL.\n");
        return false;
    }

    struct MemoryStruct chunk;
    chunk.memory = (char*)malloc(1);
    chunk.size = 0;

    curl_easy_setopt(curl_handle, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)&chunk);
    curl_easy_setopt(curl_handle, CURLOPT_USERAGENT, "vWii-Compat-Installer/1.0");
    curl_easy_setopt(curl_handle, CURLOPT_FOLLOWLOCATION, 1L);
    SetCurlCACert(curl_handle);

    CURLcode res = curl_easy_perform(curl_handle);
    long httpCode = 0;
    curl_easy_getinfo(curl_handle, CURLINFO_RESPONSE_CODE, &httpCode);
    curl_easy_cleanup(curl_handle);

    if (res != CURLE_OK) {
        WUPI_Log("Download failed: %s (%d)\n", curl_easy_strerror(res), res);
        free(chunk.memory);
        return false;
    }

    if (httpCode >= 400) {
        WUPI_Log("Download failed: HTTP Error %ld\n", httpCode);
        free(chunk.memory);
        return false;
    }

    if (chunk.size == 0) {
        WUPI_Log("Download failed: Empty response received.\n");
        free(chunk.memory);
        return false;
    }

    ShowDownloadStatus("Saving file...");

    EnsureFSADirectory(fsaClient, outPath.c_str());
    FSAFileHandle fd = 0;
    bool success = false;
    if (FSAOpenFileEx(fsaClient, outPath.c_str(), "w", (FSMode)(FS_MODE_READ_OWNER | FS_MODE_WRITE_OWNER), (FSOpenFileFlags)0, 0, &fd) == 0) {
        if (FSAWriteAligned(fsaClient, fd, chunk.memory, chunk.size)) {
            success = true;
        } else {
            WUPI_Log("Failed to write aligned data to file: %s\n", outPath.c_str());
        }
        FSACloseFile(fsaClient, fd);
    } else {
        WUPI_Log("Failed to open file for writing: %s\n", outPath.c_str());
    }

    free(chunk.memory);
    return success;
}
