#include "downloader.h"
#include "FSAUtils.h"
#include "StateUtils.h"
#include "InputUtils.h"
#include <curl/curl.h>
#include <stdlib.h>
#include <malloc.h>
#include <string.h>
#include <unistd.h>
#include "miniz.h"
#include "ScreenUtils.h"
#include "log.h"
#include <coreinit/filesystem_fsa.h>
#include "cacert_pem.h"

static int CurlProgressCallback(void *, curl_off_t, curl_off_t, curl_off_t, curl_off_t) {
    if (!State::AppRunning() || State::isExiting()) {
        return 1;
    }
    return 0;
}

static void SetCurlCACert(CURL *curl_handle) {
    curl_blob blob;
    blob.data  = (void *) cacert_pem;
    blob.len   = cacert_pem_size;
    blob.flags = CURL_BLOB_COPY;
    curl_easy_setopt(curl_handle, CURLOPT_CAINFO_BLOB, &blob);
}

extern FSAClientHandle fsaClient;

DownloadAction PromptDownloadRetry() {
    WUPI_putstr("Press (A) to Retry, (B) to Skip, (X) to Cancel.");
    Input input;
    while (State::AppRunning()) {
        input.read();
        if (input.get(TRIGGER, PAD_BUTTON_A)) return DownloadAction::RETRY;
        if (input.get(TRIGGER, PAD_BUTTON_B)) return DownloadAction::SKIP;
        if (input.get(TRIGGER, PAD_BUTTON_X)) return DownloadAction::CANCEL;
        usleep(16000);
    }
    return DownloadAction::CANCEL;
}

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

DownloadResult DownloadToMemory(const std::string& url, uint8_t** outData, size_t* outSize) {
    InitCurl();

    while (State::AppRunning()) {
        CURL *curl_handle = curl_easy_init();
        if(!curl_handle) {
            WUPI_Log("Download failed: Could not initialize cURL.\n");
            return DownloadResult::FAILED;
        }

        struct MemoryStruct chunk;
        chunk.memory = (char*)malloc(1);
        chunk.size = 0;

        curl_easy_setopt(curl_handle, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
        curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)&chunk);
        curl_easy_setopt(curl_handle, CURLOPT_USERAGENT, "vWii-Compat-Installer/1.0");
        curl_easy_setopt(curl_handle, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(curl_handle, CURLOPT_XFERINFOFUNCTION, CurlProgressCallback);
        curl_easy_setopt(curl_handle, CURLOPT_NOPROGRESS, 0L);
        SetCurlCACert(curl_handle);

        CURLcode res = curl_easy_perform(curl_handle);
        long httpCode = 0;
        curl_easy_getinfo(curl_handle, CURLINFO_RESPONSE_CODE, &httpCode);
        curl_easy_cleanup(curl_handle);

        bool fetchOk = true;
        if (res != CURLE_OK) {
            WUPI_Log("Download failed: %s (%d)\n", curl_easy_strerror(res), res);
            fetchOk = false;
        } else if (httpCode >= 400) {
            WUPI_Log("Download failed: HTTP Error %ld\n", httpCode);
            fetchOk = false;
        } else if (chunk.size == 0) {
            WUPI_Log("Download failed: Empty response received.\n");
            fetchOk = false;
        }

        if (!fetchOk) {
            free(chunk.memory);
            DownloadAction action = PromptDownloadRetry();
            if (action == DownloadAction::RETRY) {
                continue;
            }
            if (action == DownloadAction::CANCEL) {
                return DownloadResult::CANCELLED;
            }
            return DownloadResult::FAILED;
        }

        *outData = (uint8_t*)chunk.memory;
        *outSize = chunk.size;
        return DownloadResult::SUCCESS;
    }
    return DownloadResult::CANCELLED;
}

DownloadResult DownloadAndExtractApp(const std::string& appId) {
    std::string fetchMsg = "Fetching " + appId + ".zip...";
    ShowDownloadStatus(fetchMsg.c_str());

    std::string url = "https://hbb1.oscwii.org/api/contents/" + appId + "/" + appId + ".zip";

    uint8_t* zipData = nullptr;
    size_t zipSize = 0;
    DownloadResult dlRes = DownloadToMemory(url, &zipData, &zipSize);
    if (dlRes != DownloadResult::SUCCESS || !zipData) {
        return dlRes;
    }

    ShowDownloadStatus("Extracting ZIP archive...");

    mz_zip_archive zip_archive;
    memset(&zip_archive, 0, sizeof(zip_archive));

    if (!mz_zip_reader_init_mem(&zip_archive, zipData, zipSize, 0)) {
        WUPI_Log("Download failed: Invalid ZIP archive.\n");
        free(zipData);
        return DownloadResult::FAILED;
    }

    bool success = true;
    for (int i = 0; i < (int)mz_zip_reader_get_num_files(&zip_archive); i++) {
        mz_zip_archive_file_stat file_stat;
        if (!mz_zip_reader_file_stat(&zip_archive, i, &file_stat)) {
            continue;
        }

        std::string outPath = std::string("/vol/external01/") + file_stat.m_filename;
        
        if (mz_zip_reader_is_file_a_directory(&zip_archive, i)) {
            EnsureFSADir(fsaClient, outPath);
        } else {
            EnsureFSAParentDir(fsaClient, outPath);
            
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
    free(zipData);
    if (!success) {
        WUPI_Log("Download failed: File extraction failed.\n");
        return DownloadResult::FAILED;
    }
    return DownloadResult::SUCCESS;
}

DownloadResult DownloadFile(const std::string& url, const std::string& outPath) {
    std::string msg = "Downloading to " + outPath;
    ShowDownloadStatus(msg.c_str());

    uint8_t* data = nullptr;
    size_t size = 0;
    DownloadResult dlRes = DownloadToMemory(url, &data, &size);
    if (dlRes != DownloadResult::SUCCESS || !data) {
        return dlRes;
    }

    ShowDownloadStatus("Saving file...");

    EnsureFSAParentDir(fsaClient, outPath);
    FSAFileHandle fd = 0;
    bool success = false;
    if (FSAOpenFileEx(fsaClient, outPath.c_str(), "w", (FSMode)(FS_MODE_READ_OWNER | FS_MODE_WRITE_OWNER), (FSOpenFileFlags)0, 0, &fd) == 0) {
        if (FSAWriteAligned(fsaClient, fd, data, size)) {
            success = true;
        } else {
            WUPI_Log("Failed to write aligned data to file: %s\n", outPath.c_str());
        }
        FSACloseFile(fsaClient, fd);
    } else {
        WUPI_Log("Failed to open file for writing: %s\n", outPath.c_str());
    }

    free(data);
    return success ? DownloadResult::SUCCESS : DownloadResult::FAILED;
}
