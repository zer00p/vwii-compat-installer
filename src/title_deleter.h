#pragma once

#include <coreinit/filesystem_fsa.h>
#include <stdint.h>
#include <string>
#include <vector>

enum class TitleCategory {
    IOS_TITLES,
    SYSTEM_TITLES,
    SYSTEM_CHANNELS,
    INSTALLED_CHANNELS,
    DLC_CONTENT
};

enum class DeleteMode {
    CONTENT_AND_DATA,      // Content + Data (Preserve Ticket)
    EVERYTHING_INC_TICKET, // Content + Data + Ticket (Full Delete)
    CONTENT_ONLY,          // Content only (Preserve Save / Config Data & Ticket)
    DATA_ONLY              // Save / Config data only (Preserve Content & Ticket)
};

struct ManagedTitle {
    uint64_t titleId;
    TitleCategory category;
    std::string titleName;
    std::string asciiId;
    bool hasContent;
    bool hasData;
    bool hasTicket;
    bool isCritical;
};

// Extracts localized channel name from a 00000000.app banner file on FSA
std::string ExtractTitleNameFromApp(FSAClientHandle fsa, const std::string& appPath);

// Scans NAND (/vol/slccmpt01/title and /vol/slccmpt01/ticket) for all titles belonging to a specific category
std::vector<ManagedTitle> ScanTitlesByCategory(FSAClientHandle fsa, TitleCategory category);

// Deletes the specified target components (Content, Data, Ticket, etc.) for a title
bool DeleteTitleTarget(FSAClientHandle fsa, const ManagedTitle& title, DeleteMode mode);

// Main interactive menu entry point for the Delete Titles feature
void WUPI_DeleteTitlesMenu();
