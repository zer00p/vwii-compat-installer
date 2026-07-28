#include "MenuUtils.h"
#include "ScreenUtils.h"
#include "StateUtils.h"
#include "InputUtils.h"
#include <unistd.h>

static void DrawMenu(const std::vector<std::string>& header, const std::vector<std::string>& options, int selected) {
    ScreenUtils_ClearBuffer(0);
    int offset = 0;
    for (size_t i = 0; i < header.size(); i++) {
        ScreenUtils_PutFont(0, offset++, header[i].c_str());
    }

    for (size_t i = 0; i < options.size(); i++) {
        std::string line = (i == (size_t)selected ? "-> " : "   ") + options[i];
        ScreenUtils_PutFont(0, offset + 2 + i, line.c_str());
    }

    ScreenUtils_PutFont(0, offset + 3 + options.size(), "A: Select | B: Cancel | UP/DOWN: Move");
    ScreenUtils_FlipBuffers();
}

int ShowMenu(const std::vector<std::string>& header, const std::vector<std::string>& options) {
    if (options.empty()) return -1;
    
    int selected = 0;
    auto Draw = [&]() {
        DrawMenu(header, options, selected);
    };
    
    Draw();
    
    Input input;
    while (State::AppRunning()) {
        input.read();
        
        if (input.get(TRIGGER, PAD_BUTTON_UP) && selected > 0) {
            selected--;
            Draw();
        }
        else if (input.get(TRIGGER, PAD_BUTTON_DOWN) && selected < (int)options.size() - 1) {
            selected++;
            Draw();
        }
        else if (input.get(TRIGGER, PAD_BUTTON_B)) {
            return -1;
        }
        else if (input.get(TRIGGER, PAD_BUTTON_A)) {
            return selected;
        }
        
        usleep(16000);
    }
    return -1;
}

static void DrawMultiSelectMenu(const std::vector<std::string>& header, const std::vector<std::string>& options, const std::vector<bool>& selectedOptions, int cursor) {
    ScreenUtils_ClearBuffer(0);
    int offset = 0;
    for (size_t i = 0; i < header.size(); i++) {
        ScreenUtils_PutFont(0, offset++, header[i].c_str());
    }

    for (size_t i = 0; i < options.size(); i++) {
        std::string prefix = (i == (size_t)cursor ? "-> " : "   ");
        prefix += (selectedOptions[i] ? "[x] " : "[ ] ");
        std::string line = prefix + options[i];
        ScreenUtils_PutFont(0, offset + 2 + i, line.c_str());
    }

    ScreenUtils_PutFont(0, offset + 3 + options.size(), "A: Toggle | X: Toggle All | +: Confirm | B: Cancel | UP/DOWN: Move");
    ScreenUtils_FlipBuffers();
}

std::vector<int> ShowMultiSelectMenu(const std::vector<std::string>& header, const std::vector<std::string>& options, bool defaultSelected) {
    std::vector<int> result;
    if (options.empty()) return result;
    
    int cursor = 0;
    std::vector<bool> selectedOptions(options.size(), defaultSelected);
    
    auto Draw = [&]() {
        DrawMultiSelectMenu(header, options, selectedOptions, cursor);
    };
    
    Draw();
    
    Input input;
    while (State::AppRunning()) {
        input.read();
        
        bool changed = false;
        if (input.get(TRIGGER, PAD_BUTTON_UP) && cursor > 0) {
            cursor--;
            changed = true;
        }
        else if (input.get(TRIGGER, PAD_BUTTON_DOWN) && cursor < (int)options.size() - 1) {
            cursor++;
            changed = true;
        }
        else if (input.get(TRIGGER, PAD_BUTTON_B)) {
            return std::vector<int>(); // Empty result for cancel
        }
        else if (input.get(TRIGGER, PAD_BUTTON_A)) {
            selectedOptions[cursor] = !selectedOptions[cursor];
            changed = true;
        }
        else if (input.get(TRIGGER, PAD_BUTTON_X)) {
            bool anyUnselected = false;
            for (bool isSelected : selectedOptions) {
                if (!isSelected) {
                    anyUnselected = true;
                    break;
                }
            }
            for (size_t i = 0; i < selectedOptions.size(); i++) {
                selectedOptions[i] = anyUnselected;
            }
            changed = true;
        }
        else if (input.get(TRIGGER, PAD_BUTTON_PLUS)) {
            for (size_t i = 0; i < selectedOptions.size(); i++) {
                if (selectedOptions[i]) {
                    result.push_back((int)i);
                }
            }
            if (result.empty()) {
                result.push_back(cursor);
            }
            return result;
        }
        
        if (changed) {
            Draw();
        }
        
        usleep(16000);
    }
    return result;
}

bool WaitPrompt() {
    Input input;
    while (State::AppRunning()) {
        input.read();
        if (input.get(TRIGGER, PAD_BUTTON_A)) return true;
        if (input.get(TRIGGER, PAD_BUTTON_B)) return false;
        usleep(16000);
    }
    return false;
}
