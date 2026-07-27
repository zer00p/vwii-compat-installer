#pragma once
#include <string>
#include <vector>

// Shows a generic vertical menu.
// Returns the index of the selected item, or -1 if canceled (B button).
int ShowMenu(const std::vector<std::string>& header, const std::vector<std::string>& options);

// Waits for A or B. Returns true for A, false for B.
bool WaitPrompt();
