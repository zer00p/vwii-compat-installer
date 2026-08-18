#pragma once

// Displays the Reinstall & Wipe submenu
void WUPI_reinstallWipeMenu();

// System Titles installer from NUS (multi-select / batch install)
void WUPI_NusMenu();

// Granular wipe wizards:
// 1. Wipe system titles and tickets, preserving user titles, saves, user tickets, /sys/uid.sys, and shared contents
void WUPI_wipeExcludeTitlesAndTickets();

// 2. Wipe SLCCMPT partition preserving user tickets only
void WUPI_wipeExcludeTickets();

// 3. Full wipe and reinstall of SLCCMPT partition (complete erasure)
void WUPI_fullWipeAndReinstall();

