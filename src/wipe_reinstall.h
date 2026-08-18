#pragma once

// Full Wipe and Reinstall wizard:
// 1. Prompts for confirmation
// 2. Wipes SLCCMPT partition (/vol/slccmpt01) and initializes stock root directories
// 3. Prompts user for target region (with Wii U native region auto-detected)
// 4. Regenerates setting.txt with console hardware parameters & region preset
// 5. Prompts user to download and reinstall system titles from NUS or skip for manual WAD installs
// 6. Displays summary results
void WUPI_fullWipeAndReinstall();
