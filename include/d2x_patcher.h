/*
 * d2x_patcher.h
 * 
 * The cIOS patching logic in the corresponding implementation is 
 * adapted from the d2x-cios-installer project.
 * Original credits go to davebaol, xperia64, blackb0x / wiidev, 
 * and other contributors to the d2x cIOS and patchmii projects.
 *
 * Licensed under the GPLv2.
 */

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

// Will install d2x cIOS using the selected version folder on the SD card.
// Prompts the user to confirm the installation of the standard configurations.
void InstallD2X(const char* versionFolder);

#ifdef __cplusplus
}
#endif
