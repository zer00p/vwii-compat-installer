/*
 * drive_inquiry_patcher.h
 *
 * Dedicated patcher for Drive Inquiry on selected IOSes.
 */

#pragma once

#include <stdint.h>

int HandleDriveInquiryPatch(uint8_t *buf, uint32_t size, bool revert = false);
int HandleDriveInquiryPatchIOS36(uint8_t *buf, uint32_t size, bool revert = false);

// Reads base IOSes, applies Drive Inquiry patches, and installs them.
void InstallDrivePatchAll();

// Reverts the Drive Inquiry patch for selected IOSes.
void UndoDrivePatchAll();

// Non-interactive batch revert for Drive Inquiry patch
bool UndoDrivePatchAllBatch();
