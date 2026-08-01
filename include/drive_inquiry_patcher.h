/*
 * drive_inquiry_patcher.h
 *
 * Dedicated patcher for Drive Inquiry on IOS56, IOS57, IOS58.
 */

#pragma once

#include <stdint.h>

int HandleDriveInquiryPatch(uint8_t *buf, uint32_t size, bool revert = false);

// Reads base IOSes, applies Drive Inquiry patches, and installs them.
void InstallDrivePatchIOS56_57_58();

// Reverts the Drive Inquiry patch for IOS56, IOS57, IOS58.
void UndoDrivePatchIOS56_57_58();

// Non-interactive batch revert for Drive Inquiry patch
bool UndoDrivePatchIOS56_57_58Batch();
