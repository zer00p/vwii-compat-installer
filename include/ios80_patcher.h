/*
 * ios80_patcher.h
 *
 * Dedicated patcher for vWii System Menu IOS (IOS80).
 */

#pragma once

// Reads base IOS80, applies Trucha/ES/FS patches, and installs patched IOS80.
void InstallIOS80();

// Downloads the original, unpatched IOS80 from NUS and installs it.
void UndoIOS80Patches();

// Non-interactive batch patch for IOS80
bool InstallIOS80Batch();

// Non-interactive batch revert for IOS80 (restores backup or NUS)
bool UndoIOS80PatchesBatch();


