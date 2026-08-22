# Compat Title Installer

All-in-one homebrew setup tool that lets you fully softmod, configure, and repair your vWii directly from the Wii U menu (Aroma).

It features an express installer to quickly get your vWii ready with the Homebrew Channel, USB Loader GX, d2x cIOS, WAD installation, and the Open Shop Channel (Homebrew Browser / LibreShop). 

It also doubles as an advanced maintenance and recovery tool featuring a **vWii Region Change Wizard** to switch your vWii region (EUR, USA, JPN) with selective asset downloading and cleanup, and a **Decaf Menu (Reinstall & Wipe)** that fully replaces vWii-Decaffeinator with direct NUS downloading (bypassing DNS and Aroma update blocks), granular system wipes, integrity scanning, and `setting.txt` management.

## Features

### Homebrew Setup & Installation
* **Open Homebrew Channel (OHBC)**: Install or uninstall the Homebrew Channel directly to the vWii System Menu from Wii U mode without needing game exploits.
* **1-Click Express Setup & Uninstall**: Quickly batch install or remove the Homebrew Channel, d2x cIOS, IOS80 patches, USB Loader GX, and Open Shop Channel apps in a single step.
* **USB Loader GX Setup**: Download the USB Loader GX app to SD, install the vWii forwarder channel (UNEO WAD), and download the Aroma Wii U forwarder (Boot2vWii WUHB).
* **d2x cIOS Installer**: Install custom d2x cIOS into slots 248 (base 56), 249 (base 57), 250 (base 58), and 251 (base 59) directly, downloading required base IOS files from NUS or the Open Shop Channel.
* **Batch WAD Installer**: Safely browse and install `.wad` files from the SD card.
* **IOS80 Patcher**: Patch IOS80 (Trucha Bug, ES_Identify, NAND access) to run custom channels from the SD Card Menu, with an option to revert back to stock.
* **Open Shop Channel Integration**: Download homebrew apps (such as LibreShop, Homebrew Browser, and the d2x cIOS installer) directly to the SD card.

### vWii Region Change Wizard
* **Change vWii Region**: Change your vWii region to Europe (`EUR`), USA (`USA`), or Japan (`JPN`).
* **Intelligent Selective Reinstallation**: Only downloads and installs the titles that actually change between regions (System Menu, EULA, Region Select, etc.), minimizing download time and NAND writes.
* **Conflicting Channel Detection**: Detects and prompts to uninstall leftover channel titles from previous regions.
* **Shared Content Orphan Cleanup**: Scans title TMDs and `content.map` for unreferenced region-specific shared assets (such as font tables and message files) to safely reclaim SLCCMPT storage space.
* **Automatic `setting.txt` Update**: Updates or regenerates `setting.txt` to match the target region.

### Decaf Menu (System Recovery & Unbricking)
* **Direct NUS Reinstallation**: Downloads and reinstalls system titles directly from Nintendo Update Servers (NUS) without requiring manual DNS configuration or disabling Aroma update blockers.
* **System Scanner (Scan & Restore)**: Scans SLCCMPT for corrupted, modified, or missing system titles/IOSes, validates TMD RSA signatures and SHA-1 content hashes, checks filesystem ownership/permissions, and offers selective 1-click repairs.
* **Reinstall System Titles**: Selectively download and reinstall any or all stock vWii system titles and IOSes from NUS.
* **Granular System Wipes**:
  * **Wipe System Titles (Preserve User Titles & Tickets)**: Reinstalls all system titles while preserving user homebrew/VC titles, saves, and tickets.
  * **Wipe Everything (Preserve User Tickets)**: Wipes all titles and saves while preserving user ticket licenses.
  * **Full Factory Wipe & Reinstall**: Completely wipes SLCCMPT and performs a fresh reinstall of all system titles with properly initialized system files and stock permissions.
* **Title Deleter**: Interactive title manager to browse and delete specific system titles, channels, or user titles, with options to preserve or remove associated save data.

### `setting.txt` Tools
* **View `setting.txt`**: View current parsed vWii configuration fields.
* **Hardware MCP Regeneration**: Rebuild `setting.txt` automatically using the console's factory Wii U production settings (MCP) with proper stock permissions (`0x444` / read-only, UID 4096, GID 1) to eliminate boot black screens.
* **Region Presets & Field Editor**: Quickly apply region presets (`EUR`, `USA`, `JPN`) or edit individual fields (`AREA`, `MODEL`, `DVD`, `MPCH`, `CODE`, `SERNO`, `VIDEO`, `GAME`).
* **Backup & Restore**: Backup `setting.txt` to the SD card and restore it at any time.

### Hardware & Compatibility Patches
* **Drive Inquiry Patch [EXPERIMENTAL]**: Apply GaryOderNichts's no-disc-drive inquiry patch to common IOSes, allowing the vWii to boot and function even if the console has a faulty or disconnected disc drive. Includes an option to undo the patch.

### Accurate Stock Permissions & Filesystem Integrity
* **Authentic SFFS Permissions**: All files and directories are created with exact stock ownership (UIDs, GIDs) and `FSMode` bitmasks rather than generic permissions.
* **System File Recovery**: Validates and reconstructs `/sys/uid.sys` and `/sys/cert.sys` to ensure proper title UID allocation and certificate chain verification.

## Building

You need devkitPPC, devkitARM and WUT installed, and the environment variables set
correctly. You will need the following libraries:

* [libmocha](https://github.com/wiiu-env/libmocha)

If everything is installed, run 'make release' and the output will be available as
'compat_installer-HBL.zip' and 'compat_installer-Aroma.zip'.

## Credits

* Dimok, smealum, others for iosuhax and Mocha CFW.
* FIX94, this repo is largely based off of wuphax.
* @Ingunar on GitHub, for the awesome icons
* TheLordScruffy/mkwcat, for the original Compat Title Installer
* Xpl0itU (aka DaThinkingChair), for the WUT Port
* zer00p, for v2.0 & v2.1 features
* Team Twiizers / fail0verflow (dhewg, bushing, marcan, segher & others) for the original Homebrew Channel
* mbedtls contributors, for the cryptography library used for WAD installation
* Segher Boessenkool, BFGR, and libertyernie, for the WAD tools
* WiiBrew contributors (wiibrew.org), for the invaluable documentation on the WAD file format and title structures
* davebaol, xperia64, blackb0x / wiidev, and other contributors to d2x-cios-installer for the cIOS patching engine
* leethomason/tinyxml2 for the tinyxml2 parsing library
* The Open Shop Channel (oscwii.org) for their backend repository API used for downloading homebrew apps.
* richgel999/miniz for the single-file ZIP extraction library.
* Dr Clipper, ZRicky11, damysteryman, GaryOderNichts, and contributors for the Patched IOS installers and No Disc Drive patches.
* GaryOderNichts for vWii-Decaffeinator and the `setting.txt` generation logic.
* Brawl345 for the USB Loader GX Boot2vWii Forwarder.

## License

This software is licensed under the GNU General Public License version 2 (or any
later version). The full license can be found in the LICENSE file.

The Open Homebrew Channel (OHBC) by FIX94 is included in binary form, based on
the original Homebrew Channel by Team Twiizers / fail0verflow (GPLv2). A copy of
the source code is available at
[fail0verflow/hbc](https://github.com/fail0verflow/hbc).

The `mbedtls` library is dual-licensed under the Apache License 2.0 and GPLv2 (or any later version).
