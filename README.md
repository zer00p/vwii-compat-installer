# Compat Title Installer

Install a channel to the vWii Menu from Wii U Mode. In its current state, it
simply installs the Homebrew Channel.

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
* mbedtls contributors, for the cryptography library used for WAD installation
* Segher Boessenkool, BFGR, and libertyernie, for the WAD tools
* WiiBrew contributors (wiibrew.org), for the invaluable documentation on the WAD file format and title structures
* davebaol, xperia64, blackb0x / wiidev, and other contributors to d2x-cios-installer for the cIOS patching engine
* leethomason/tinyxml2 for the tinyxml2 parsing library

## License

This software is licensed under the GNU General Public License version 2 (or any
later version). The full license can be found in the LICENSE file.

The Homebrew Channel is licensed under GPLv2 and is included in binary form. A
copy of the source code is available at
[fail0verflow/hbc](https://github.com/fail0verflow/hbc).

The `mbedtls` library is dual-licensed under the Apache License 2.0 and GPLv2 (or any later version).
