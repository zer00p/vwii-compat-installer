/* WAD Installer integration
 *   Copyright (C) 2026
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef FILEBROWSER_H
#define FILEBROWSER_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// Interactive WAD selector that renders to the screen using OSScreen.
// Returns a dynamically allocated string containing the absolute path to the selected WAD, 
// or NULL if the user cancelled or an error occurred.
// The caller is responsible for freeing the returned string.
char* BrowseWADs(void);

#ifdef __cplusplus
}
#endif

#endif // FILEBROWSER_H
