#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Returns an allocated string with the full path to the selected d2x version folder.
 * Returns NULL if the user cancelled or no folders were found.
 * Caller must free() the returned string.
 */
char* BrowseD2XVersions(void);

#ifdef __cplusplus
}
#endif
