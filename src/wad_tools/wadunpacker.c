// wad-tools
// Licensed under the terms of the GNU GPL, version 2
// http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt
// Based on BFGR WadTools v0.39a by BFGR based on Zeventig by Segher

#include <sys/types.h>
#include <sys/stat.h>
#ifdef _MSC_VER
#include <direct.h>
#else
#include <unistd.h>
#endif
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "tools.h"
#include "../installer.h"

#include <stdint.h>
#include <stdbool.h>
extern bool GetCommonKeyFromOTP(uint8_t index, uint8_t outKey[16]);

#define ERROR(s) do { fprintf(stderr, s "\n"); exit(1); } while (0)

static FILE *fp;

static u8 *get_wad(u32 len)
{
	u32 rounded_len;
	u8 *p;

	rounded_len = round_up(len, 0x40);
	p = (u8*)malloc(rounded_len);
	if (p == 0)
		fatal("malloc");
	if (len)
		if (fread(p, rounded_len, 1, fp) != 1)
			fatal("get_wad read, len = %x", len);

	return p;
}

int ExtractWadToMemory(const char* filepath, void** out_ticket, uint32_t* ticket_size, void** out_tmd, uint32_t* tmd_size, CINS_Content** out_contents, uint16_t* out_numContents, uint64_t* out_titleId)
{
	u8 header[0x80];
	u32 header_len, cert_len, tik_len, tmd_len, app_len, trailer_len;
	u8 *cert, *tik, *tmd, *app, *trailer;
	u8 title_key[16], iv[16];
	u32 i, len, rounded_len;
	u16 num_contents;
	u8 *p;
	CINS_Content *c_arr;

	fp = fopen(filepath, "rb");
	if (!fp) return -1;

	if (fread(header, 0x40, 1, fp) != 1) {
		fclose(fp);
		return -1;
	}
	header_len = be32(header);
	if (header_len >= 0x40) {
		if (fread(header + 0x40, 0x40, 1, fp) != 1) {
			fclose(fp);
			return -1;
		}
	}

	cert_len = be32(header + 8);
	tik_len = be32(header + 0x10);
	tmd_len = be32(header + 0x14);
	app_len = be32(header + 0x18);
	trailer_len = be32(header + 0x1c);

	cert = get_wad(cert_len);
	tik = get_wad(tik_len);
	tmd = get_wad(tmd_len);
	app = get_wad(app_len);
	trailer = get_wad(trailer_len);
	fclose(fp);

	*out_titleId = be64(tmd + 0x018c);
	*out_ticket = tik;
	*ticket_size = tik_len;
	*out_tmd = tmd;
	*tmd_size = tmd_len;

	u8 ckey_idx = 0;
	u32 sigType = be32(tik);
	u32 payloadOffset = 0;
	if (sigType == 0x00010000) payloadOffset = 0x240;
	else if (sigType == 0x00010001) payloadOffset = 0x140;
	else if (sigType == 0x00010002) payloadOffset = 0x80;
	if (payloadOffset > 0 && tik_len >= payloadOffset + 0x1F2) {
		ckey_idx = tik[payloadOffset + 0x1F1];
	}

	u8 dynamic_common_key[16];
	if (GetCommonKeyFromOTP(ckey_idx, dynamic_common_key)) {
		set_common_key(dynamic_common_key);
	} else {
		free(cert); free(tik); free(tmd); free(app); free(trailer);
		return -1;
	}

	decrypt_title_key(tik, title_key);
	num_contents = be16(tmd + 0x01de);
	*out_numContents = num_contents;

	c_arr = (CINS_Content*)malloc(sizeof(CINS_Content) * num_contents);
	if (!c_arr) return -1;

	p = app;
	for (i = 0; i < num_contents; i++) {
		len = be64(tmd + 0x01ec + 0x24*i);
		rounded_len = round_up(len, 0x40);

		memset(iv, 0, sizeof iv);
		memcpy(iv, tmd + 0x01e8 + 0x24*i, 2);
		aes_cbc_dec(title_key, iv, p, rounded_len, p);

		u8* decrypted_app = (u8*)malloc(len);
		memcpy(decrypted_app, p, len);

		u8 expected_hash[20];
		memcpy(expected_hash, tmd + 0x01f4 + 0x24*i, 20);

		u8 actual_hash[20];
		sha(decrypted_app, len, actual_hash);

		if (memcmp(expected_hash, actual_hash, 20) != 0) {
			free(decrypted_app);
			for (u32 j = 0; j < i; j++) free(c_arr[j].data);
			free(c_arr);
			free(cert); free(trailer); free(app);
			free(tik); free(tmd);
			return -1;
		}

		c_arr[i].data = decrypted_app;
		c_arr[i].length = len;

		p += rounded_len;
	}

	*out_contents = c_arr;

	free(cert);
	free(trailer);
	free(app);

	return 0;
}
