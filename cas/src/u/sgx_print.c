// Copyright 2022 Daniel Andrade

#include <stdio.h>
#include <string.h>
#include <inttypes.h>

#include "sgx_print.h"

// TODO dava jeito versão que devolvesse a string para utilizar directamente no printf ou no LOG

// Dump uint8_t array to string.
// Invoke with NULL dest to know needed length (excluding NUL).
// Separator is e.g. "" or ":" or " " or etc.
// Returns length of string. (Don't forget to add +1 in cap for NUL.)
static size_t u8_to_str(char *dest, const uint8_t *src, size_t len, const char *sep)
{
	if (len == 0) {
		return 0;
	}

	size_t total = len * 2 + (len - 1) * strlen(sep);

	if (dest == NULL) {
		return total;
	}

	char *next_pos;
	for (size_t i = 0; i < len - 1; i++) {
		next_pos = dest + i * 2 + i * strlen(sep);
		sprintf(next_pos, "%02"PRIx8"%s", src[i], sep);
	}
	next_pos = dest + (len - 1) * 2 + (len - 1) * strlen(sep);
	sprintf(next_pos, "%02"PRIx8, src[len - 1]);

	return strlen(dest);
}
// NOTE copied from u/attestation.c (shouldn't this be in one.h ??)

// TORM obsolete, use usgx
void sgx_quote_to_str_0(size_t cap, char dest[static cap],
		const sgx_quote_t *quote)
{
	// TODO calc size and return when dest is NULL

	char epid_group_id[12] = {0};
	// printf("epid size: %zu\n", u8_to_str(NULL, quote->epid_group_id, 4, " "));
	u8_to_str(epid_group_id, quote->epid_group_id, 4, " ");
	// printf("epid size: %zu\n", u8_to_str(epid_group_id, quote->epid_group_id, 4, " "));

	char basename[32*3] = {0};
	u8_to_str(basename, (uint8_t *) &quote->basename, 32, " ");

	snprintf(dest, cap, "{\n"
			"  .version          %"PRIu16",\n"
			"  .sign_type        %"PRIu16",\n"
			"  .epid_group_id    %s,\n"
			"  .qe_svn           %"PRIu16",\n"
			"  .pce_svn          %"PRIu16",\n"
			"  .xeid             %"PRIu16",\n"
			"  .basename         %s,\n"
			"  .signature_len    %"PRIu32",\n"
			"}",

			quote->version,
			quote->sign_type,
			epid_group_id,
			quote->qe_svn,
			quote->pce_svn,
			quote->xeid,
			basename,

			quote->signature_len);
}

// TORM obsolete, use usgx
void sgx_quote_to_str_1(size_t cap, char dest[static cap],
		const sgx_quote_t *quote)
{
	char epid_group_id[12] = {0};
	u8_to_str(epid_group_id, quote->epid_group_id, 4, " ");

	char basename[32*3] = {0};
	u8_to_str(basename, (uint8_t *) &quote->basename, 32, " ");

	snprintf(dest, cap, "{"
			".version = %"PRIu16", "
			".sign_type = %"PRIu16", "
			".epid_group_id = %s, "
			".qe_svn = %"PRIu16", "
			".pce_svn = %"PRIu16", "
			".xeid = %"PRIu16", "
			".basename = %s, "
			".signature_len = %"PRIu32
			"}",

			quote->version,
			quote->sign_type,
			epid_group_id,
			quote->qe_svn,
			quote->pce_svn,
			quote->xeid,
			basename,

			quote->signature_len);
}

size_t sgx_egid_to_string_len(uint32_t egid)
{
	return 4 * 2 + 3;
}

char *sgx_egid_to_string(char *dest, uint32_t egid)
{
	char *next_pos;
	for (size_t i = 0; i < 3; i++) {
		next_pos = dest + i * (2 + 1);
		sprintf(next_pos, "%02"PRIx8" ", ((uint8_t *) &egid)[i]);
	}
	next_pos = dest + 3 * (2 + 1);
	sprintf(next_pos, "%02"PRIx8" ", ((uint8_t *) &egid)[3]);

	return dest;
}
