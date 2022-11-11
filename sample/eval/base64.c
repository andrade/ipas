#include <assert.h>
#include <stdlib.h>
#include <stdio.h>

#include "cencode.h"
#include "cdecode.h"

#include "base64.h"

// handles padding, but assumes no line breaks; adds +1 for \0
size_t base64_encode_fr_u8_calc_len(uint32_t input_len)
{
	return ((input_len * 4 / 3 + 3) & ~3) + 1; // last 1 is null-termination
}

// output is NUL-terminated
int base64_encode_fr_u8(char *output, size_t ocap,
		const uint8_t *input, uint32_t ilen)
{
	assert(ilen == 0 || input != NULL);

	if (ilen == 0) {
		output[0] = '\0';
		return 0;
	}

	/*
	** base64 is always a multiple of four (might be padded).
	** each base64 digit represents 6 bits of data, meaning
	** three bytes (24 bits) are encoded into four bytes.
	*/
	//size_t buf_size = ((input_size + 2) / 3) * 4 + 1;
	//FIXME:  Formula above resulting in errors.
	// size_t buf_size = input_size * 2; // larger than necessary
	//
	// char *p = malloc(buf_size);
	// if (!p)
	// 	return -1;
	// //memset(p, '\0', buf_size);

	char *in = (char *) input;
	char *current = output;
	int count = 0;

	base64_encodestate s;
	base64_init_encodestate(&s);
	count = base64_encode_block(in, ilen, current, &s);
	current += count;
	count = base64_encode_blockend(current, &s);
	current += count;

	*current = '\0';

	fprintf(stderr, "encoded in base 64:\n%s\n", output);

	return 0;
}

size_t base64_decode_to_u8_calc_len(uint32_t input_len)
{
	return input_len * 3 / 4; // not including +1 for null-termination
}

// input is NUL-terminated
int base64_decode_to_u8(uint8_t *output, uint32_t ocap, uint32_t *olen,
		const char *input, uint32_t ilen)
{
	assert(ilen == 0 || input != NULL);

	if (ilen == 0) {
		*olen = 0;
		return 0;
	}

	char *pos = (char *) output;
	int count = 0;

	base64_decodestate s;
	base64_init_decodestate(&s);
	count = base64_decode_block(input, ilen, pos, &s);
	pos += count;
	/* no decode blockend */

	// *olen = pos - input;
	*olen = count;

	return 0;
}
