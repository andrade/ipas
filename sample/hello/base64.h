#ifndef UTIL_BASE64_H
#define UTIL_BASE64_H

#include <stdint.h>

// returns output capacity needed for encoding
size_t base64_encode_fr_u8_calc_len(uint32_t input_len);

int base64_encode_fr_u8(char *output, size_t ocap,
		const uint8_t *input, uint32_t ilen);

// returns output capacity needed for decoding
size_t base64_decode_to_u8_calc_len(uint32_t input_len);
// may need less capacity, but only know that after decoding (due to padding)

int base64_decode_to_u8(uint8_t *output, uint32_t ocap, uint32_t *olen,
		const char *input, uint32_t ilen);

#endif
