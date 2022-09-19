#include <assert.h>

#include "one.h"

static size_t min(size_t a, size_t b)
{
	return a < b ? a : b;
}

size_t l1_hstr_to_u8(size_t cap, uint8_t dest[cap], size_t n, const char src[n])
{
	if (dest == NULL) {
		if (cap)
			return min(n / 2 + n % 2, cap);
		else
			return n / 2 + n % 2;
	}

	if (cap == 0)
		return 0;

	size_t pos = 0;

	if (n % 2 != 0) {
		uint8_t right;

		if (src[0] >= '0' && src[0] <= '9') {
			right = src[0] - '0';
		} else if (src[0] >= 'a' && src[0] <= 'f') {
			right = src[0] - 'a' + 10;
		} else if (src[0] >= 'A' && src[0] <= 'F') {
			right = src[0] - 'A' + 10;
		} else {
			right = 0x00;
			assert(right);
		}

		dest[pos++] = 0x0f & right;
	}

	for (size_t i = pos; i < n && pos < cap; i += 2) {
		uint8_t left, right;

		if (src[i] >= '0' && src[i] <= '9') {
			left = src[i] - '0';
		} else if (src[i] >= 'a' && src[i] <= 'f') {
			left = src[i] - 'a' + 10;
		} else if (src[i] >= 'A' && src[i] <= 'F') {
			left = src[i] - 'A' + 10;
		} else {
			left = 0x00;
			assert(left);
		}

		if (src[i+1] >= '0' && src[i+1] <= '9') {
			right = src[i+1] - '0';
		} else if (src[i+1] >= 'a' && src[i+1] <= 'f') {
			right = src[i+1] - 'a' + 10;
		} else if (src[i+1] >= 'A' && src[i+1] <= 'F') {
			right = src[i+1] - 'A' + 10;
		} else {
			right = 0x00;
			assert(right);
		}

		dest[pos++] = (0xf0 & left << 4) | (0x0f & right << 0);
	}

	return pos;
}
