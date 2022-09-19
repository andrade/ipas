#pragma once

#include <stddef.h>
#include <stdint.h>

size_t l1_hstr_to_u8(size_t cap, uint8_t dest[cap], size_t n, const char src[n]);
