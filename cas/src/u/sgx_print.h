// Copyright 2022 Daniel Andrade

// Support functions for printing SGX data types.

#ifndef SGX_PRINT_TYPES
#define SGX_PRINT_TYPES

#include <stddef.h>
#include <stdint.h>

#include <sgx_quote.h>

// TORM obsolete, use usgx
/**
** Print quote to `dest` string of capacity `cap`.
** Truncated when capacity is insufficient.
** Prints in column mode.
**/
void sgx_quote_to_str_0(size_t cap, char dest[static cap],
		const sgx_quote_t *quote);

// TORM obsolete, use usgx
/**
** Print quote to `dest` string of capacity `cap`.
** Truncated when capacity is insufficient.
** Prints in a single line.
**/
void sgx_quote_to_str_1(size_t cap, char dest[static cap],
		const sgx_quote_t *quote);

// check if fits into given cap, if not assert and return 0 (fail?) or truncate better this way doesn't fail. Caller has no excuse, can check needed size beforehand!

// length required, excluding the terminating null byte
size_t sgx_egid_to_string_len(uint32_t egid);

char *sgx_egid_to_string(char *dest, uint32_t egid);

#endif
