// Copyright 2022 Daniel Andrade
// SPDX-License-Identifier: BSD-3-Clause

#include <stdbool.h>
#include <string.h>

static bool is_hex(char c)
{
	return (c >= '0' && c <= '9')
			|| (c >= 'A' && c <= 'F')
			|| (c >= 'a' && c <= 'f');
}

static char capitalize(char c)
{
	if (c >= 'a' && c <= 'z') {
		return c ^ 0x20;
	}

	return c;
}

// receives char `c` in hexadecimal and converts to its decimal ASCII encoding
// If not hex then return itself.
static int decimal(char hex)
{
	if (hex >= '0' && hex <= '9') {
		return hex - '0'; // '0' is 48 in decimal
	}

	if (hex >= 'A' && hex <= 'F') {
		return hex - 'A' + 10; // 'A' is 65 in decimal
	}

	if (hex >= 'a' && hex <= 'f') {
		return hex - 'a' + 10; // 'a' is 97 in decimal
	}

	return hex;
}

// Receives two hex chars and returns corresponding ASCII char
static char decode(char a, char b)
{
	return decimal(a) * 16 + decimal(b);
}

// RFC 3986 § 2.2 Reserved Characters
// Plus % and some other useful ones.
// Works as whitelist: when returning
// always true it decodes everything.
static bool is_reserved(char c)
{
	switch (c) {
	case '%':

	case '\n':
	case '\r':
	case ' ':

	case ':':
	case '/':
	case '?':
	case '#':
	case '[':
	case ']':
	case '@':

	case '!':
	case '$':
	case '&':
	case '\'':
	case '(':
	case ')':
	case '*':
	case '+':
	case ',':
	case ';':
	case '=':
		return true;
	default:
		return false;
	}
}

void percent_decode(char *output, const char *input)
{
	size_t len = strlen(input);

	// i is input position, j is output position
	size_t i = 0;
	size_t j = 0;
	while (i < len) {
		char c;

		if (input[i] == '%' && i + 2 < len
				&& is_hex(input[i + 1])
				&& is_hex(input[i + 2])
				&& is_reserved(c = decode(capitalize(input[i + 1]), capitalize(input[i + 2])))) {
			output[j] = c;
			i += 3;
		} else {
			output[j] = input[i];
			i++;
		}

		j++;
	}

	output[j] = '\0';
}
