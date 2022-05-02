#ifndef CEBUG_H
#define CEBUG_H

#ifdef DEBUG
#include <stdio.h>
#include <inttypes.h>
#include <string.h>
#define CEBUG_DB(s, a, n) \
		do { if (1) { \
			if ((a) == NULL || (n) <= 0) break; \
			size_t _n = (n); \
\
			char *_s = (s);\
			char l1[48];\
			if (!_s) snprintf(l1, 48, "[CEBUG] %36s  -", "");\
			else if (strlen(_s)<=36) snprintf(l1, 48, "[CEBUG] %-36s  -", _s);\
			else snprintf(l1, 48, "[CEBUG] %-.36s \\-", _s);\
			const char *L2 = "-----------------------------------------------";\
\
			size_t cut = 1024; \
\
			char dest[47*2 + 1024*2 + (1024-1) + (1024/16-1) + 1] = {0}; \
			const uint8_t *src = (const void *) (a); \
\
			char *next_pos = dest; \
			size_t max = _n < cut ? _n : cut; \
			for (size_t i = 0; i < max - 1; i++, next_pos += 2 + 1) {  \
				if (i > 0 && i % 16 == 0) sprintf(next_pos - 1, "\n"); \
				sprintf(next_pos, "%02"PRIx8" ", src[i]);              \
			}                                                          \
			if (_n <= cut)                                   \
				sprintf(next_pos, "%02"PRIx8, src[max - 1]); \
			else                                             \
				sprintf(--next_pos, "...");                  \
\
			fprintf(stderr, "%s\n%s\n%s\n", l1, dest, L2); \
		}} while (0)
#else
#define CEBUG_DB(a, n) \
		do { } while (0)
#endif

#endif
