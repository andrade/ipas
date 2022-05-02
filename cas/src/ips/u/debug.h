#ifndef DEBUG_H
#define DEBUG_H

#ifdef DEBUG
#define LOG(...) \
		do { if (1) fprintf(stderr, "[DEBUG] " __VA_ARGS__); } while (0)
#else
#define LOG(...) \
		do { if (0) fprintf(stderr, "[DEBUG] " __VA_ARGS__); } while (0)
		/* do nothing but still validate macro */
#endif

#endif
