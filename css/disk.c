#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "disk.h"

/**
** Finds the file size pointed to by `stream`.
**
** Returns zero on success, or non-zero on error.
** The error value is that returned by `errno`.
**/
static int fsize(size_t *size, FILE *stream)
{
	assert(stream);
	assert(size);

	if (fseek(stream, 0L, SEEK_END))
		return errno;

	long offset = ftell(stream);
	if (-1 == offset)
		return errno;
	*size = offset;

	if (fseek(stream, 0L, SEEK_SET))
		return errno;

	return 0;
}

// `data` can be null in order to find the required destination buffer size
int load_data(void *data, size_t capacity, size_t *size, const char *path)
{
	//assert(data);
	assert(size);
	assert(path);

	FILE *fp = fopen(path, "rb");
	if (!fp) {
		int errsv = errno;
		fprintf(stderr, "fopen(), failure: %s (%s)\n", strerror(errsv), path);
		return EXIT_FAILURE;
	}

	int ret = EXIT_SUCCESS;

	size_t file_size = 0;
	if ((errno = fsize(&file_size, fp))) {
		int errsv = errno;
		fprintf(stderr, "fsize(), failure: %s\n", strerror(errsv));
		ret = EXIT_FAILURE;
		goto finally;
	}
	*size = file_size;

	if (!data) {
		goto finally;  // leave early, goal is to find the required buffer size
	}

	if (file_size > capacity) {
		fprintf(stderr,
				"Destination buffer too small (capacity=%zu, required=%zu)\n",
				capacity, file_size);
		ret = EXIT_FAILURE;
		goto finally;
	}

	if (fread(data, file_size, 1, fp) != 1) {
		fprintf(stderr, "fread(), failure\n");
		ret = EXIT_FAILURE;
		goto finally;
	}

finally:
	if (fclose(fp)) {
		int errsv = errno;
		fprintf(stderr, "fclose(), failure: %s\n", strerror(errsv));
		ret = EXIT_FAILURE;
	}
	return ret;
}

int save_data(const void *data, size_t size, const char *path)
{
	assert(data);
	assert(path);

	FILE *fp = fopen(path, "wb");
	if (!fp) {
		int errsv = errno;
		fprintf(stderr, "fopen(), failure: %s (%s)\n", strerror(errsv), path);
		return EXIT_FAILURE;
	}

	int ret = EXIT_SUCCESS;

	if (fwrite(data, size, 1, fp) != 1) {
		fprintf(stderr, "fwrite(), failure\n");
		ret = EXIT_FAILURE;
	}

	if (fclose(fp)) {
		int errsv = errno;
		fprintf(stderr, "fclose(), failure: %s\n", strerror(errsv));
		ret = EXIT_FAILURE;
	}

	return ret;
}
