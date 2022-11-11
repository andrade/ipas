#pragma once

// EXIT_SUCCESS on success, `data` can be null
int load_data(void *data, size_t capacity, size_t *size, const char *path);

// EXIT_SUCCESS on success
int save_data(const void *data, size_t size, const char *path);
