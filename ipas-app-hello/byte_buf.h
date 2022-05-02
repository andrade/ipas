#ifndef BYTE_BUFFER_220412_H
#define BYTE_BUFFER_220412_H

// Defines a structure for passing byte buffers around.
// Assumes 8-bit bytes and therefore uses uint8_t for storing data.

struct byte_buf {
	uint8_t *buf; // actual data
	size_t cap;   // maximum length (some call it size) of the buffer
	size_t len;   // current length (or size) of the buffer
};

// Don't forget to update `cap` and `len` fields accordingly!
// And use `struct byte_buf` don't typedef it hidding things.



// // 1: static allocation, split
// uint8_t a[64] = {0};
// struct byte_buf bb = {
// 	.buf = a,
// 	.cap = sizeof a,
// 	.len = 0,
// };
//
// // 2: dynamic allocation
// struct byte_buf bb = {
// 	.buf = malloc(64),
// 	.cap = 64,
// 	.len = 0,
// };
// // 2: requires free() after no longer needed
// free(bb.buf);
//
// // 3: static allocation, single line
// struct byte_buf bb = {
// 	.buf = (uint8_t[64]){0},
// 	.cap = 64,
// 	.len = 0,
// };



// #define MK_BYTE_BUFFER(cap) do {
// } while (0)


#endif
