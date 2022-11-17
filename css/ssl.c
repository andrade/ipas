#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#include <arpa/inet.h>

// #include <foossl_server.h>
#include <foossl_common.h>

#include "debug.h"

#include "ssl.h"

int ssl_handle_request(SSL *ssl, int (*f)(uint8_t *, uint32_t, uint32_t *, const uint8_t *, uint32_t), int (*finalize)(int))
{
	size_t bsz = 8 * 1024 * 1024; // 8 MiB
	void *buf = malloc(bsz);
	if (!buf) {
		return finalize(505);
	}
	uint32_t len = 0;

	// read message length
	if (foossl_rexact(ssl, &len, 4)) {
		fprintf(stderr, "TLS socket read size failure\n");
		free(buf);
		return finalize(503);
	}
	len = ntohl(len);
	LOG("read %"PRIu32" bytes\n", len);

	if (len > bsz) {
		fprintf(stderr, "Error: len > cap (%"PRIu32", %zu)\n", len, bsz);
		free(buf);
		return finalize(500);
	}

	// read message data
	if (foossl_rexact(ssl, buf, len)) {
		fprintf(stderr, "TLS socket read data failure\n");
		free(buf);
		return finalize(504);
	}

	// process client request
	if (f(buf, bsz, &len, buf, len)) {
		// TODO return internal error to client, or terminate immediately?
		free(buf);
		return finalize(1);
	}

	// write message length
	len = htonl(len);
	if (foossl_sexact(ssl, &len, sizeof(len))) {
		fprintf(stderr, "TLS socket write size failure\n");
		free(buf);
		return finalize(501);
	}
	len = ntohl(len);

	// write message data
	if (foossl_sexact(ssl, buf, len)) {
		fprintf(stderr, "TLS socket write data failure\n");
		free(buf);
		return finalize(502);
	}

	free(buf);

	return finalize(0);
}
