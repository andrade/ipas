#include <stdint.h>

#include <arpa/inet.h>

// #include <foossl_server.h>
#include <foossl_common.h>

#include "ssl.h"

int ssl_handle_request(SSL *ssl, int (*f)(uint8_t *, uint32_t, uint32_t *, const uint8_t *, uint32_t), int (*finalize)(int))
{
	// uint8_t buf[8192 + 2*1024*1024] = {0};
	uint8_t buf[4*1024*1024] = {0}; // 4 MiB
	uint32_t len = 0;

	// read message length
	if (foossl_rexact(ssl, &len, 4)) {
		fprintf(stderr, "TLS socket read size failure\n");
		return finalize(503);
	}
	len = ntohl(len);
	fprintf(stdout, "read %"PRIu32" bytes\n", len);

	if (len > sizeof(buf)) {
		fprintf(stderr, "Error: len > cap (%"PRIu32", %zu)\n", len, sizeof(buf));
		return finalize(500);
	}

	// read message data
	if (foossl_rexact(ssl, buf, len)) {
		fprintf(stderr, "TLS socket read data failure\n");
		return finalize(504);
	}

	// process client request
	if (f(buf, sizeof(buf), &len, buf, len)) {
		// TODO return internal error to client, or terminate immediately?
		return finalize(1);
	}

	// char dest[4096] = {0};
	// u8_to_str(dest, buf, len, "");
	// fprintf(stderr, "%s\n", dest);

	// write message length
	len = htonl(len);
	if (foossl_sexact(ssl, &len, sizeof(len))) {
		fprintf(stderr, "TLS socket write size failure\n");
		return finalize(501);
	}
	len = ntohl(len);

	// write message data
	if (foossl_sexact(ssl, buf, len)) {
		fprintf(stderr, "TLS socket write data failure\n");
		return finalize(502);
	}

	return finalize(0);
}
