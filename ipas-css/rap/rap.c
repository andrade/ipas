#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include <arpa/inet.h>          // htonl, ntohl
#include <unistd.h>             // close(fd)

#include <sgx_quote.h>

#include <jansson.h>
#include "base64.h"
#include "network.h"
#include "serialization.h"

#include "debug.h"

// #include "rap.capnp.h"

#include "ra_types.h"
#include "rap.h"

/**
** Performs one cleartext network exchange with a peer.
**
** Protocol:
**   Write data size, 4 octets in network byte order
**   Write data
**   Read data size, 4 octets in network byte order
**   Read data
**
** Caller may use the same buffer as wbuf/rbuf and
** the same buffer length variable as wlen/rlen since
** data is read from socket only after writing wbuf.
**
** [o]  rbuf:  received data
** [o]  rcap:  capacity of read buffer
** [o]  rlen:  length of data in read buffer
**
** [i]  fd:    file descriptor to an open channel
** [i]  wbuf:  data to write
** [i]  wlen:  length of data to write
**
** Returns zero on success, non-zero otherwise.
**/
static int network_exchange(uint8_t *rbuf, uint32_t rcap, uint32_t *rlen, int fd, const uint8_t *wbuf, uint32_t wlen)
{
	// write length of message
	wlen = htonl(wlen);
	if (socket_write(fd, &wlen, sizeof(wlen))) {
		fprintf(stderr, "socket write size failure\n");
		return 501;
	}
	wlen = ntohl(wlen);

	// write message data
	if (socket_write(fd, wbuf, wlen)) {
		fprintf(stderr, "socket write data failure\n");
		return 502;
	}

	// read length of message
	if (socket_read(fd, rlen, 4)) {
		fprintf(stderr, "socket read size failure\n");
		return 503;
	}
	*rlen = ntohl(*rlen);

	if (*rlen > rcap) {
		fprintf(stderr, "Error: *rlen > rcap (%"PRIu32", %"PRIu32")\n", *rlen, rcap);
		return 500;
	}

	// read message data
	if (socket_read(fd, rbuf, *rlen)) {
		fprintf(stderr, "socket read data failure\n");
		return 504;
	}

	return 0;
}

// TODO Handle SigRL, right now only return HTTP status code!
/**
** Sends a Group ID to RAP, and receives the SigRL in return.
**
** [o]  code:  HTTP response code
**
** [i]  fd: file descriptor used by function (ignored, would be channel reuse)
** [i]  gid: Group ID sent to RAP
**
** Returns zero on success, non-zero otherwise.
**/
int get_sigrl(uint32_t *code, int fd_ignored, sgx_epid_group_id_t *gid)
{
	int fd;
	if ((fd = socket_connect("127.0.0.1", 7878)) < 0) {
		fprintf(stderr, "socket_connect failure\n");
		return 555;
	}


	uint8_t buffer[8192] = {0};
	uint32_t buffer_len = 0;

	struct ra_sigrl ra_sigrl = {0};
	memcpy(&(ra_sigrl.gid), gid, 4);

	// send p1 to AS (which sends it to IAS):
	if (rap_encode_request_sigrl(buffer, 8192, &buffer_len, &ra_sigrl)) {
		fprintf(stderr, "Error: rap_encode_request_sigrl\n");
		return 111;
	}

	if (network_exchange(buffer, sizeof(buffer), &buffer_len, fd, buffer, buffer_len)) {
		fprintf(stderr, "network_exchange failure\n");
		return 499;
	}

	if (rap_decode_reply_sigrl(&ra_sigrl, buffer, buffer_len)) {
		fprintf(stderr, "Error: rap_decode_reply_sigrl\n");
		return 111;
	}
	fprintf(stderr, "HTTP response code received (SigRL): %"PRIu32"\n", ra_sigrl.code);
	*code = ra_sigrl.code;


	close(fd);

	return 0;
}

/**
** Sends a quote to RAP, and receives the report in return (plus headers).
**
** [o]  code:   HTTP response code
** [o]  rid:    Request ID
** [o]  sig:    IAS signature over HTTP response body
** [o]  cc:     Certificate chain
** [o]  report: Attestation verification report produced by IAS
**
** [i]  fd: file descriptor used by function (ignored, would be channel reuse)
** [i]  quote
** [i]  quote_size
**
** Returns zero on success, non-zero otherwise.
**/
int get_report(uint32_t *code,
		char *rid, size_t rid_cap,
		char *sig, size_t sig_cap,
		char *cc, size_t cc_cap,
		char *report, size_t report_cap,
		// char *quote_status,
		int fd_ignored, sgx_quote_t *quote, uint32_t quote_size)
{
	int fd;
	if ((fd = socket_connect("127.0.0.1", 7878)) < 0) {
		fprintf(stderr, "socket_connect failure\n");
		return 555;
	}


	uint8_t buffer[8192] = {0};
	uint32_t buffer_len = 0;

	struct ra_report rr = {0};
	if (quote_size > sizeof(rr.aep.quote)) {
		fprintf(stderr, "quote too large for allocated space\n");
		return 0xE;
	}
	rr.aep.quote_size = quote_size;
	memcpy(rr.aep.quote, quote, quote_size);
	// generate request nonce: TODO function for this; do it inside enclave?
	for (size_t i = 0; i < 16; i++) {
		*(rr.aep.nonce.rand + i) = i+2;
	}

	// send p1 to AS (which sends it to IAS):
	if (rap_encode_request_report(buffer, sizeof buffer, &buffer_len, &rr)) {
		fprintf(stderr, "rap_encode_request_report\n");
		return 111;
	}

	if (network_exchange(buffer, sizeof(buffer), &buffer_len, fd, buffer, buffer_len)) {
		fprintf(stderr, "network_exchange failure\n");
		return 499;
	}

	if (rap_decode_reply_report(&rr, buffer, buffer_len)) {
		fprintf(stderr, "rap_decode_reply_report\n");
		return 111;
	}
	fprintf(stderr, "HTTP response code received (report): %"PRIu32"\n", rr.code);

	*code = rr.code;
	// strncpy(quote_status, rr.avr.quote_status, sizeof(rr.avr.quote_status));


	close(fd);

	return 0;
}
