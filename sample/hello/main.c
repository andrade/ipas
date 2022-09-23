#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>                     // abort(), strtoull(), exit()
#include <stdbool.h>
#include <strings.h>                    // strcasecmp()
#include <inttypes.h>
#include <unistd.h>                     // getopt()
#include <arpa/inet.h>
#include <getopt.h>

#include <foossl_client.h>
#include <foossl_common.h>

#include <sgx_urts.h>
#include <sgx_quote.h>

#include <ipas/u/attestation.h>
#include <ipas/u/sealing.h>

#include "disk.h"
#include "network.h"
#include "serialization.h"
#include "ra_types.h"

#include "css.capnp.h"
#include "enclave_u.h"

#define ENCLAVE_FILE "enclave.signed.so"

/** Default filename for sealed data. */
static const char SEALED_DATA_FILE[] = "sealed.sd";

// command-line options are stored in this structure, then fed to run functions
struct mainopts {
	const char *host;       // CSS host
	int port;               // CSS port
	const char *spid;       // unique identifier of the Service Provider
	const char *output;     // path for storing the sealed data file
	const char *input;      // path for reading the sealed data file
	const char *message;    // message to seal
};

static int create_enclave(sgx_enclave_id_t *eid)
{
	sgx_launch_token_t token = {0};
	int updated = 0;
	sgx_status_t ss = SGX_SUCCESS;

	ss = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG,
			&token, &updated, eid, NULL);
	if (SGX_SUCCESS != ss) {
		fprintf(stderr, "app error %#x, failed to create enclave\n", ss);
		return 1;
	}
	fprintf(stdout, "sgx_create_enclave(): success (eid=%"PRIu64")\n", *eid);

	return 0;
}

static int destroy_enclave(sgx_enclave_id_t *eid)
{
	if (SGX_SUCCESS != sgx_destroy_enclave(*eid)) {
		fprintf(stderr, "sgx_destroy_enclave(): failure\n");
		return 1;
	}
	fprintf(stdout, "sgx_destroy_enclave(): success\n");

	return 0;
}

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
static int ne(uint8_t *rbuf, uint32_t rcap, uint32_t *rlen, SSL *fd, const uint8_t *wbuf, uint32_t wlen)
{
	// write length of message
	wlen = htonl(wlen);
	if (foossl_sexact(fd, &wlen, sizeof(wlen))) {
		fprintf(stderr, "socket write size failure\n");
		return 501;
	}
	wlen = ntohl(wlen);

	// write message data
	if (foossl_sexact(fd, wbuf, wlen)) {
		fprintf(stderr, "socket write data failure\n");
		return 502;
	}

	// read length of message
	if (foossl_rexact(fd, rlen, 4)) {
		fprintf(stderr, "socket read size failure\n");
		return 503;
	}
	*rlen = ntohl(*rlen);

	if (*rlen > rcap) {
		fprintf(stderr, "Error: *rlen > rcap (%"PRIu32", %"PRIu32")\n", *rlen, rcap);
		return 500;
	}

	// read message data
	if (foossl_rexact(fd, rbuf, *rlen)) {
		fprintf(stderr, "socket read data failure\n");
		return 504;
	}

	return 0;
}

// NOTE: run_ma was separated into three functions so
//       it's easier to reuse during seal and unseal.

/**
** Setup of mutual attestation.
** Returns zero on success, or non-zero otherwise.
** If successfull, resources are released afterwards with `run_ma_step_3_free`.
**/
static int run_ma_step_1_init(sgx_enclave_id_t *eid, struct ipas_attest_st *ia, const char *spid)
{
	// create enclave
	if (create_enclave(eid)) {
		return 1;
	}

	// setup MA library
	if (ipas_ma_init(ia, 1, *eid, ROLE_INITIATOR, spid)) {
		fprintf(stderr, "ipas_ma_init: failure\n");
		destroy_enclave(eid);
		return 1;
	}

	return 0;
}

/**
** Executes the mutual attestation protocol.
** Invoke run_ma_step_1_init beforehand to setup enclave and library.
** Invoke run_ma_step_3_free afterwards to release resources.
** Returns zero on success, or non-zero otherwise.
**/
static int run_ma_step_2_execute(struct ipas_attest_st *ia, SSL *ssl)
{
	int r;

	size_t bsz = 8 * 1024 * 1024; // 8 MiB
	void *buffer = malloc(bsz);
	if (!buffer) {
		return 0xE2;
	}
	uint32_t length;

	// get m1 in A (initiator)
	struct ipas_ma_m1 m1 = {0};
	if (ipas_ma_get_m1(ia, &m1)) {
		fprintf(stderr, "ipas_ma_get_m1: failure\n");
		free(buffer);
		return 0xE2;
	}

	// read enclave from persistent memory
	size_t tdso_max = 5 * 1024 * 1024; // 5 MiB
	void *tdso = malloc(tdso_max);
	if (!tdso) {
		free(buffer);
		return 0xE2;
	}
	size_t tdso_size = 0;
	if (load_data(tdso, tdso_max, &tdso_size, "enclave.signed.so")) {
		fprintf(stderr, "Error: loading enclave\n");
		goto error;
	}

	// read untrusted DSO from persistent memory
	uint8_t udso[256 * 1024] = {0}; // 256 KiB
	size_t udso_size = 0;
	if (load_data(udso, sizeof(udso), &udso_size, "untrusted.so")) {
		fprintf(stderr, "Error: loading untrusted shared library\n");
		goto error;
	}

	// serialize m1
	if (encode_m1(buffer, bsz, &length,
			tdso, tdso_size,
			udso, udso_size,
			&m1.egid_a, sizeof(m1.egid_a),
			&m1.gid_a, sizeof(m1.gid_a),
			&m1.pub_a, sizeof(m1.pub_a))) {
		fprintf(stderr, "Error: encode_m1\n");
		goto error;
	}

	// send m1 to B (responder) and receive m2
	if (ne(buffer, bsz, &length, ssl, buffer, length)) {
		fprintf(stderr, "Error: m1 <> m2\n");
		goto error;
	}
	fprintf(stdout, "> Message 1\n");
	fprintf(stdout, "< Message 2\n");

	// deserialize m2
	struct ipas_ma_m2 m2 = {0};
	if (decode_m2(&m2, buffer, length)) {
		fprintf(stderr, "Error: decode_m2\n");
		goto error;
	}

	// get m3 in A (initiator)
	struct ipas_ma_m3 m3 = {0};
	if (ipas_ma_get_m3(ia, &m2, &m3)) {
		fprintf(stderr, "ipas_ma_get_m3: failure\n");
		goto error;
	}
	ipas_ma_dump_m3(&m3);

	// serialize m3
	if (encode_m3(buffer, bsz, &length, m3.quote_a, m3.size_a)) {
		fprintf(stderr, "Error: encode_m3\n");
		goto error;
	}

	// send m3 to B (responder) and receive m4
	if (ne(buffer, bsz, &length, ssl, buffer, length)) {
		fprintf(stderr, "Error: m3 <> m4\n");
		goto error;
	}
	fprintf(stdout, "> Message 3\n");
	fprintf(stdout, "< Message 4\n");

	// deserialize m4
	struct ipas_ma_m4 m4 = {0};
	if (decode_m4(&m4, buffer, length)) {
		fprintf(stderr, "Error: decode_m4\n");
		goto error;
	}

	// process m4 in A (initiator) and complete MA protocol
	if (r = ipas_ma_conclude(ia, &m4)) {
		fprintf(stderr, "ipas_ma_conclude: failure (%d)\n", r);
		goto error;
	}

	free(buffer);
	free(tdso);
	return 0;
error:
	free(buffer);
	free(tdso);
	return 0xE2;
}

/**
** Releases resources allocated on a successful call to `run_ma_step_1_init`.
**/
static void run_ma_step_3_free(sgx_enclave_id_t *eid, struct ipas_attest_st *ia)
{
	ipas_ma_free(ia);
	destroy_enclave(eid);
}

/**
** Runs the IPAS sealing protocol.
**
** Invoke only after successful MA.
**
** [i]  eid
** [i]  ssl
** [i]  toseal:         client data to seal
** [i]  toseal_size:    size of the client data to seal
** [o]  sealed_data:    the sealed data
** [o]  sd_cap:         the capacity of the sealed data buffer
** [o]  sd_len:         the actual length of `sealed_data` (on success)
**
** Returns zero on success, non-zero otherwise.
**/
static int run_sealing(sgx_enclave_id_t *eid, SSL *ssl,
		const void *toseal, size_t toseal_size,
		void *sealed_data, size_t sd_cap, size_t *sd_len)
{
	uint8_t buffer[1024] = {0};
	uint32_t length;

	// get m1 (=m11 in CSS specification) in A (initiator)
	struct ipas_s_m1 m1 = {0};
	if (ipas_s_get_m1(*eid, 1, &m1)) {
		fprintf(stderr, "ipas_s_get_m1 failure\n");
		return 0xE2;
	}

	// serialize m1
	if (encode_m11(buffer, sizeof(buffer), &length, &m1)) {
		fprintf(stderr, "Error: encode_m1\n");
		return 0xE2;
	}

	// send m1 to B (responder) and receive m2
	if (ne(buffer, sizeof(buffer), &length, ssl, buffer, length)) {
		fprintf(stderr, "Error: m1 <> m2\n");
		return 0xE2;
	}
	fprintf(stdout, "> Message 1\n");
	fprintf(stdout, "< Message 2\n");

	// deserialize m2
	struct ipas_s_m2 m2 = {0};
	if (decode_m12(&m2, buffer, length)) {
		fprintf(stderr, "Error: decode_m2\n");
		return 0xE2;
	}

	// process m2 in A (initiator) and complete sealing protocol
	if (ipas_s_conclude(*eid, 1, &m2)) {
		fprintf(stderr, "Error: ipas_s_conclude\n");
		return 0xE2;
	}


	// Now that MA completed successfully, we seal the client data:

	int r = 1;
	sgx_status_t ss = 1;
	ss = ecall_seal_data(*eid, &r, sealed_data, sd_cap, sd_len, toseal, toseal_size);
	if (ss || r) {
		fprintf(stderr, "Error: ecall_seal_data (ss=0x%"PRIx32", is=%"PRIu32")\n", ss, r);
		return 0xE3;
	}
	fprintf(stdout, "ecall_seal_data: OK\n");

	fprintf(stderr, "sd_len=%zu\n", *sd_len);

	return 0;
}

/**
** Runs the IPAS unsealing protocol.
**
** Invoke only after successful MA, otherwise libipas-sealing does
** not have access to the internal secret key for decrypting data.
**
** [i]  eid
** [i]  ssl
** [i]  data:           sealed data bundle
** [i]  size:           size of the sealed data bundle
** [o]  unsealed_data:  the unsealed data
** [o]  ud_cap:         the capacity of the unsealed data buffer
** [o]  ud_len:         the actual length of `unsealed_data` (on success)
**
** Returns zero on success, non-zero otherwise.
**/
static int run_unsealing(sgx_enclave_id_t *eid, SSL *ssl,
		const void *data, size_t size,
		void *unsealed_data, size_t ud_cap, size_t *ud_len)
{
	uint8_t buffer[1024] = {0};
	uint32_t length;

	// get m1 (=m21 in CSS specification) in A (initiator)
	struct ipas_u_m1 m1 = {0};
	// if (ipas_u_get_m1(*eid, 1, &m1, data, size)) {
	// Este data+32 é para obter o S2 que tem capsize 640. TODO
	if (ipas_u_get_m1(*eid, 1, &m1, data+32, 640)) {
		fprintf(stderr, "ipas_u_get_m1 failure\n");
		return 0xE2;
	}

	// serialize m1
	if (encode_m21(buffer, sizeof(buffer), &length, &m1)) {
		fprintf(stderr, "Error: encode_m1\n");
		return 0xE2;
	}

	// send m1 to B (responder) and receive m2
	if (ne(buffer, sizeof(buffer), &length, ssl, buffer, length)) {
		fprintf(stderr, "Error: m1 <> m2\n");
		return 0xE2;
	}
	fprintf(stdout, "> Message 1\n");
	fprintf(stdout, "< Message 2\n");

	// deserialize m2
	struct ipas_u_m2 m2 = {0};
	if (decode_m22(&m2, buffer, length)) {
		fprintf(stderr, "Error: decode_m2\n");
		return 0xE2;
	}

	// process m2 in A (initiator) and complete sealing protocol
	if (ipas_u_conclude(*eid, 1, &m2)) {
		fprintf(stderr, "Error: ipas_u_conclude\n");
		return 0xE2;
	}


	// Now that MA completed successfully, we unseal the client data:

	int r = 1;
	sgx_status_t ss = 1;
	ss = ecall_unseal_data(*eid, &r, unsealed_data, ud_cap, ud_len, data, size);
	if (ss || r) {
		fprintf(stderr, "Error: ecall_unseal_data (ss=0x%"PRIx32", is=%"PRIu32")\n", ss, r);
		return 0xE3;
	}
	fprintf(stdout, "ecall_unseal_data: OK\n");

	return 0;
}

// using single parse function for all commands, but should have one for each
static struct mainopts parse_options(int argc, char *argv[])
{
	struct mainopts options = {
		.host = "localhost",
		.port = 54433,
		.spid = "000E",
		.output = SEALED_DATA_FILE,
		.input = SEALED_DATA_FILE,
		.message = "no message set",
	};

	const struct option longopts[] = {
		{"host", required_argument, NULL, 'h'},
		{"port", required_argument, NULL, 'p'},
		{"spid", required_argument, NULL, 's'},
		{"output", required_argument, NULL, 'o'},
		{"input", required_argument, NULL, 'i'},
		{"message", required_argument, NULL, 'm'},
		{0, 0, 0, 0}
	};

	int c;

	while ((c = getopt_long(argc, argv, "h:p:s:o:i:m:", longopts, NULL)) != -1) {
		switch (c) {
		case 'h':
			options.host = optarg;
			break;
		case 'p':
			options.port = atoi(optarg);
			break;
		case 's':
			options.spid = optarg;
			break;
		case 'o':
			options.output = optarg;
			break;
		case 'i':
			options.input = optarg;
			break;
		case 'm':
			options.message = optarg;
			break;
		case '?':
			break;
		default:
			break;
		}
	}

	return options;
}

// level=0 print full help, level=1 print short version, level=2 print synopsis
static int help(int level)
{
	const char synopsis[] =
			"SYNOPSIS\n"
			"       hello help\n"
			"       hello ma     [-h host] [-p port] [-s spid]\n"
			"       hello seal   [-h host] [-p port] [-s spid] [-o output] [-m message]\n"
			"       hello unseal [-h host] [-p port] [-s spid] [-i input]\n"
			"       hello version\n"
			"\n";

	const char description[] =
			"DESCRIPTION\n"
			"       hello is a sample application of the IPAS libraries.\n"
			"\n";

	const char commands[] =
			"COMMANDS\n"
			"       help\n"
			"              Print help information.\n"
			"\n"
			"       ma\n"
			"              Mutual attestation between this client and CSS.\n"
			"\n"
			"       seal\n"
			"              Seal a message provided as input, store to disk.\n"
			"\n"
			"       unseal\n"
			"              Unseal a previously sealed message.\n"
			"\n"
			"       version\n"
			"              Display version information.\n"
			"\n";

	const char options[] =
			"OPTIONS\n"
			"       -h host, --host=host\n"
			"              CSS host.\n"
			"\n"
			"       -p port, --port=port\n"
			"              CSS port.\n"
			"\n"
			"       -s spid, --spid=spid\n"
			"              Unique identifier of the Service Provider in hex.\n"
			"\n"
			"       -o file, --output=file\n"
			"              Path for storing the application sealed data.\n"
			"\n"
			"       -i file, --input=file\n"
			"              Path for loading the application sealed data.\n"
			"\n"
			"       -m text, --message=text\n"
			"              User-provided message for sealing.\n"
			"\n";

	const char author[] =
			"AUTHOR\n"
			"       Written by Daniel Andrade.\n"
			"\n";

	switch (level) {
	case 0:
		printf("%s%s%s%s%s", synopsis, description, commands, options, author);
		return EXIT_SUCCESS;
	case 1:
		printf("try 'hello help'\n");
		return EXIT_SUCCESS;
	case 2:
	default:
		printf("%s", synopsis);
		return EXIT_SUCCESS;
	}
}

static int attest(int argc, char *argv[])
{
	struct mainopts opts = parse_options(argc, argv);
	printf("host=%s\nport=%d\nspid=%s\n", opts.host, opts.port, opts.spid);

	struct foossl_client_st foossl;

	if (foossl_client_connect(&foossl, opts.host, opts.port)) {
		perror("unable to open secure connection to remote server");
		foossl_client_destroy(&foossl);
		return -1;
	}


	// run_ma(foossl.ssl);
	sgx_enclave_id_t eid = {0};
	struct ipas_attest_st ia = {0};

	if (!run_ma_step_1_init(&eid, &ia, opts.spid)) {
		run_ma_step_2_execute(&ia, foossl.ssl);
		run_ma_step_3_free(&eid, &ia);
	}


	SSL_shutdown(foossl.ssl);
	if (foossl_client_destroy(&foossl)) {
		perror("unable to close secure connection to remote server");
		return -1;
	}

	return EXIT_SUCCESS;
}

static int seal(int argc, char *argv[])
{
	struct mainopts opts = parse_options(argc, argv);
	printf("host=%s\nport=%d\nspid=%s\n", opts.host, opts.port, opts.spid);

	char *data = opts.message;
	fprintf(stderr, "data=%s\n", data);

	struct foossl_client_st foossl;

	if (foossl_client_connect(&foossl, opts.host, opts.port)) {
		perror("unable to open secure connection to remote server");
		foossl_client_destroy(&foossl);
		return -1;
	}


	// run_ma(foossl.ssl);
	sgx_enclave_id_t eid = {0};
	struct ipas_attest_st ia = {0};

	if (!run_ma_step_1_init(&eid, &ia, opts.spid)) {
		if (!run_ma_step_2_execute(&ia, foossl.ssl)) {
			uint8_t sealed_data[4096] = {0};
			uint32_t size = 0;

			int r = run_sealing(&eid, foossl.ssl,
					data, strlen(data) + 1,
					sealed_data, sizeof(sealed_data), &size);

			if (r) {
				fprintf(stderr, "Error: run_sealing\n");
				run_ma_step_3_free(&eid, &ia);
				SSL_shutdown(foossl.ssl);
				foossl_client_destroy(&foossl);
				return EXIT_FAILURE;
			}

			// write sealed data to disk
			if (save_data(sealed_data, size, opts.output)) {
				fprintf(stderr, "Error: writing sealed data to disk\n");
				run_ma_step_3_free(&eid, &ia);
				SSL_shutdown(foossl.ssl);
				foossl_client_destroy(&foossl);
				return EXIT_FAILURE;
			}
			fprintf(stdout, "Wrote sealed data to disk (file=%s)\n", opts.output);

		}
		run_ma_step_3_free(&eid, &ia);
	}


	SSL_shutdown(foossl.ssl);
	if (foossl_client_destroy(&foossl)) {
		perror("unable to close secure connection to remote server");
		return -1;
	}

	return EXIT_SUCCESS;
}

static int unseal(int argc, char *argv[])
{
	struct mainopts opts = parse_options(argc, argv);
	printf("host=%s\nport=%d\nspid=%s\n", opts.host, opts.port, opts.spid);

	// read sealed data from disk
	uint8_t data[4096] = {0};
	size_t size = 0;
	if (load_data(data, sizeof(data), &size, opts.input)) {
		fprintf(stderr, "Error: reading sealed data from disk\n");
		return 1;
	}
	fprintf(stdout, "Read sealed data from disk (file=%s)\n", opts.input);

	char unsealed_data[256] = {0};
	size_t ud_len = 0;

	struct foossl_client_st foossl;

	if (foossl_client_connect(&foossl, opts.host, opts.port)) {
		perror("unable to open secure connection to remote server");
		foossl_client_destroy(&foossl);
		return -1;
	}


	// run_ma(foossl.ssl);
	sgx_enclave_id_t eid = {0};
	struct ipas_attest_st ia = {0};

	if (!run_ma_step_1_init(&eid, &ia, opts.spid)) {
		if (!run_ma_step_2_execute(&ia, foossl.ssl)) {
			int r = run_unsealing(&eid, foossl.ssl,
					data, size,
					unsealed_data, sizeof(unsealed_data), &ud_len);

			// do something with the unsealed data
			if (!r) {
				printf("ud: %s\n", unsealed_data);
			}

		}
		run_ma_step_3_free(&eid, &ia);
	}


	SSL_shutdown(foossl.ssl);
	if (foossl_client_destroy(&foossl)) {
		perror("unable to close secure connection to remote server");
		return -1;
	}

	return EXIT_SUCCESS;
}

static int version()
{
	fprintf(stderr, "version not implemented\n");
	return EXIT_SUCCESS;
}

// REVIEW Talvez seal melhor receber um ficheiro para seal (vem de fora mas serve para demonstrar o funcionamento; e unseal recebe depois outro ficheiro, neste caso o sealed-file-blob.)
int main(int argc, char *argv[])
{
	printf("%s\n", OPENSSL_VERSION_TEXT);

	if (argc < 2) {
		fprintf(stderr, "Bad argc, try 'hello help'\n");
		return EXIT_FAILURE;
	}

	const char *op_str = argv[1];
	if (!strcasecmp(op_str, "help")) {
		return help(0);
	} else if (!strcasecmp(op_str, "ma")) {
		return attest(--argc, ++argv);
	} else if (!strcasecmp(op_str, "seal")) {
		return seal(--argc, ++argv);
	} else if (!strcasecmp(op_str, "unseal")) {
		return unseal(--argc, ++argv);
	} else if (!strcasecmp(op_str, "version")) {
		return version();
	} else {
		fprintf(stderr, "No match, else'd out of it, try 'hello help'\n");
		return EXIT_FAILURE;
	}
}
