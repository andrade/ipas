#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>                     // abort(), strtoull(), exit()
#include <stdbool.h>
#include <strings.h>                    // strcasecmp()
#include <inttypes.h>
#include <unistd.h>                     // getopt()
#include <arpa/inet.h>

#include <foossl_client.h>
#include <foossl_common.h>

#include <sgx_urts.h>
#include <sgx_quote.h>

// #include <u/util.h>

#include <ipas/u/attestation.h>
#include <ipas/u/sealing.h>

#include "enclave_u.h"
#include "disk.h"
// #include "network2.h"

#include "network.h"
#include "serialization.h"
#include "ra_types.h"

#include "cebug.h"


#include "css.capnp.h"

#define ENCLAVE_FILE "enclave.signed.so"

static const char SEALED_DATA_FILE[] = "sealed.sd";

// static const char SRX_STATE_PATH[] = "data.srx";
// static const char INIT_RP_PATH[] = "rpinit.srx";

// static uint64_t str2u64(const char *s)
// {
// 	errno = 0;
// 	char *endptr = NULL;
//
// 	unsigned long long int ull = strtoull(s, &endptr, 0);
//
// 	if (errno || ull > UINT64_MAX) {
// 		abort();
// 	}
// 	if (s == endptr) {
// 		fprintf(stderr, "`%s` is not a number\n", s);
// 		abort();
// 	}
//
// 	return (uint64_t) ull;
// }
//
// static void print_ret(const char *func, sgx_status_t ss, srx_status xs)
// {
// 	const char s[] = "%s:\n«SGX = OK»\n«SRX = %s»\n";
// 	fprintf(stdout, s, func, srxerror(xs));
// }
//
// static void print_uint8a(const uint8_t *src, size_t n, char mod)
// {
// 	if (0 == n) {
// 		printf("\n");
// 	} else if ('x' == mod) {
// 		for (size_t i = 0; i < n - 1; i++)
// 			printf("%02"PRIx8":", src[i]);
// 		printf("%02"PRIx8"\n", src[n - 1]);
// 	} else if ('d' == mod){
// 		for (size_t i = 0; i < n - 1; i++)
// 			printf("%03"PRIu8":", src[i]);
// 		printf("%03"PRIu8"\n", src[n - 1]);
// 	} else {
// 		printf("Unknown mod (`%c`) in `print_uint8a`\n", mod);
// 	}
// }

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

// static int handle_init(bool overwrite)
// {
// 	if (server_connect()) {
// 		fprintf(stderr, "could not connect to the remote server\n");
// 		return EXIT_FAILURE;
// 	}
//
// 	sgx_enclave_id_t eid;
// 	sgx_status_t ss = SGX_SUCCESS;
// 	srx_status xs = 0;
//
// 	if (create_enclave(&eid))
// 		return EXIT_FAILURE;
//
// 	ss = ecall_srx_init(eid, &xs, SRX_STATE_PATH);
// 	if (SGX_SUCCESS != ss) {
// 		fprintf(stderr, "ecall_srx_init(): failure\n");
// 		destroy_enclave(&eid);
// 		return EXIT_FAILURE;
// 	}
// 	print_ret("ecall_srx_init()", 0, xs);
//
// 	if (destroy_enclave(&eid))
// 		return EXIT_FAILURE;
//
// 	server_disconnect();
//
// 	return EXIT_SUCCESS;
// }
//
// static int handle_auth()
// {
// 	sgx_enclave_id_t eid;
// 	sgx_status_t ss;
// 	srx_status xs;
//
// 	if (create_enclave(&eid))
// 		return EXIT_FAILURE;
//
// 	ss = trigger_auth(eid, &xs, SRX_STATE_PATH);
// 	if (SGX_SUCCESS != ss) {
// 		fprintf(stderr, "ecall_srx_auth(): failure\n");
// 		destroy_enclave(&eid);
// 		return EXIT_FAILURE;
// 	}
// 	print_ret("ecall_srx_auth()", 0, xs);
//
// 	if (destroy_enclave(&eid))
// 		return EXIT_FAILURE;
//
// 	return EXIT_SUCCESS;
// }
//
// // `str` is salt, `length` is length of secret key, `policy` is auth requirement
// static int handle_get_sk(const char *str, int length, int policy)
// {
// 	uint8_t salt[strlen(str)];
// 	memcpy(salt, str, strlen(str));
//
// 	uint8_t sk[length];
//
// 	sgx_enclave_id_t eid;
// 	sgx_status_t ss;
// 	srx_status xs;
//
// 	if (create_enclave(&eid))
// 		return EXIT_FAILURE;
//
// 	ss = trigger_get_sk(eid, &xs,
// 			SRX_STATE_PATH, salt, sizeof salt, sk, length, policy);
// 	if (SGX_SUCCESS != ss) {
// 		fprintf(stderr, "ecall_srx_get_sk(): failure\n");
// 		destroy_enclave(&eid);
// 		return EXIT_FAILURE;
// 	}
// 	print_ret("ecall_srx_get_sk()", 0, xs);
//
// 	if (destroy_enclave(&eid))
// 		return EXIT_FAILURE;
//
// 	print_uint8a(sk, length, 'x');
//
// 	return EXIT_SUCCESS;
// }
//
// static int handle_init_rp()
// {
// 	if (server_connect()) {
// 		fprintf(stderr, "could not connect to the remote server\n");
// 		return EXIT_FAILURE;
// 	}
//
// 	sgx_enclave_id_t eid;
// 	sgx_status_t ss = SGX_SUCCESS;
// 	srx_status xs = 0;
// 	uint8_t buf[1024] = {0};
// 	size_t size = 0;
//
// 	if (create_enclave(&eid))
// 		return EXIT_FAILURE;
//
// 	ss = ecall_srx_init_rp(eid, &xs, buf, sizeof buf, &size);
// 	if (SGX_SUCCESS != ss) {
// 		fprintf(stderr, "ecall_srx_init_rp(): failure\n");
// 		destroy_enclave(&eid);
// 		return EXIT_FAILURE;
// 	}
// 	print_ret("ecall_srx_init_rp()", 0, xs);
//
// 	if (destroy_enclave(&eid))
// 		return EXIT_FAILURE;
//
// 	server_disconnect();
//
// 	if (save_data(buf, size, INIT_RP_PATH))
// 		return EXIT_FAILURE;
// 	fprintf(stdout, "handle_init_rp: wrote %zu bytes to disk (%s)\n",
// 			size, INIT_RP_PATH);
//
// 	return EXIT_SUCCESS;
// }
//
// static int handle_add_rp()
// {
// 	uint8_t buf[1024] = {0};
// 	size_t size = 0;
// 	if (load_data(buf, sizeof buf, &size, INIT_RP_PATH))
// 		return EXIT_FAILURE;
// 	fprintf(stdout, "handle_add_rp: read %zu bytes from disk (%s)\n",
// 			size, INIT_RP_PATH);
//
// 	sgx_enclave_id_t eid;
// 	sgx_status_t ss;
// 	srx_status xs;
//
// 	if (create_enclave(&eid))
// 		return EXIT_FAILURE;
//
// 	ss = trigger_add_rp(eid, &xs, SRX_STATE_PATH, buf, size);
// 	if (SGX_SUCCESS != ss) {
// 		fprintf(stderr, "ecall_srx_add_rp(): failure\n");
// 		destroy_enclave(&eid);
// 		return EXIT_FAILURE;
// 	}
// 	print_ret("ecall_srx_add_rp()", 0, xs);
//
// 	if (destroy_enclave(&eid))
// 		return EXIT_FAILURE;
//
// 	return EXIT_SUCCESS;
// }
//
// static int handle_remove_rp(uint64_t rpid)
// {
// 	sgx_enclave_id_t eid;
// 	sgx_status_t ss;
// 	srx_status xs;
//
// 	if (create_enclave(&eid))
// 		return EXIT_FAILURE;
//
// 	ss = trigger_remove_rp(eid, &xs, SRX_STATE_PATH, rpid);
// 	if (SGX_SUCCESS != ss) {
// 		fprintf(stderr, "ecall_srx_remove_rp(): failure\n");
// 		destroy_enclave(&eid);
// 		return EXIT_FAILURE;
// 	}
// 	print_ret("ecall_srx_remove_rp()", 0, xs);
//
// 	if (destroy_enclave(&eid))
// 		return EXIT_FAILURE;
//
// 	return EXIT_SUCCESS;
// }
//
// static int handle_list()
// {
// 	size_t cap = 32;
// 	uint64_t pids[cap];
// 	size_t count;
//
// 	sgx_enclave_id_t eid;
// 	sgx_status_t ss;
// 	srx_status xs;
//
// 	if (create_enclave(&eid))
// 		return EXIT_FAILURE;
//
// 	ss = trigger_list(eid, &xs, pids, cap, &count, SRX_STATE_PATH);
// 	if (SGX_SUCCESS != ss) {
// 		fprintf(stderr, "ecall_srx_list(): failure\n");
// 		destroy_enclave(&eid);
// 		return EXIT_FAILURE;
// 	}
// 	print_ret("ecall_srx_list()", 0, xs);
//
// 	if (destroy_enclave(&eid))
// 		return EXIT_FAILURE;
//
// 	if (!xs) {
// 		for (size_t i = 0; i < count; i++) {
// 			fprintf(stdout, "%3zu: 0x%016"PRIx64"\n", i, pids[i]);
// 		}
// 	}
//
// 	return EXIT_SUCCESS;
// }
//
// static int handle_dump()
// {
// 	char buf[4096] = {0};
//
// 	sgx_enclave_id_t eid;
// 	sgx_status_t ss;
// 	int ecall_return;
//
// 	if (create_enclave(&eid))
// 		return EXIT_FAILURE;
//
// 	ss = ecall_srx_dump(eid, &ecall_return, buf, sizeof buf, SRX_STATE_PATH);
// 	if (SGX_SUCCESS != ss) {
// 		fprintf(stderr, "ecall_srx_dump(): failure\n");
// 		destroy_enclave(&eid);
// 		return EXIT_FAILURE;
// 	}
// 	fprintf(stdout, "ecall_srx_dump(): SGX=OK, retval=%d\n", ecall_return);
//
// 	if (destroy_enclave(&eid))
// 		return EXIT_FAILURE;
//
// 	if (!ecall_return) {
// 		fprintf(stdout, "%s", buf);
// 	}
//
// 	return EXIT_SUCCESS;
// }
//
// static void print_usage(const char *prog)
// {
// 	fprintf(stderr, "Usage: %s <init[-f] "
// 			"| auth "
// 			"| sk -s <salt> -L <length> -P <policy> " // ex: `-s 123 -L 16 -P 0`
// 			"| init-rp "
// 			"| add-rp "
// 			"| remove -p <rpid> "
// 			"| list "
// 			"| dump>\n", prog);
// }

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

#if 0
//NOTE  this was the intiial version to test TLS, real one for SGX is below
static int test(SSL *ssl)
{
	uint8_t buffer[8192 + 2*1024*1024] = {0};
	uint32_t length;

	// read enclave from persistent memory
	// uint8_t enclave[350] = {0x01, 0x02, 0x05}; // TODO read enclave from disk
	uint8_t enclave[2*1024*1024] = {0};
	size_t size = 0;
	if (load_data(enclave, sizeof(enclave), &size, "enclave.signed.so")) {
		fprintf(stderr, "Error: loading enclave\n");
		return 1;
	}

	// serialize m1
	if (encode_m1(buffer, sizeof(buffer), &length, enclave, sizeof(enclave))) {
		fprintf(stderr, "Error: encode_m1\n");
		return 1;
	}

	// send m1, receive m2
	if (ne(buffer, sizeof(buffer), &length, ssl, buffer, length)) {
		fprintf(stderr, "Error: m1 <> m2\n");
		return 1;
	}

	// deserialize m2
	// TODO
	if (decode_m2(/* output stuff here */buffer, length)) {
		fprintf(stderr, "Error: decode m2\n");
		return 1;
	}

	// serialize m3
	uint8_t quote[1089] = {[0 ... 1088] = 0x55}; // TEMP
	if (encode_m3(buffer, sizeof(buffer), &length, quote, sizeof(quote))) {
		fprintf(stderr, "Error: encode_m3\n");
		return 1;
	}

	// send m3, receive m4
	if (ne(buffer, sizeof(buffer), &length, ssl, buffer, length)) {
		fprintf(stderr, "Error: m3 <> m4\n");
		return 1;
	}

	// deserialize m4
	// TODO
	if (decode_m4(/* output stuff here */buffer, length)) {
		fprintf(stderr, "Error: decode m4\n");
		return 1;
	}


	// {
	// 	// Teste: Consigo deserializar correctamente?
	// 	struct capn rc;
	// 	int init_mem_ret = capn_init_mem(&rc, buffer, length, 0);
	// 	assert(!init_mem_ret);
	//
	// 	struct Message m;
	// 	Message_ptr root = { .p = capn_getp(capn_root(&rc), 0, 1) };
	// 	{
	// 		// DEBUG
	// 		// NOTE pelo código interno da biblioteca, se capn_getp falhar tudo 0s
	// 		// Imprimindo a estrutura, parecem lá estar os 350 bytes set a 0xff.
	// 		// Então porque está a falhar a leitura dos bytes do enclave???
	// 		//
	// 		// char dest[4096] = {0};
	// 		// u8_to_str(dest, (uint8_t *) &root, 750, "");
	// 		// fprintf(stderr, "%s\n", dest);
	// 	}
	// 	read_Message(&m, root);
	//
	// 	printf("deserialized request, which index is: %d\n", m.which);
	//
	// 	struct M1Q m1;
	// 	// M1Q_ptr p1 = { .p = capn_getp(capn_root(&rc), 0, 1) };
	// 	// read_M1Q(&m1, p1);
	// 	read_M1Q(&m1, m.m1);
	//
	// 	printf("sizeof(enclave)=%d\n", m1.enclave.p.len);
	// 	{
	// 		char dest[4096] = {0};
	// 		u8_to_str(dest, m1.enclave.p.data, m1.enclave.p.len, "");
	// 		fprintf(stderr, "%s\n", dest);
	// 	}
	//
	// 	printf("sizeof(aExGroup)=%d\n", m1.aExGroup.p.len);
	// 	{
	// 		char dest[4096] = {0};
	// 		u8_to_str(dest, m1.aExGroup.p.data, m1.aExGroup.p.len, "");
	// 		fprintf(stderr, "%s\n", dest);
	// 	}
	// }


	// len = htonl(len);
	// if (foossl_sexact(ssl, &len, sizeof(len))) {
	// 	fprintf(stderr, "socket write size failure\n");
	// 	return 501;
	// }
	// len = ntohl(len);
	//
	//
	// // strcpy(buffer, "foo foo two");
	// if (foossl_sexact(ssl, output, len)) {
	// 	fprintf(stderr, "could not write %d bytes\n", len);
	// 	return -1;
	// }
	// printf("ssl write: %s\n", buffer);
	//
	// if (foossl_rexact(ssl, &len, sizeof(len))) {
	// 	fprintf(stderr, "could not read %d bytes\n", n);
	// 	return -1;
	// }
	// len = ntohl(len);
	// printf("ssl read: %s\n", buffer);
	//
	// strcpy(buffer, "client says hello");
	//
	// if (foossl_rexact(ssl, buffer, len)) {
	// 	fprintf(stderr, "could not read %d bytes\n", len);
	// 	return -1;
	// }
	// buffer[len] = '\0';
	// fprintf(stdout, "read %"PRIu32" bytes\n", len);

	return 0;
}
#endif

// NOTE: run_ma was separated into three functions so
//       it's easier to reuse during seal and unseal.

/**
** Setup of mutual attestation.
** Returns zero on success, or non-zero otherwise.
** If successfull, resources are released afterwards with `run_ma_step_3_free`.
**/
static int run_ma_step_1_init(sgx_enclave_id_t *eid, struct ipas_attest_st *ia)
{
	// create enclave
	if (create_enclave(eid)) {
		return 1;
	}

	// setup MA library
	if (ipas_ma_init(ia, 1, *eid, NULL, ROLE_INITIATOR)) {
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

	uint8_t buffer[8192 + 3*1024*1024] = {0};
	uint32_t length;

	// get m1 in A (initiator)
	struct ipas_ma_m1 m1 = {0};
	if (ipas_ma_get_m1(ia, &m1)) {
		fprintf(stderr, "ipas_ma_get_m1: failure\n");
		return 0xE2;
	}

	// read enclave from persistent memory
	uint8_t tdso[2*1024*1024] = {0};
	size_t tdso_size = 0;
	if (load_data(tdso, sizeof(tdso), &tdso_size, "enclave.signed.so")) {
		fprintf(stderr, "Error: loading enclave\n");
		return 0xE2;
	}

	// read untrusted DSO from persistent memory
	uint8_t udso[64*1024] = {0};
	size_t udso_size = 0;
	if (load_data(udso, sizeof(udso), &udso_size, "untrusted.so")) {
		fprintf(stderr, "Error: loading untrusted shared library\n");
		return 0xE2;
	}

	// serialize m1
	if (encode_m1(buffer, sizeof(buffer), &length,
			tdso, tdso_size,
			udso, udso_size,
			&m1.egid_a, sizeof(m1.egid_a),
			&m1.gid_a, sizeof(m1.gid_a),
			&m1.pub_a, sizeof(m1.pub_a))) {
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
	struct ipas_ma_m2 m2 = {0};
	if (decode_m2(&m2, buffer, length)) {
		fprintf(stderr, "Error: decode_m2\n");
		return 0xE2;
	}

	// get m3 in A (initiator)
	struct ipas_ma_m3 m3 = {0};
	if (ipas_ma_get_m3(ia, &m2, &m3)) {
		fprintf(stderr, "ipas_ma_get_m3: failure\n");
		return 0xE2;
	}
	ipas_ma_dump_m3(&m3);

	// serialize m3
	if (encode_m3(buffer, sizeof(buffer), &length, m3.quote_a, m3.size_a)) {
		fprintf(stderr, "Error: encode_m3\n");
		return 0xE2;
	}

	// send m3 to B (responder) and receive m4
	if (ne(buffer, sizeof(buffer), &length, ssl, buffer, length)) {
		fprintf(stderr, "Error: m3 <> m4\n");
		return 0xE2;
	}
	fprintf(stdout, "> Message 3\n");
	fprintf(stdout, "< Message 4\n");

	// deserialize m4
	struct ipas_ma_m4 m4 = {0};
	if (decode_m4(&m4, buffer, length)) {
		fprintf(stderr, "Error: decode_m4\n");
		return 0xE2;
	}

	// process m4 in A (initiator) and complete MA protocol
	if (r = ipas_ma_conclude(ia, &m4)) {
		fprintf(stderr, "ipas_ma_conclude: failure (%d)\n", r);
		return 0xE2;
	}

	return 0;
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
** The sealed data is stored in a file named by constant `SEALED_DATA_FILE`.
**
** [i]  eid
** [i]  ssl
** [i]  data:           client data to seal
** [i]  size:           size of the client data to seal
**
** Returns zero on success, non-zero otherwise.
**/
static int run_sealing(sgx_enclave_id_t *eid, SSL *ssl,
		const void *toseal, size_t toseal_size)
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

	uint8_t sealed_data[4096] = {0};
	uint32_t size = 0;

	int r = 1;
	sgx_status_t ss = 1;
	ss = ecall_seal_data(*eid, &r, sealed_data, sizeof(sealed_data), &size, toseal, toseal_size);
	if (ss || r) {
		fprintf(stderr, "Error: ecall_seal_data (ss=0x%"PRIx32", is=%"PRIu32")\n", ss, r);
		return 0xE3;
	}
	fprintf(stdout, "ecall_seal_data: OK\n");

	fprintf(stderr, "sd_len=%"PRIu32"\n", size);

	// write sealed data to disk
	if (save_data(sealed_data, size, SEALED_DATA_FILE)) {
		fprintf(stderr, "Error: writing sealed data to disk\n");
		return 0xE4;
	}
	fprintf(stdout, "Wrote sealed data to disk (file=%s)\n", SEALED_DATA_FILE);

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

static int help()
{
	const char *help = "$ hello help";
	const char *ma = "$ hello ma <host> <port>";
	const char *seal = "$ hello seal <host> <port> <data>";
	const char *unseal = "$ hello unseal <host> <port> <sealed blob>";
	const char *version = "$ hello version";

	fprintf(stdout, "  %s\n  %s\n  %s\n  %s\n  %s\n",
			help, ma, seal, unseal, version);

	return EXIT_SUCCESS;
}

static int attest(int argc, char *argv[])
{
	if (argc < 3) {
		fprintf(stderr, "Expected: $ hello ma <host> <port>\n");
		return EXIT_FAILURE;
	}

	const char *host = argv[1];
	int port = atoi(argv[2]);

	struct foossl_client_st foossl;

	if (foossl_client_connect(&foossl, host, port)) {
		perror("unable to open secure connection to remote server");
		foossl_client_destroy(&foossl);
		return -1;
	}


	// run_ma(foossl.ssl);
	sgx_enclave_id_t eid = {0};
	struct ipas_attest_st ia = {0};

	if (!run_ma_step_1_init(&eid, &ia)) {
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
	if (argc < 4) {
		fprintf(stderr, "$ hello seal <host> <port> <data>\n");
		return EXIT_FAILURE;
	}

	const char *host = argv[1];
	int port = atoi(argv[2]);
	char *data = argv[3];

	fprintf(stderr, "data=%s\n", data);

	struct foossl_client_st foossl;

	if (foossl_client_connect(&foossl, host, port)) {
		perror("unable to open secure connection to remote server");
		foossl_client_destroy(&foossl);
		return -1;
	}


	// run_ma(foossl.ssl);
	sgx_enclave_id_t eid = {0};
	struct ipas_attest_st ia = {0};

	if (!run_ma_step_1_init(&eid, &ia)) {
		if (!run_ma_step_2_execute(&ia, foossl.ssl)) {
			run_sealing(&eid, foossl.ssl, data, strlen(data) + 1);
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
	if (argc < 3) {
		fprintf(stderr, "$ hello unseal <host> <port>\n");
		return EXIT_FAILURE;
	}

	const char *host = argv[1];
	int port = atoi(argv[2]);

	// read sealed data from disk
	uint8_t data[4096] = {0};
	size_t size = 0;
	if (load_data(data, sizeof(data), &size, SEALED_DATA_FILE)) {
		fprintf(stderr, "Error: reading sealed data from disk\n");
		return 1;
	}
	fprintf(stdout, "Read sealed data from disk (file=%s)\n", SEALED_DATA_FILE);

	char unsealed_data[256] = {0};
	size_t ud_len = 0;

	struct foossl_client_st foossl;

	if (foossl_client_connect(&foossl, host, port)) {
		perror("unable to open secure connection to remote server");
		foossl_client_destroy(&foossl);
		return -1;
	}


	// run_ma(foossl.ssl);
	sgx_enclave_id_t eid = {0};
	struct ipas_attest_st ia = {0};

	if (!run_ma_step_1_init(&eid, &ia)) {
		if (!run_ma_step_2_execute(&ia, foossl.ssl)) {
			int r = run_unsealing(&eid, foossl.ssl, data, size, unsealed_data, sizeof(unsealed_data), &ud_len);

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

// TODO:
// $ hello ma <ip | css-ip>
// $ hello seal <output file> <css-ip> <data>
// $ hello unseal <sealed blob> <css-ip>
// Talvez seal melhor receber um ficheiro para seal (vem de fora mas serve para demonstrar o funcionamento; e unseal recebe depois outro ficheiro, neste caso o sealed-file-blob.)
int main(int argc, char *argv[])
{
	printf("%s\n", OPENSSL_VERSION_TEXT);

	if (argc < 2) {
		fprintf(stderr, "Bad argc\n");
		return EXIT_FAILURE;
	}

	const char *op_str = argv[1];
	if (!strcasecmp(op_str, "help")) {
		return help();
	} else if (!strcasecmp(op_str, "ma")) {
		return attest(--argc, ++argv);
	} else if (!strcasecmp(op_str, "seal")) {
		return seal(--argc, ++argv);
	} else if (!strcasecmp(op_str, "unseal")) {
		return unseal(--argc, ++argv);
	} else if (!strcasecmp(op_str, "version")) {
		return version();
	} else {
		fprintf(stderr, "No match, else'd out of it\n");
		return EXIT_FAILURE;
	}
}
