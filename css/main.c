#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include <assert.h>
#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <strings.h>
#include <inttypes.h>
#include <limits.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <foossl_server.h>
#include <foossl_common.h>

#include <sgx_urts.h>
#include <sgx_quote.h>

#include <ipas/u/attestation.h>
#include <ipas/u/sealing.h>

#include "cebug.h"
#include "debug.h"
#include "ssl.h"

// #include "rap/network.h"
// #include "rap/ra_types.h"
#include "rap/rap.h"

#include "css.capnp.h"

static sgx_enclave_id_t eid; // enclave received from client
static struct ipas_attest_st ia; // MA context
static void *udso_h; // dlopen handle for the untrusted DSO

static int create_enclave_from_buf(sgx_enclave_id_t *eid, uint8_t *enclave, size_t size)
{
	sgx_status_t ss = SGX_SUCCESS;

	ss = sgx_create_enclave_from_buffer_ex(enclave, size, SGX_DEBUG_FLAG,
			eid, NULL, 0, NULL);
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

// write binary using file descriptor
static int write_bd(const void *data, size_t size, const int *fd)
{
	assert(data);

	FILE *fp = fdopen(fd, "wb");
	if (!fp) {
		int errsv = errno;
		LOG("Error: fdopen() (%s)\n", strerror(errsv));
		return EXIT_FAILURE;
	}

	int ret = EXIT_SUCCESS;

	if (fwrite(data, size, 1, fp) != 1) {
		LOG("Error: fwrite()\n");
		ret = EXIT_FAILURE;
	}

	if (fclose(fp)) {
		int errsv = errno;
		LOG("Error: fclose() (%s)\n", strerror(errsv));
		ret = EXIT_FAILURE;
	}

	return ret;
}

// on success handle will be set and must be released by caller with dlclose
static void *dlopen_from_buf(const void *dso, size_t size, int flags)
{
	assert(dso);
	assert(size > 0);

	// temporary file path for untrusted DSO
	char template[] = "untrusted.so.XXXXXX";
	int fd = mkstemp(template);
	if (fd == -1) {
		LOG("Error: mkstemp\n");
		return NULL;
	}

	// save untrusted DSO to temporary location
	if (write_bd(dso, size, fd)) {
		LOG("Error: saving untrusted code shared object to disk\n");
		unlink(template);
		return NULL;
	}

	char path[PATH_MAX];
	if (!realpath(template, path)) {
		LOG("Error: realpath()\n");
		unlink(template);
		return NULL;
	}
	LOG("real path: %s\n", path);

	dlerror();
	void *handle = dlopen(path, flags);
	if (!handle) {
		LOG("Error: dlopening untrusted code shared object (%s)\n", dlerror());
		unlink(path);
		return NULL;
	}
	LOG("Loaded untrusted DSO\n");

	if (unlink(path)) {
		LOG("Warning: unlink (%s)\n", strerror(errno));
		// keep going
	}

	return handle;
}

// data buffer to capn_data: on error (struct is zeroed and) type is CAPN_NULL.
// caller should probably check return value, but I don't.
static capn_data d2c(struct capn_segment *cs, const void *data, size_t size)
{
	assert(INT_MAX >= size);

	capn_data x = {0};

	capn_list8 list = capn_new_list8(cs, size);
	if (list.p.type == CAPN_NULL) {
		return x;
	}
	if (capn_setv8(list, 0, data, size) == -1) {
		return x;
	}

	x.p = list.p;

	return x;
}

/**
** Copies the data in `src` to `dest`.
** Data size is placed in `len` when `len` is not NULL.
** Returns a pointer to `dest`. Or NULL when length of source is out of bounds.
**/
static void *c2dcpy(void *dest, size_t cap, size_t *len, const capn_data *src) {
	assert(dest && src);

	if (src->p.len < 0 || (size_t) src->p.len > cap) {
		LOG("Warning: bad src length in c2dcpy (len=%d)\n", src->p.len);
		memset(dest, 0, cap);
		return NULL;
	}
	memcpy(dest, src->p.data, src->p.len);
	if (len) {
		*len = src->p.len;
	}

	return dest;
}

static struct capn_text s2c(const char *string) {
	return (struct capn_text) {
		.len = (int) strlen(string),
		.str = string,
		.seg = NULL,
	};
}

/**
** Serializes an error condition in message 2.
** All other fields of message 2 are not set.
**
** [i]  ms          the message error
**
** Returns zero on success, or non-zero on error.
**/
static int return_m2_error(uint8_t *wbuf, uint32_t wcap, uint32_t *wlen,
		const enum CSSMessageStatus ms)
{
	struct capn ctx;
	capn_init_malloc(&ctx);
	struct capn_ptr root = capn_root(&ctx);
	struct capn_segment *cs = root.seg;

	CSSMessage_ptr m0p = new_CSSMessage(cs);
	struct CSSMessage message = {
		.which = CSSMessage_m2,
		.m2 = new_M2P(cs),
	};

	struct M2P m2 = {
		.status = ms,
	};
	write_M2P(&m2, message.m2);

	write_CSSMessage(&message, m0p);
	int setp_ret = capn_setp(root, 0, m0p.p);
	int64_t len = capn_write_mem(&ctx, wbuf, wcap, 0);
	capn_free(&ctx);
	if (len < 0 || len > UINT32_MAX) {
		LOG("capn_write_mem length out of bounds (len=%"PRId64")\n", len);
		return 1;
	}
	*wlen = len;

	return 0;
}

// aggregates: (i) cleanup MA resources and
//            (ii) serialization of m2 with error condition
static int fail_m1(uint8_t *wbuf, uint32_t wcap, uint32_t *wlen,
		struct ipas_attest_st *ia, const enum CSSMessageStatus ms)
{
	// if (ia && ipas_ma_free(ia)) {
	// 	LOG("ipas_ma_free: failure\n");
	// 	// proceed anyway: return error to client
	// }
	return return_m2_error(wbuf, wcap, wlen, ms);
}

/**
** Get proxy message 2, in B, from RAP.
**
** Protocol:
**   send platform group to RAP (which forwards it to IAS)
**   receive signature revocation list from RAP, for this specific platform
**   do this for both platforms: AGroup and BGroup
**
** Returns zero on success, non-zero otherwise.
**/
static int get_p2(struct ipas_attest_st *ia, struct ipas_ma_p1 *p1, struct ipas_ma_p2 *p2)
{
	assert(ia && p1 && p2);

	if (get_sigrl(&p2->status_a, 0, &p1->gid_a)) {
		LOG("Error: get_sigrl failed for initiator\n");
		return 1;
	}

	if (get_sigrl(&p2->status_b, 0, &p1->gid_b)) {
		LOG("Error: get_sigrl failed for responder\n");
		return 2;
	}

	return 0;
}

// processes Message 1, in `m`, and writes serialized response into `wbuf`
static int process_m1(uint8_t *wbuf, uint32_t wcap, uint32_t *wlen, struct CSSMessage *m)
{
	// deserialize rest of request from client
	struct M1Q m1q;
	read_M1Q(&m1q, m->m1);

	// process incoming m1
	struct ipas_ma_m1 m1 = {0};
	if (m1q.aExGroup.p.len < 0 || m1q.aGroup.p.len < 0 || m1q.aPublic.p.len < 0
			|| (size_t) m1q.aExGroup.p.len > sizeof(m1.egid_a)
			|| (size_t) m1q.aGroup.p.len > sizeof(m1.gid_a)
			|| (size_t) m1q.aPublic.p.len > sizeof(m1.pub_a)) {
		LOG("Error: request fields are too large\n");
		return fail_m1(wbuf, wcap, wlen, NULL, CSSMessageStatus_invalid);
	}
	memcpy(&m1.egid_a, m1q.aExGroup.p.data, m1q.aExGroup.p.len);
	memcpy(&m1.gid_a, m1q.aGroup.p.data, m1q.aGroup.p.len);
	memcpy(&m1.pub_a, m1q.aPublic.p.data, m1q.aPublic.p.len);

	// create client enclave
	if (create_enclave_from_buf(&eid, (uint8_t *) m1q.enclave.p.data, m1q.enclave.p.len)) {
		LOG("Error: creating client enclave in CSS\n");
		return fail_m1(wbuf, wcap, wlen, NULL, CSSMessageStatus_failure);
	}

	// load untrusted DSO (enclave's untrusted code)
	udso_h = dlopen_from_buf(m1q.untrusted.p.data, m1q.untrusted.p.len, RTLD_NOW);
	if (!udso_h) {
		return fail_m1(wbuf, wcap, wlen, NULL, CSSMessageStatus_failure);
	}

	// LOG("sizeof(enclave)=%d\n", m1q.enclave.p.len);
	// LOG("sizeof(aPublic)=%d\n", m1q.aPublic.p.len);
	// LOG("sizeof(aGroup)=%d\n", m1q.aGroup.p.len);
	// LOG("sizeof(aExGroup)=%d\n", m1q.aExGroup.p.len);

	// setup MA library
	// struct ipas_attest_st ia = {0};
	if (ipas_ma_init_dynamic(&ia, 2, eid, udso_h, ROLE_RESPONDER)) {
		fprintf(stderr, "ipas_ma_init: failure\n");
		return 10;
	}


	// handle request:

	struct ipas_ma_p1 p1 = {0};
	if (ipas_ma_get_p1(&ia, &m1, &p1)) {
		LOG("Error: ipas_ma_get_p1\n");
		return fail_m1(wbuf, wcap, wlen, &ia, CSSMessageStatus_failure);
	}
	ipas_ma_dump_p1(&p1);

	struct ipas_ma_p2 p2 = {0};
	if (get_p2(&ia, &p1, &p2)) {
		LOG("Error: get_p2\n");
		return fail_m1(wbuf, wcap, wlen, &ia, CSSMessageStatus_failure);
	}
	// ipas_ma_dump_p2(&p2);
	// ipas_ma_m2_dump(&p2);
	// FIXME dump m2

	// get m2 in B (responder)
	struct ipas_ma_m2 m2 = {0};
	if (ipas_ma_get_m2(&ia, &p2, &m2)) {
		LOG("Error: ipas_ma_get_m2\n");
		return fail_m1(wbuf, wcap, wlen, &ia, CSSMessageStatus_failure);
	}
	ipas_ma_m2_dump(&m2);


	// prepare reply:
	/*
	// Message 2
	// sent from B to A
	struct ipas_ma_m2 {
		uint32_t egid_b;                    // BExGroup
		sgx_ec256_public_t pub_b;           // BPublic

		uint32_t status_a;          // HTTP status (e.g. "200" for OK)
		uint32_t length_a;          // length of SigRL (only when status 200 OK)
		uint8_t srl_a[IPAS_SRL_RSP_B_SIZE]; // ASigRL
	};
	*/

	struct capn ctx;
	capn_init_malloc(&ctx);
	struct capn_ptr root = capn_root(&ctx);
	struct capn_segment *cs = root.seg;

	CSSMessage_ptr m0p = new_CSSMessage(cs);
	struct CSSMessage message = {
		.which = CSSMessage_m2,
		.m2 = new_M2P(cs),
	};

	struct M2P m2p = {
		.status = CSSMessageStatus_success,
		.bExGroup = m2.egid_b,
		.bPublic = d2c(cs, &m2.pub_b, sizeof m2.pub_b),
		.aStatusCode = m2.status_a,
		.aSigRL = d2c(cs, &m2.srl_a, m2.length_a),
	};

	write_M2P(&m2p, message.m2);

	write_CSSMessage(&message, m0p);
	int setp_ret = capn_setp(root, 0, m0p.p);
	int64_t len = capn_write_mem(&ctx, wbuf, wcap, 0);
	LOG("capn_size=%d, capn_write_mem=%"PRId64"\n", capn_size(&ctx), len);
	capn_free(&ctx);
	if (len < 0 || len > UINT32_MAX) {
		LOG("capn_write_mem length out of bounds (len=%"PRId64")\n", len);
		return 1;
	}
	*wlen = len;


	// serialize response for client

	return 0;
}

/**
** Serializes an error condition in message 4.
** All other fields of message 4 are not set.
**
** [i]  ms          the message error
**
** Returns zero on success, or non-zero on error.
**/
static int return_m4_error(uint8_t *wbuf, uint32_t wcap, uint32_t *wlen,
		const enum CSSMessageStatus ms)
{
	struct capn ctx;
	capn_init_malloc(&ctx);
	struct capn_ptr root = capn_root(&ctx);
	struct capn_segment *cs = root.seg;

	CSSMessage_ptr m0p = new_CSSMessage(cs);
	struct CSSMessage message = {
		.which = CSSMessage_m4,
		.m4 = new_M4P(cs),
	};

	struct M4P m4 = {
		.status = ms,
	};
	write_M4P(&m4, message.m4);

	write_CSSMessage(&message, m0p);
	int setp_ret = capn_setp(root, 0, m0p.p);
	int64_t len = capn_write_mem(&ctx, wbuf, wcap, 0);
	capn_free(&ctx);
	if (len < 0 || len > UINT32_MAX) {
		LOG("capn_write_mem length out of bounds (len=%"PRId64")\n", len);
		return 1;
	}
	*wlen = len;

	return 0;
}

// aggregates: (i) cleanup MA resources and
//            (ii) serialization of m4 with error condition
static int fail_m3(uint8_t *wbuf, uint32_t wcap, uint32_t *wlen,
		struct ipas_attest_st *ia, const enum CSSMessageStatus ms)
{
	// if (ia && ipas_ma_free(ia)) {
	// 	LOG("ipas_ma_free: failure\n");
	// 	// proceed anyway: return error to client
	// }
	return return_m4_error(wbuf, wcap, wlen, ms);
}

/**
** Get proxy message 4, in B, from RAP.
**
** Protocol:
**   send quote to RAP (which forwards it to IAS)
**   receive report signed by IAS from RAP, for this specific platform
**   do this for both platforms: AQuote and BQuote
**
** Returns zero on success, non-zero otherwise.
**/
static int get_p4(struct ipas_attest_st *ia, struct ipas_ma_p3 *p3, struct ipas_ma_p4 *p4)
{
	assert(ia && p3 && p4);

	if (get_report(&p4->status_a,
			p4->rid_a, sizeof(p4->rid_a),
			p4->sig_a, sizeof(p4->sig_a),
			p4->cc_a, sizeof(p4->cc_a),
			p4->report_a, sizeof(p4->report_a),
			// p4->eqs_a,
			0, (sgx_quote_t *) p3->quote_a, p3->size_a)) {
		LOG("Error: get_report failed for initiator\n");
		return 1;
	}

	if (get_report(&p4->status_b,
			p4->rid_b, sizeof(p4->rid_b),
			p4->sig_b, sizeof(p4->sig_b),
			p4->cc_b, sizeof(p4->cc_b),
			p4->report_b, sizeof(p4->report_b),
			// p4->eqs_b,
			0, (sgx_quote_t *) p3->quote_b, p3->size_b)) {
		LOG("Error: get_report failed for responder\n");
		return 1;
	}

	return 0;
}

// processes Message 3, in `m`, and writes serialized response into `wbuf`
static int process_m3(uint8_t *wbuf, uint32_t wcap, uint32_t *wlen, struct CSSMessage *m)
{
	int r;

	// deserialize rest of request from client
	struct M3Q m3q;
	read_M3Q(&m3q, m->m3);

	// process incoming m3
	struct ipas_ma_m3 m3 = {0};
	if (m3q.aQuote.p.len < 0 || (size_t) m3q.aQuote.p.len > sizeof(m3.quote_a)) {
		LOG("Error: invalid request fields\n");
		return fail_m3(wbuf, wcap, wlen, &ia, CSSMessageStatus_invalid);
	}
	memcpy(&m3.quote_a, m3q.aQuote.p.data, m3q.aQuote.p.len);
	m3.size_a = m3q.aQuote.p.len;


	// handle request:

	struct ipas_ma_p3 p3 = {0};
	if (r = ipas_ma_get_p3(&ia, &m3, &p3)) {
		LOG("Error: ipas_ma_get_p3 (%d)\n", r);
		return fail_m3(wbuf, wcap, wlen, &ia, CSSMessageStatus_failure);
	}
	ipas_ma_p3_dump(&p3);

	struct ipas_ma_p4 p4 = {0};
	if (get_p4(&ia, &p3, &p4)) {
		LOG("Error: get_p4\n");
		return fail_m3(wbuf, wcap, wlen, &ia, CSSMessageStatus_failure);
	}
	// TODO dump p4

	// get m4 in B (responder)
	struct ipas_ma_m4 m4 = {0};
	if (r = ipas_ma_get_m4(&ia, &p4, &m4)) {
		LOG("Error: ipas_ma_get_m4 (%d)\n", r);
		return fail_m3(wbuf, wcap, wlen, &ia, CSSMessageStatus_failure);
	}
	ipas_ma_dump_m4(&m4);


	// prepare reply:
	// serialize response for client:

	struct capn ctx;
	capn_init_malloc(&ctx);
	struct capn_ptr root = capn_root(&ctx);
	struct capn_segment *cs = root.seg;

	CSSMessage_ptr m0p = new_CSSMessage(cs);
	struct CSSMessage message = {
		.which = CSSMessage_m4,
		.m4 = new_M4P(cs),
	};

	struct M4P m4p = {
		.status = CSSMessageStatus_success,
		.aStatusCode = m4.status_a,
		.aRequestId = s2c(m4.rid_a),
		.aReportSig = s2c(m4.sig_a),
		.aCertChain = s2c(m4.cc_a),
		.aReport = s2c(m4.report_a),
		// .aReport = d2c(cs, m4.report_a, m4.length_a),
		.bStatusCode = m4.status_b,
		.bRequestId = s2c(m4.rid_b),
		.bReportSig = s2c(m4.sig_b),
		.bCertChain = s2c(m4.cc_b),
		.bReport = s2c(m4.report_b),
		// .bReport = d2c(cs, m4.report_b, m4.length_b),
		.data = d2c(cs, m4.data, sizeof(m4.data)),
		.mac = d2c(cs, m4.mac, sizeof(m4.mac)),
	};

	write_M4P(&m4p, message.m4);

	write_CSSMessage(&message, m0p);
	int setp_ret = capn_setp(root, 0, m0p.p);
	int64_t len = capn_write_mem(&ctx, wbuf, wcap, 0);
	LOG("capn_size=%d, capn_write_mem=%"PRId64"\n", capn_size(&ctx), len);
	capn_free(&ctx);
	if (len < 0 || len > UINT32_MAX) {
		LOG("capn_write_mem length out of bounds (len=%"PRId64")\n", len);
		return 1;
	}
	*wlen = len;

	return 0;
}

/**
** Serializes an error condition in message 12.
** All other fields of message 12 are not set.
**
** [i]  ms          the message error
**
** Returns zero on success, or non-zero on error.
**/
static int return_m12_error(uint8_t *wbuf, uint32_t wcap, uint32_t *wlen,
		const enum CSSMessageStatus ms)
{
	struct capn ctx;
	capn_init_malloc(&ctx);
	struct capn_ptr root = capn_root(&ctx);
	struct capn_segment *cs = root.seg;

	CSSMessage_ptr m0p = new_CSSMessage(cs);
	struct CSSMessage message = {
		.which = CSSMessage_m12,
		.m12 = new_M12P(cs),
	};

	struct M12P m2 = {
		.status = ms,
	};
	write_M12P(&m2, message.m12);

	write_CSSMessage(&message, m0p);
	int setp_ret = capn_setp(root, 0, m0p.p);
	int64_t len = capn_write_mem(&ctx, wbuf, wcap, 0);
	capn_free(&ctx);
	if (len < 0 || len > UINT32_MAX) {
		LOG("capn_write_mem length out of bounds (len=%"PRId64")\n", len);
		return 1;
	}
	*wlen = len;

	return 0;
}

static int fail_m11(uint8_t *wbuf, uint32_t wcap, uint32_t *wlen,
		const enum CSSMessageStatus ms)
{
	return return_m12_error(wbuf, wcap, wlen, ms);
}

// processes Message 11, in `m`, and writes serialized response into `wbuf`
static int process_m11(uint8_t *wbuf, uint32_t wcap, uint32_t *wlen,
		struct CSSMessage *m)
{
	int r;

	// deserialize rest of request from client
	struct M11Q m11q;
	read_M11Q(&m11q, m->m11);

	// process incoming m11
	struct ipas_s_m1 m1 = {0};
	if (!c2dcpy(m1.iv, sizeof(m1.iv), NULL, &m11q.iv)
			|| !c2dcpy(m1.ct, sizeof(m1.ct), NULL, &m11q.ct)
			|| !c2dcpy(m1.tag, sizeof(m1.tag), NULL, &m11q.tag)) {
		return fail_m11(wbuf, wcap, wlen, CSSMessageStatus_invalid);
	}

	// get m2 (=m12 in CSS specification) in B (responder)
	struct ipas_s_m2 m2 = {0};
	if (r = ipas_s_get_m2(eid, ia.udso, 2, &m1, &m2)) {
		LOG("Error: ipas_s_get_m2 (%d)\n", r);
		return fail_m11(wbuf, wcap, wlen, CSSMessageStatus_invalid);
	}
	// TODO dump m2

	// prepare outgoing m12:

	struct capn ctx;
	capn_init_malloc(&ctx);
	struct capn_ptr root = capn_root(&ctx);
	struct capn_segment *cs = root.seg;

	CSSMessage_ptr m0p = new_CSSMessage(cs);
	struct CSSMessage message = {
		.which = CSSMessage_m12,
		.m12 = new_M12P(cs),
	};

	struct M12P m12p = {
		.status = CSSMessageStatus_success,
		.data = d2c(cs, m2.data, m2.size),
		.mac = d2c(cs, m2.mac, sizeof(m2.mac)),
	};

	write_M12P(&m12p, message.m12);

	write_CSSMessage(&message, m0p);
	int setp_ret = capn_setp(root, 0, m0p.p);
	int64_t len = capn_write_mem(&ctx, wbuf, wcap, 0);
	LOG("capn_size=%d, capn_write_mem=%"PRId64"\n", capn_size(&ctx), len);
	capn_free(&ctx);
	if (len < 0 || len > UINT32_MAX) {
		LOG("capn_write_mem length out of bounds (len=%"PRId64")\n", len);
		return 1;
	}
	*wlen = len;

	return 0;
}

/**
** Serializes an error condition in message 22.
** All other fields of message 22 are not set.
**
** [i]  ms          the message error
**
** Returns zero on success, or non-zero on error.
**/
static int return_m22_error(uint8_t *wbuf, uint32_t wcap, uint32_t *wlen,
		const enum CSSMessageStatus ms)
{
	struct capn ctx;
	capn_init_malloc(&ctx);
	struct capn_ptr root = capn_root(&ctx);
	struct capn_segment *cs = root.seg;

	CSSMessage_ptr m0p = new_CSSMessage(cs);
	struct CSSMessage message = {
		.which = CSSMessage_m22,
		.m22 = new_M22P(cs),
	};

	struct M22P m2 = {
		.status = ms,
	};
	write_M22P(&m2, message.m22);

	write_CSSMessage(&message, m0p);
	int setp_ret = capn_setp(root, 0, m0p.p);
	int64_t len = capn_write_mem(&ctx, wbuf, wcap, 0);
	capn_free(&ctx);
	if (len < 0 || len > UINT32_MAX) {
		LOG("capn_write_mem length out of bounds (len=%"PRId64")\n", len);
		return 1;
	}
	*wlen = len;

	return 0;
}

static int fail_m21(uint8_t *wbuf, uint32_t wcap, uint32_t *wlen,
		const enum CSSMessageStatus ms)
{
	return return_m22_error(wbuf, wcap, wlen, ms);
}

// processes Message 21, in `m`, and writes serialized response into `wbuf`
static int process_m21(uint8_t *wbuf, uint32_t wcap, uint32_t *wlen,
		struct CSSMessage *m)
{
	int r;

	// deserialize rest of request from client
	struct M21Q m21q;
	read_M21Q(&m21q, m->m21);

	// process incoming m21
	struct ipas_u_m1 m1 = {0};
	if (!c2dcpy(m1.nonce, sizeof(m1.nonce), NULL, &m21q.nonce)
			|| !c2dcpy(m1.data, sizeof(m1.data), (size_t *) &m1.size, &m21q.data)
			|| !c2dcpy(m1.mac, sizeof(m1.mac), NULL, &m21q.mac)) {
		return fail_m21(wbuf, wcap, wlen, CSSMessageStatus_invalid);
	}

	// get m2 (=m22 in CSS specification) in B (responder)
	struct ipas_u_m2 m2 = {0};
	if (r = ipas_u_get_m2(eid, ia.udso, 2, &m1, &m2)) {
		LOG("Error: ipas_u_get_m2 (%d)\n", r);
		return fail_m21(wbuf, wcap, wlen, CSSMessageStatus_invalid);
	}
	// TODO dump m2

	// prepare outgoing m22:

	struct capn ctx;
	capn_init_malloc(&ctx);
	struct capn_ptr root = capn_root(&ctx);
	struct capn_segment *cs = root.seg;

	CSSMessage_ptr m0p = new_CSSMessage(cs);
	struct CSSMessage message = {
		.which = CSSMessage_m22,
		.m22 = new_M22P(cs),
	};

	struct M22P m22p = {
		.status = CSSMessageStatus_success,
		.iv = d2c(cs, m2.iv, sizeof(m2.iv)),
		.ct = d2c(cs, m2.ct, sizeof(m2.ct)),
		.tag = d2c(cs, m2.tag, sizeof(m2.tag)),
	};

	write_M22P(&m22p, message.m22);

	write_CSSMessage(&message, m0p);
	int setp_ret = capn_setp(root, 0, m0p.p);
	int64_t len = capn_write_mem(&ctx, wbuf, wcap, 0);
	LOG("capn_size=%d, capn_write_mem=%"PRId64"\n", capn_size(&ctx), len);
	capn_free(&ctx);
	if (len < 0 || len > UINT32_MAX) {
		LOG("capn_write_mem length out of bounds (len=%"PRId64")\n", len);
		return 1;
	}
	*wlen = len;

	return 0;
}

// Processes one client request: deserializes part of request from client, finds message type, calls correct handling function.
// Caller allocates read and write buffers.
static int process_request(uint8_t *wbuf, uint32_t wcap, uint32_t *wlen, const uint8_t *rbuf, uint32_t rlen)
{
	struct capn rc;
	int init_mem_ret = capn_init_mem(&rc, rbuf, rlen, 0);

	struct CSSMessage m;
	CSSMessage_ptr root;
	root.p = capn_getp(capn_root(&rc), 0, 1);
	read_CSSMessage(&m, root);

	LOG("deserialized request, which index is: %d\n", m.which);

	// char dest[4096] = {0};
	// u8_to_str(dest, rbuf, rlen, "");
	// fprintf(stderr, "%s\n", dest);

	switch (m.which) {
	case CSSMessage_m1:
		return process_m1(wbuf, wcap, wlen, &m);
	case CSSMessage_m3:
		return process_m3(wbuf, wcap, wlen, &m);
	case CSSMessage_m11:
		return process_m11(wbuf, wcap, wlen, &m);
	case CSSMessage_m21:
		return process_m21(wbuf, wcap, wlen, &m);
	default:
		fprintf(stderr, "Error: bad message index (%d)\n", m.which);
		return 1;
	}
}

// Instead of having two functions, 'cleanup success' and 'cleanup failure', this function has a more flexible result parameter that indicates the error and enables cleanup accordingly.
// Returns the same value passed in as argument.
static int cleanup(int result)
{
	if (result && eid) {
		LOG("destroy_enclave\n");
		destroy_enclave(&eid);
		eid = 0;
	}
	if (result) {
		LOG("ipas_ma_free\n");
		ipas_ma_free(&ia);
	}
	if (result && udso_h) {
		dlclose(udso_h);
		udso_h = NULL;
		LOG("Unloaded untrusted DSO\n");
	}

	return result;
}

int main(int argc, char *argv[])
{
	LOG("Started CSS\n");

	struct foossl_server_st foossl;

	if (foossl_server_connect(&foossl, 54433)) {
		perror("connect: unable to create secure listening connection");
		foossl_server_destroy(&foossl);
		return -1;
	}

	while (1) {
		SSL *ssl = NULL;

		LOG("Waiting for the next client...\n");

		if (foossl_server_loop_acquire(&foossl, &ssl)) {
			perror("acquire: could not acquire client resources");
			continue;
		}

		while (!ssl_handle_request(ssl, process_request, cleanup));
		// int r;
		// do {
		// 	LOG("Handling next request...\n");
		// 	r = ssl_handle_request(ssl, process_request);
		// } while (!r);

		if (foossl_server_loop_release(ssl)) {
			perror("release: could not release client resources");
			continue;
		}
	}
	// TODO Ctrl+D

	if (foossl_server_destroy(&foossl)) {
		perror("destroy: unable to destroy server resources");
		return -1;
	}

	return 0;
}
