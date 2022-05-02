#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include <limits.h>
#include <assert.h>
//
// #include <jansson.h>
// #include "base64.h"

#include "cebug.h"
#include "debug.h"

#include <ipas/u/attestation.h>
#include <ipas/u/sealing.h>
#include "css.capnp.h"
#include "serialization.h"

// // need free .str or done by lib ?
// static struct capn_text gid_to_text(sgx_epid_group_id_t gid) {
// 	char *s = malloc(8 + 1);
//
// 	for (size_t i = 0; i < 8; i += 2) {
// 		snprintf(s+i, 9-i, "%02"PRIx8, gid[i/2]);
// 	}
//
// 	return (struct capn_text) {
// 		.len = (int) strlen(s),
// 		.str = s,
// 		.seg = NULL,
// 	};
// }

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

/**
** Copies the string in src to dest.
** The destination string is always null-terminated.
** Returns a pointer to the destination string. Or NULL when insufficient cap.
**/
static char *c2scpy(char *dest, size_t cap, const capn_text *src) {
	assert(dest && src);

	if (src->len < 0 || (size_t) src->len > cap + 1) {
		LOG("Warning in c2scpy: src.len out of bounds (len=%d, cap=%zu)\n",
				src->len, cap);
		memset(dest, 0, cap);
		return NULL;
	}
	strncpy(dest, src->str, src->len);
	dest[src->len] = '\0';

	return dest;
}

// static struct capn_text str_to_text(const char *string) {
// 	return (struct capn_text) {
// 		.len = (int) strlen(string),
// 		.str = string,
// 		.seg = NULL,
// 	};
// }
//
// // REVIEW caller needs to free it, or capnp handles freeing of all tree?
// static struct capn_text nonce_to_text(sgx_quote_nonce_t nonce) {
// 	char *s = malloc(16 * 2 + 1);
// 	// memset(s, 0, sizeof s);
//
// 	for (size_t i = 0; i < 32; i += 2) {
// 		snprintf(s + i, 33 - i, "%02"PRIx8, nonce.rand[i/2]);
// 	}
// 	// s[16 * 2] = '\0'; // feito por snprintf
//
// 	return (struct capn_text) {
// 		.len = (int) strlen(s),
// 		.str = s,
// 		.seg = NULL,
// 	};
// }

// TEMP trouxe para aqui do attestation, para eliminar...
size_t u8_to_str(char *dest, const uint8_t *src, size_t len, const char *sep)
{
	if (len == 0) {
		return 0;
	}

	size_t total = len * 2 + (len - 1) * strlen(sep);
	//FIXME não é preciso +1 para NUL ?
	// return value is the number of characters (excluding the terminating null  byte) (Check return in snprintf man page!!) TODO

	if (dest == NULL) {
		return total;
	}

	char *next_pos;
	for (size_t i = 0; i < len - 1; i++) {
		next_pos = dest + i * 2 + i * strlen(sep);
		sprintf(next_pos, "%02"PRIx8"%s", src[i], sep);
	}
	next_pos = dest + (len - 1) * 2 + (len - 1) * strlen(sep);
	sprintf(next_pos, "%02"PRIx8, src[len - 1]);

	return strlen(dest);
}

int encode_m1(uint8_t *output, size_t output_cap, uint32_t *output_len,
		const uint8_t *enclave, size_t e_size,
		const uint8_t *untrusted, size_t u_size,
		const uint8_t *aeg, size_t aeg_size,
		const uint8_t *ag, size_t ag_size,
		const uint8_t *apub, size_t apub_size)
{
	assert(output_cap > e_size + u_size + apub_size + ag_size + aeg_size);

	struct capn ctx;
	capn_init_malloc(&ctx);
	struct capn_ptr root = capn_root(&ctx);
	struct capn_segment *cs = root.seg;

	CSSMessage_ptr m0p = new_CSSMessage(cs);
	struct CSSMessage message = {
		.which = CSSMessage_m1,
		.m1 = new_M1Q(cs),
	};


	struct M1Q m1;

	{
		capn_list8 list = capn_new_list8(cs, e_size);
		capn_setv8(list, 0, enclave, e_size);
		m1.enclave.p = list.p;
		LOG("sizeof(enclave)=%d\n", m1.enclave.p.len);
	}

	{
		capn_list8 list = capn_new_list8(cs, u_size);
		capn_setv8(list, 0, untrusted, u_size);
		m1.untrusted.p = list.p;
		LOG("sizeof(udso)=%d\n", m1.untrusted.p.len);
	}

	{
		capn_list8 list = capn_new_list8(cs, aeg_size);
		capn_setv8(list, 0, aeg, aeg_size);
		m1.aExGroup.p = list.p;
	}

	{
		capn_list8 list = capn_new_list8(cs, ag_size);
		capn_setv8(list, 0, ag, ag_size);
		m1.aGroup.p = list.p;
	}

	{
		capn_list8 list = capn_new_list8(cs, apub_size);
		capn_setv8(list, 0, apub, apub_size);
		m1.aPublic.p = list.p;
	}

	write_M1Q(&m1, message.m1);


	write_CSSMessage(&message, m0p);
	int setp_ret = capn_setp(root, 0, m0p.p);
	int64_t len = capn_write_mem(&ctx, output, output_cap, 0);
	LOG("capn_size=%d, capn_write_mem=%"PRId64"\n", capn_size(&ctx), len);
	capn_free(&ctx);
	if (len < 0 || len > UINT32_MAX) {
		LOG("capn_write_mem length out of bounds (len=%"PRId64")\n", len);
		return 1;
	}
	*output_len = len;

	// int total_size = capn_size(&ctx);
	// printf("total_size=%d, write_mem=%"PRId64"\n", capn_size(&ctx), len);

	// char dest[4096] = {0};
	// u8_to_str(dest, output, len, "");
	// fprintf(stderr, "%s\n", dest);

	return 0;
}

int decode_m2(struct ipas_ma_m2 *m2, const uint8_t *ibuf, size_t ilen)
{
	struct capn rc;
	int init_mem_ret = capn_init_mem(&rc, ibuf, ilen, 0);

	struct CSSMessage m;
	CSSMessage_ptr root;
	root.p = capn_getp(capn_root(&rc), 0, 1);
	read_CSSMessage(&m, root);

	if (m.which != 2) {
		LOG("Error: expected message index 2 but got %d\n", m.which);
		capn_free(&rc);
		return 1;
	}

	struct M2P m2p;
	read_M2P(&m2p, m.m2);

	if (m2p.status) {
		LOG("Error: message 2 status is %d (expected 0 = OK)\n", m2p.status);
		capn_free(&rc);
		return 2;
	}

	m2->egid_b = m2p.bExGroup;

	if (m2p.bPublic.p.len != sizeof(m2->pub_b)) {
		LOG("Error: BPublic has wrong size (got=%d, expected=%zu)\n",
				m2p.bPublic.p.len, sizeof(m2->pub_b));
		capn_free(&rc);
		return 3;
	}
	memcpy(&m2->pub_b, m2p.bPublic.p.data, sizeof(m2->pub_b));

	m2->status_a = m2p.aStatusCode;
	if (m2p.aSigRL.p.len > sizeof(m2->srl_a)) {
		LOG("Error: ASigRL does not fit in available space\n");
		capn_free(&rc);
		return 4;
	}
	memcpy(&m2->srl_a, m2p.aSigRL.p.data, m2p.aSigRL.p.len);

	capn_free(&rc);

	return 0;
}

int encode_m3(uint8_t *output, size_t output_cap, uint32_t *output_len,
		const uint8_t *quote, size_t size)
{
	// assert(output_cap > size);

	struct capn ctx;
	capn_init_malloc(&ctx);
	struct capn_ptr root = capn_root(&ctx);
	struct capn_segment *cs = root.seg;

	CSSMessage_ptr m0p = new_CSSMessage(cs);
	struct CSSMessage message = {
		.which = CSSMessage_m3,
		.m3 = new_M3Q(cs),
	};


	struct M3Q m3 = {
		.status = CSSMessageStatus_success, // FIXME
		.aQuote = d2c(cs, quote, size),
	};

	write_M3Q(&m3, message.m3);

	write_CSSMessage(&message, m0p);
	int setp_ret = capn_setp(root, 0, m0p.p);
	int64_t len = capn_write_mem(&ctx, output, output_cap, 0);
	LOG("capn_size=%d, capn_write_mem=%"PRId64"\n", capn_size(&ctx), len);
	capn_free(&ctx);
	if (len < 0 || len > UINT32_MAX) {
		LOG("capn_write_mem length out of bounds (len=%"PRId64")\n", len);
		return 1;
	}
	*output_len = len;

	// fprintf(stderr, "------- serialzed msg3:\n");
	// char dest[4096] = {0};
	// u8_to_str(dest, output, len, "");
	// fprintf(stderr, "%s\n", dest);

	return 0;
}

int decode_m4(struct ipas_ma_m4 *m4, const uint8_t *ibuf, size_t ilen)
{
	assert(m4 && ibuf);

	struct capn rc;
	int init_mem_ret = capn_init_mem(&rc, ibuf, ilen, 0);

	struct CSSMessage m;
	CSSMessage_ptr root;
	root.p = capn_getp(capn_root(&rc), 0, 1);
	read_CSSMessage(&m, root);

	LOG("deserialized request, which index is: %d\n", m.which);
	if (m.which != 4) {
		LOG("Error: expected message index 4 but got %d\n", m.which);
		capn_free(&rc);
		return 1;
	}

	struct M4P m4p;
	read_M4P(&m4p, m.m4);

	if (m4p.status) {
		LOG("Error: message 4 status is %d (expected 0 = OK)\n", m4p.status);
		capn_free(&rc);
		return 2;
	}
	LOG("Message 4 status: %d\n", m4p.status);

	m4->status_a = m4p.aStatusCode;
	c2scpy(m4->rid_a, sizeof(m4->rid_a), &m4p.aRequestId);
	c2scpy(m4->sig_a, sizeof(m4->sig_a), &m4p.aReportSig);
	c2scpy(m4->cc_a, sizeof(m4->cc_a), &m4p.aCertChain);
	c2scpy(m4->report_a, sizeof(m4->report_a), &m4p.aReport);

	m4->status_b = m4p.bStatusCode;
	c2scpy(m4->rid_b, sizeof(m4->rid_b), &m4p.bRequestId);
	c2scpy(m4->sig_b, sizeof(m4->sig_b), &m4p.bReportSig);
	c2scpy(m4->cc_b, sizeof(m4->cc_b), &m4p.bCertChain);
	c2scpy(m4->report_b, sizeof(m4->report_b), &m4p.bReport);

	if (m4p.data.p.len < 0 || (size_t) m4p.data.p.len > sizeof(m4->data)) {
		LOG("Error: data has inconvenient size (got=%d, buffer=%zu)\n",
				m4p.data.p.len, sizeof(m4->data));
		capn_free(&rc);
		return 5;
	}
	memcpy(m4->data, m4p.data.p.data, m4p.data.p.len);

	if (m4p.mac.p.len < 0 || (size_t) m4p.mac.p.len > sizeof(m4->mac)) {
		LOG("Error: MAC has wrong size (got=%d, expected=%zu)\n",
				m4p.mac.p.len, sizeof(m4->mac));
		capn_free(&rc);
		return 6;
	}
	memcpy(m4->mac, m4p.mac.p.data, m4p.mac.p.len);

	capn_free(&rc);

	return 0;
}

int encode_m11(uint8_t *obuf, size_t ocap, uint32_t *olen,
		const struct ipas_s_m1 *m1)
{
	assert(obuf);
	assert(m1);

	struct capn ctx;
	capn_init_malloc(&ctx);
	struct capn_ptr root = capn_root(&ctx);
	struct capn_segment *cs = root.seg;

	CSSMessage_ptr m0p = new_CSSMessage(cs);
	struct CSSMessage message = {
		.which = CSSMessage_m11,
		.m11 = new_M11Q(cs),
	};

	struct M11Q m11q = {
		.iv = d2c(cs, m1->iv, sizeof(m1->iv)),
		.ct = d2c(cs, m1->ct, sizeof(m1->ct)),
		.tag = d2c(cs, m1->tag, sizeof(m1->tag)),
	};

	write_M11Q(&m11q, message.m11);

	write_CSSMessage(&message, m0p);
	int setp_ret = capn_setp(root, 0, m0p.p);
	int64_t len = capn_write_mem(&ctx, obuf, ocap, 0);
	LOG("capn_size=%d, capn_write_mem=%"PRId64"\n", capn_size(&ctx), len);
	capn_free(&ctx);
	if (len < 0 || len > UINT32_MAX) {
		LOG("capn_write_mem length out of bounds (len=%"PRId64")\n", len);
		return 1;
	}
	*olen = len;

	return 0;
}

int decode_m12(struct ipas_s_m2 *m2, const uint8_t *ibuf, size_t ilen)
{
	assert(m2);
	assert(ibuf);

	struct capn rc;
	int init_mem_ret = capn_init_mem(&rc, ibuf, ilen, 0);

	struct CSSMessage m;
	CSSMessage_ptr root;
	root.p = capn_getp(capn_root(&rc), 0, 1);
	read_CSSMessage(&m, root);

	LOG("deserialized request, which index is: %d\n", m.which);
	if (m.which != 6) {
		LOG("Error: expected message index 11 but got %d\n", m.which);
		capn_free(&rc);
		return 1;
	}

	struct M12P m12p;
	read_M12P(&m12p, m.m12);

	if (m12p.status) {
		LOG("Error: message 12 status is %d (expected 0 = OK)\n", m12p.status);
		capn_free(&rc);
		return 2;
	}
	LOG("Message 12 status: %d ✓\n", m12p.status);

	if (!c2dcpy(m2->data, sizeof(m2->data), (size_t *) &m2->size, &m12p.data)) {
		capn_free(&rc);
		return 1;
	}
	if (!c2dcpy(m2->mac, sizeof(m2->mac), NULL, &m12p.mac)) {
		capn_free(&rc);
		return 1;
	}

	capn_free(&rc);

	return 0;
}

int encode_m21(uint8_t *obuf, size_t ocap, uint32_t *olen,
		const struct ipas_u_m1 *m1)
{
	assert(obuf);
	assert(m1);

	struct capn ctx;
	capn_init_malloc(&ctx);
	struct capn_ptr root = capn_root(&ctx);
	struct capn_segment *cs = root.seg;

	CSSMessage_ptr m0p = new_CSSMessage(cs);
	struct CSSMessage message = {
		.which = CSSMessage_m21,
		.m21 = new_M21Q(cs),
	};

	struct M21Q m21q = {
		.nonce = d2c(cs, m1->nonce, sizeof(m1->nonce)),
		.data = d2c(cs, m1->data, m1->size),
		.mac = d2c(cs, m1->mac, sizeof(m1->mac)),
	};

	write_M21Q(&m21q, message.m21);

	write_CSSMessage(&message, m0p);
	int setp_ret = capn_setp(root, 0, m0p.p);
	int64_t len = capn_write_mem(&ctx, obuf, ocap, 0);
	LOG("capn_size=%d, capn_write_mem=%"PRId64"\n", capn_size(&ctx), len);
	capn_free(&ctx);
	if (len < 0 || len > UINT32_MAX) {
		LOG("capn_write_mem length out of bounds (len=%"PRId64")\n", len);
		return 1;
	}
	*olen = len;

	return 0;
}

int decode_m22(struct ipas_u_m2 *m2, const uint8_t *ibuf, size_t ilen)
{
	assert(m2);
	assert(ibuf);

	struct capn rc;
	int init_mem_ret = capn_init_mem(&rc, ibuf, ilen, 0);

	struct CSSMessage m;
	CSSMessage_ptr root;
	root.p = capn_getp(capn_root(&rc), 0, 1);
	read_CSSMessage(&m, root);

	LOG("deserialized request, which index is: %d\n", m.which);
	if (m.which != 8) {
		LOG("Error: expected message index 21 but got %d\n", m.which);
		capn_free(&rc);
		return 1;
	}

	struct M22P m22p;
	read_M22P(&m22p, m.m22);

	if (m22p.status) {
		LOG("Error: message 22 status is %d (expected 0 = OK)\n", m22p.status);
		capn_free(&rc);
		return 2;
	}
	LOG("Message 22 status: %d ✓\n", m22p.status);

	if (!c2dcpy(m2->iv, sizeof(m2->iv), NULL, &m22p.iv)) {
		capn_free(&rc);
		return 1;
	}
	if (!c2dcpy(m2->ct, sizeof(m2->ct), NULL, &m22p.ct)) {
		capn_free(&rc);
		return 1;
	}
	if (!c2dcpy(m2->tag, sizeof(m2->tag), NULL, &m22p.tag)) {
		capn_free(&rc);
		return 1;
	}

	capn_free(&rc);

	return 0;
}
