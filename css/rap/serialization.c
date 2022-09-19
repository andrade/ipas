#include <stdlib.h>
#include <inttypes.h>
#include <string.h>

#include <jansson.h>
#include "base64.h"

#include "debug.h"

#include "rap.capnp.h"

#include "serialization.h"

// static int evidence_to_json(const uint8_t *p, uint32_t size, char **output, size_t *output_size)

// prep request AEP serialized in json and with base64 as required
static int ra_aep_to_json(char *output, size_t ocap, const struct ra_aep *aep)
{
	// encode quote
	char quote[2048] = {0};
	// if (base64_encode_fr_u8(quote, sizeof(quote), (uint8_t *) &aep->quote, aep->quote_size)) {
	if (base64_encode_fr_u8(quote, sizeof(quote), aep->quote, aep->quote_size)) {
		LOG("Error: base64_encode_fr_u8 (1)\n");
		return 1;
	}
	// LOG("base64 of quote: %s (strlen=%zu)\n", quote, strlen(quote));

	// encode nonce
	char nonce[64] = {0};
	if (base64_encode_fr_u8(nonce, sizeof(nonce), (uint8_t *) &aep->nonce, sizeof(aep->nonce))) {
		LOG("Error: base64_encode_fr_u8 (2)\n");
		return 1;
	}
	// LOG("base64 of nonce: %s (strlen=%zu)\n", nonce, strlen(nonce));

	//json_t *root = json_object();
	//json_object_set_new(root, "isvEnclaveQuote", );

	//TODO:
	//1. base64 encode uint8 quote
	//2. encodedQuote to JSON
	//3. prepare libcurl header/body and send to server
	//4. don't know if need to parse response in inverse

	//NOTE: Encode input to base64 needs to be done individually for quote, pse, and nonce. Then when transforming base64 into JSON we use single function!

	// //TODO: check ret vaukes
	// char *output_base64;
	// uint32_t size_base64;
	// if (base64_encode(p, size, &output_base64, &size_base64)) {
	// 	fprintf(stderr, "base64_encode: failure\n");
	// 	return -1;
	// }



	const char json_format[] = "{s:s%,s:s%}";
	json_t *j = json_pack(json_format,
			"isvEnclaveQuote", quote, strlen(quote),
			"nonce", nonce, strlen(nonce));

	// make sure fits in buffer
	if (json_dumpb(j, NULL, 0, 0) > ocap) {
		LOG("Error: json_dumpb not large enough (3)\n");
		json_decref(j);
		return 3;
	}

	json_dumpb(j, output, ocap, 0);
	json_decref(j);

	return 0;
}

/**
** Helper function to extract string with key `key` from a JSON object.
**
** String copied with strncpy, but ensures null-termination of destination.
** String may be truncated if not enough capacity in destination.
**
** Can check return value to differentiate errors from key not found
** because some keys may be optional.
**
** Returns zero on success, <0 if not found, >0 (error) if not string.
**/
static int json_to_string(char *str, size_t cap, json_t *root, const char *key)
{
	json_t *object = json_object_get(root, key);

	if (!object) {
		LOG("Error: key not found or error (%s: string)\n", key);
		return -1;
	}
	if (!json_is_string(object)) {
		LOG("Error: JSON object is not a string (%s: string)\n", key);
		return 1;
	}

	strncpy(str, json_string_value(object), cap - 1);
	str[cap - 1] = '\0';

	return 0;
}

// parse buffer received from RAP into a local structure
static int json_to_ra_avr(struct ra_avr *avr, const char *input, int len)
{
	json_error_t error;
	json_t *root = json_loadb(input, len, 0, &error);

	if (!root) {
		LOG("Error parsing JSON: L%d (%s)", error.line, error.text);
		return 1;
	}

	json_t *object;

	// if (object = json_object_get(root, "id")) {
	// 	// FIXME only works for optional strings, this one is mandatory
	// 	if (!json_is_string(object)) {
	// 		LOG("Error: JSON object is not a string (id: string)\n");
	// 		json_decref(root);
	// 		return 1;
	// 	}
	// 	size_t emo = sizeof(avr->report_id) - 1; // end minus one, ensure \0
	// 	strncpy(avr->report_id, json_string_value(object), emo);
	// 	avr->report_id[emo] = '\0';
	// }
	if (json_to_string(avr->report_id, sizeof(avr->report_id), root, "id")) {
		json_decref(root);
		return 1;
	}

	if (json_to_string(avr->timestamp, sizeof(avr->timestamp), root, "timestamp")) {
		json_decref(root);
		return 1;
	}

	// version is mandatory
	object = json_object_get(root, "version");
	if (!object) {
		LOG("Error: version is mandatory but key not found\n");
		json_decref(root);
		return 1;
	}
	if (!json_is_integer(object)) {
		LOG("Error: JSON object is not an integer (version: integer)\n");
		json_decref(root);
		return 1;
	}
	json_int_t num = json_integer_value(object);
	if (num < 0 || num > UINT32_MAX) {
		LOG("Error: version is out of bounds, expected uint32_t\n");
		json_decref(root);
		return 1;
	}
	avr->version = num;

	if (json_to_string(avr->quote_status, sizeof(avr->quote_status), root, "isvEnclaveQuoteStatus")) {
		json_decref(root);
		return 1;
	}

	if (json_to_string(avr->quote_body, sizeof(avr->quote_body), root, "isvEnclaveQuoteBody")) {
		json_decref(root);
		return 1;
	}

	// nonce is optional
	if (object = json_object_get(root, "nonce")) {
		if (!json_is_string(object)) {
			LOG("Error: JSON object is not a string (nonce: string)\n");
			json_decref(root);
			return 1;
		}

		size_t len = json_string_length(object);
		uint8_t s[len];
		uint32_t olen = 0;
		if (base64_decode_to_u8(s, len, &olen,
				json_string_value(object), len)) {
			LOG("Error: base64_decode_to_u8 (nonce)\n");
		} else {
			if (olen > sizeof(avr->nonce)) {
				LOG("Error: object too large (nonce=%s)\n", json_string_value(object));
			}
			memcpy(&avr->nonce, s, len);
		}
	}

	json_decref(root);

	return 0;
}





// onebuf h/c: create, delete, clear, enlarge, shrink
//TODO onebuf mini-lib: h,c for now ?

/*
struct cereal_buf *create_cereal_buf(size_t cap)
{
	uint8_t *a = malloc(cap);
	if (!cap) {
		return NULL;
	}

	struct cereal_buf *p = malloc(sizeof(struct cereal_buf));
	if (!p) {
		free(a);
		return NULL;
	}

	p->buf = a;
	p->len = 0;
	p->cap = cap;

	return p;
}

void delete_cereal_buf(struct cereal_buf *p)
{
	free(p->buf);
	free(p);
}
*/




// need free .str or done by lib ?
static struct capn_text gid_to_text(sgx_epid_group_id_t gid) {
	char *s = malloc(8 + 1);

	for (size_t i = 0; i < 8; i += 2) {
		snprintf(s+i, 9-i, "%02"PRIx8, gid[i/2]);
	}

	return (struct capn_text) {
		.len = (int) strlen(s),
		.str = s,
		.seg = NULL,
	};
}

static struct capn_text str_to_text(const char *string) {
	return (struct capn_text) {
		.len = (int) strlen(string),
		.str = string,
		.seg = NULL,
	};
}

// REVIEW caller needs to free it, or capnp handles freeing of all tree?
static struct capn_text nonce_to_text(sgx_quote_nonce_t nonce) {
	char *s = malloc(16 * 2 + 1);
	// memset(s, 0, sizeof s);

	for (size_t i = 0; i < 32; i += 2) {
		snprintf(s + i, 33 - i, "%02"PRIx8, nonce.rand[i/2]);
	}
	// s[16 * 2] = '\0'; // feito por snprintf

	return (struct capn_text) {
		.len = (int) strlen(s),
		.str = s,
		.seg = NULL,
	};
}

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

/*
// REVIEW buffer length should be uint32_t... check here for out of bounds down/up
int encode_request_sigrl_old_1(uint8_t *a, size_t cap, uint32_t *n, sgx_epid_group_id_t gid)
{
	struct capn c;
	capn_init_malloc(&c);
	capn_ptr cr = capn_root(&c);
	struct capn_segment *cs = cr.seg;

	struct RequestSigrl request = {
		.gid = gid_to_text(gid),
	};
	fprintf(stderr, "in lib, gid: %s (%d)\n", request.gid.str, request.gid.len);

	RequestSigrl_ptr p = new_RequestSigrl(cs);
	write_RequestSigrl(&request, p);
	int setp_ret = capn_setp(capn_root(&c), 0, p.p);

	int64_t len = capn_write_mem(&c, a, cap, 0);
	// *n = capn_write_mem(&c, a, cap, 0);
	capn_free(&c);
	if (len < 0 || len > UINT32_MAX) {
		fprintf(stderr, "capn_write_mem length does not fit in uint32_t\n");
		return 1;
	}
	*n = len;

	char dest[4096] = {0};
	u8_to_str(dest, a, *n, " ");
	fprintf(stderr, "buffer in encode_request_sigrl: %s\n", dest);

	return 0;
}

static int create_request_sigrl_structure(RequestSigrl_ptr *p, sgx_epid_group_id_t gid)
{
	struct capn c;
	capn_init_malloc(&c);
	capn_ptr cr = capn_root(&c);
	struct capn_segment *cs = cr.seg;

	struct RequestSigrl request = {
		.gid = gid_to_text(gid),
	};
	fprintf(stderr, "in lib, gid: %s (%d)\n", request.gid.str, request.gid.len);

	// RequestSigrl_ptr p = new_RequestSigrl(cs);
	*p = new_RequestSigrl(cs);
	write_RequestSigrl(&request, *p);
	int setp_ret = capn_setp(capn_root(&c), 0, p->p);

	return 0;
}
*/

//-----------------------

// cap must be at least 12, otherwise UB
char *sgx_epid_group_id_to_str(char *dest, size_t cap, sgx_epid_group_id_t *gid)
{
	size_t len = 4;
	size_t total = len * 2 + (len - 1) + 1; // 4-1 is separator, 1 is \0

	char *next_pos;
	for (size_t i = 0; i < len - 1; i++) {
		next_pos = dest + i * (2 + 1); // extra 1 is for separator
		sprintf(next_pos, "%02"PRIx8"%s", ((uint8_t *) gid)[i], " ");
	}
	next_pos = dest + (len - 1) * (2 + 1);
	sprintf(next_pos, "%02"PRIx8, ((uint8_t *) gid)[len - 1]);

	// printf("gid internally is %s\n", dest);

	return dest;
}

// int encode_request_sigrl(uint8_t *a, size_t cap, uint32_t *n, sgx_epid_group_id_t gid)
int rap_encode_request_sigrl(uint8_t *a, size_t cap, uint32_t *n, struct ra_sigrl *data)
{
	// reverse Group ID
	sgx_epid_group_id_t reversed = {0};
	for (size_t i = 0; i < 4; i++) {
		// reversed[0] = gid[3-i];  // FIXME doesn't work this line, memcpy does, why?
		memcpy(reversed+i, ((uint8_t *) data->gid)+3-i, sizeof(uint8_t));
	}

	struct capn c; // context
	capn_init_malloc(&c);

	capn_ptr cr = capn_root(&c);
	struct capn_segment *cs = cr.seg;

	// set initial object
	struct RAPMessage message = {
		.which = RAPMessage_requestSigrl,
		// .requestSigrl = p1,
	};


	struct RequestSigrl request = {
		.gid = gid_to_text(reversed),
	};

	// capn_ptr cr1 = capn_new_struct(cs, sizeof(request), 0);
	// struct capn_segment *cs1 = cr1.seg;
	// RequestSigrl_ptr p1 = new_RequestSigrl(cs1);
	//
	// NOTE: work with 3 lines above, and with one line below
	//plus other two write and message set liones
	// Do not understand why !!
	//
	RequestSigrl_ptr p1 = new_RequestSigrl(cs);

	write_RequestSigrl(&request, p1);
	message.requestSigrl = p1;


	RAPMessage_ptr p = new_RAPMessage(cs);
	write_RAPMessage(&message, p);
	int setp_ret = capn_setp(capn_root(&c), 0, p.p);

	int64_t len = capn_write_mem(&c, a, cap, 0);
	// *n = capn_write_mem(&c, a, cap, 0);
	capn_free(&c);
	if (len < 0 || len > UINT32_MAX) {
		fprintf(stderr, "capn_write_mem length does not fit in uint32_t\n");
		return 1;
	}
	*n = len;



	/*

	// create RequestSigrl structure

	struct RequestSigrl request = {
		.gid = gid_to_text(gid),
	};
	fprintf(stderr, "in lib, gid: %s (%d)\n", request.gid.str, request.gid.len);

	struct capn c;
	capn_init_malloc(&c);
	capn_ptr cr = capn_root(&c);
	struct capn_segment *cs = cr.seg;
	// struct capn c1;
	// capn_init_malloc(&c1);
	// capn_ptr cr1 = capn_root(&c1);
	// struct capn_segment *cs1 = cr1.seg;
	RequestSigrl_ptr p1 = new_RequestSigrl(cs);
	write_RequestSigrl(&request, p1);
	// int setp_ret = capn_setp(capn_root(&c), 0, p.p);
	//
	// int64_t len = capn_write_mem(&c, a, cap, 0);
	// // *n = capn_write_mem(&c, a, cap, 0);
	// capn_free(&c);


	// create Message structure
	// struct capn c;
	// capn_init_malloc(&c);
	// capn_ptr cr = capn_root(&c);
	// struct capn_segment *cs = cr.seg;

	struct Message message = {
		.which = Message_requestSigrl,
		.requestSigrl = p1,
	};

	Message_ptr p = new_Message(cs);
	write_Message(&request, p);
	int setp_ret = capn_setp(capn_root(&c), 0, p.p);

	int64_t len = capn_write_mem(&c, a, cap, 0);
	// *n = capn_write_mem(&c, a, cap, 0);
	capn_free(&c);
	if (len < 0 || len > UINT32_MAX) {
		fprintf(stderr, "capn_write_mem length does not fit in uint32_t\n");
		return 1;
	}
	*n = len;


	*/

	char dest[4096] = {0};
	u8_to_str(dest, a, *n, " ");
	fprintf(stderr, "buffer in encode_request_sigrl: %s\n", dest);

	return 0;
}

int rap_decode_reply_sigrl(struct ra_sigrl *data, const uint8_t *a, size_t n)
{
	struct capn rc;
	int init_mem_ret = capn_init_mem(&rc, a, n, 0);

	struct RAPMessage rep;
	RAPMessage_ptr root;
	root.p = capn_getp(capn_root(&rc), 0, 1);
	read_RAPMessage(&rep, root);

	fprintf(stderr, "deserialized reply, which index is: %d\n", rep.which);

	struct ResponseSigrl r2;
	ResponseSigrl_ptr inner_rep = rep.responseSigrl;
	read_ResponseSigrl(&r2, inner_rep);
	data->code = r2.code;
	// snprintf(data->rid, sizeof(data->rid), "%s", r2.rid.p.data);
	// TODO copy over SigRL and its size

	fprintf(stderr, "deserialized reply, code: %"PRIu32"\n", r2.code);

	return 0;
}

// does not change report fields
int rap_encode_request_report(uint8_t *output, size_t output_cap, uint32_t *output_len, const struct ra_report *report)
{
	char aep[4096] = {0};
	if (ra_aep_to_json(aep, sizeof(aep), &report->aep)) {
		LOG("Error: rap_aep_to_json\n");
		return 1;
	}
	// LOG("rap_aep_to_json: %s (strlen=%zu)\n", aep, strlen(aep));



	struct capn c;
	capn_init_malloc(&c);

	capn_ptr cr = capn_root(&c);
	struct capn_segment *cs = cr.seg;

	// outer structure
	struct RAPMessage message = {
		.which = RAPMessage_requestReport,
	};

	// inner structure
	struct RequestReport r2 = {
		// .nonce = nonce_to_text(report->aep.nonce),
		.aep = str_to_text(aep),
	};
	// LOG("random string is %s (%d)\n", r2.aep.str, r2.aep.len);

	// // Tentativa 0: works!
	// capn_ptr cr3 = capn_new_struct(cs, sizeof(r2), 0);
	// struct capn_segment *cs3 = cr3.seg;
	// RequestReport_ptr p3 = new_RequestReport(cs3);
	// write_RequestReport(&r2, p3);
	// message.requestReport = p3;

	// // Tentativa 1: works!
	// RequestReport_ptr p2 = new_RequestReport(cs);
	// write_RequestReport(&r2, p2);
	// message.requestReport = p2;

	// Tentativa 2: works!
	message.requestReport = new_RequestReport(cs);
	write_RequestReport(&r2, message.requestReport);



	RAPMessage_ptr p = new_RAPMessage(cs);
	write_RAPMessage(&message, p);
	int setp_ret = capn_setp(capn_root(&c), 0, p.p);

	// *n = capn_write_mem(&c, a, cap, 0);
	int64_t len = capn_write_mem(&c, output, output_cap, 0);
	capn_free(&c);
	if (len < 0 || len > UINT32_MAX) {
		LOG("capn_write_mem length does not fit in uint32_t\n");
		return 1;
	}
	*output_len = len;

	return 0;
}

int rap_decode_reply_report(struct ra_report *report, const uint8_t *input, size_t input_len)
{
	struct capn rc;
	int init_mem_ret = capn_init_mem(&rc, input, input_len, 0);

	struct RAPMessage rep;
	RAPMessage_ptr root;
	root.p = capn_getp(capn_root(&rc), 0, 1);
	read_RAPMessage(&rep, root);

	LOG("deserialized reply, which index is: %d\n", rep.which);

	struct ResponseReport r2;
	ResponseReport_ptr inner_rep = rep.responseReport;
	read_ResponseReport(&r2, inner_rep);
	report->code = r2.code;
	snprintf(report->rid, sizeof(report->rid), "%s", r2.rid.str);
	snprintf(report->signature, sizeof(report->signature), "%s", r2.signature.str);
	snprintf(report->certificates, sizeof(report->certificates), "%s", r2.certificates.str);

	// extract, and parse, avr
	const char *data = r2.avr.p.data;
	int len = r2.avr.p.len;
	// printf("len of data=%d\n", r2.avr.p.len);
	// if (json_to_ra_avr(&report->avr, data, len)) {
	// 	return 1;
	// }
	//
	if (len < 0 || len + 1 > sizeof(report->avr)) {
		LOG("Error: report bad size\n");
		capn_free(&rc);
		return 0xE;
	}
	memcpy(report->avr, data, len);
	report->avr[len] = '\0';

	LOG("deserialized reply, code: %"PRIu32"\n", r2.code);

	return 0;
}
