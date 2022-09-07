#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <dlfcn.h>
#include <inttypes.h>
#include <unistd.h>

#include <sgx_error.h>
#include <sgx_ukey_exchange.h>
#include <sgx_uae_epid.h>               // quote
#include <sgx_report.h>

#include <usgx/c/print_types.h>

#include "ipas/u/attestation.h"
#include "attestation_u.h"
#include "one.h"
#include "sgx_print.h"

#include "debug.h"

// #include "serialization.h"

// #include "rap.capnp.h" // temp



// TORM
static size_t u8_to_str(char *dest, const uint8_t *src, size_t len, const char *sep);



// // TEMP TORM
// static size_t u8_to_str(char *dest, const uint8_t *src, size_t len, const char *sep);

// TODO Cliente deve passar um SID aqui porque cliente é que sabe quais existem, dentro do enclave não verifico collisions.
int ipas_ma_init(struct ipas_attest_st *ia, uint32_t sid, sgx_enclave_id_t eid, void *uh, enum role role)
{
	ia->sid = sid;
	ia->eid = eid;
	if (role == ROLE_RESPONDER) {
		dlerror();
		ia->udso = dlopen("/home/daniel/w/main/20A1/vc/ipas/ipas-css/temp_untrusted.so", RTLD_NOW);
		// FIXME responder deve passar library para aqui, se assim se justificar
		if (!ia->udso) {
			LOG("Error: dlopening untrusted code shared object (%s)\n", dlerror());
			return 1;
		}
		LOG("Loaded untrusted DSO in attestation library\n");
	}
	//
	// FIXME Quando crio dlopen aqui funciona, mas passar handle falha porquê?
	//
	// if (role == ROLE_RESPONDER) {
	// 	ia->udso = uh;
	// }
	ia->role = role;

	return 0;
}

int ipas_ma_free(struct ipas_attest_st *ia)
{
	ia->eid = 0;
	if (ia->udso) {
		dlclose(ia->udso);
		ia->udso = NULL;
	}
	// if (ia->udso) {
	// 	ia->udso = NULL;
	// }

	return 0;
}

// Processed by A
int ipas_ma_get_m1(struct ipas_attest_st *ia, struct ipas_ma_m1 *m1)
{
	// get AExGroup
	uint32_t extended_epid_group_id = 0;
	if (sgx_get_extended_epid_group_id(&extended_epid_group_id)) {
		return 1;
	}
	ia->egid_a = extended_epid_group_id;

	// get AGroup
	sgx_epid_group_id_t gid = {0};
	sgx_target_info_t qe_target_info;
	memset(&qe_target_info, 0, sizeof(qe_target_info));
	if (sgx_init_quote(&qe_target_info, &gid)) {
		return 1;
	}
	memcpy(&ia->qe_target_info, &qe_target_info, sizeof(qe_target_info));
	memcpy(&ia->gid_a, &gid, sizeof(gid));

	// get APublic, ANonce
	sgx_status_t ss;
	ipas_status is;
	sgx_ec256_public_t public;
	uint8_t nonce[16];
	ss = ipas_ma_create_keys(ia->eid, &is, &public, nonce, ia->sid, 1);
	if (SGX_SUCCESS != ss) {
		LOG("ipas_ma_create_keys: failure (ss=%"PRIx32", er=%"PRIx32")\n", ss, is);
		return 1;
	}
	LOG("ipas_ma_create_keys: success\n");
	memcpy(&ia->pub_a, &public, sizeof(public));
	// memcpy(m3->nonce_a, nonce, 16); // save nonce in ia struct?

	// prepare outgoing m1
	m1->egid_a = extended_epid_group_id;
	memcpy(&m1->gid_a, &gid, sizeof(gid));
	memcpy(&m1->pub_a, &public, sizeof(sgx_ec256_public_t));

	return 0;
}

// Processed by B
int ipas_ma_get_p1(struct ipas_attest_st *ia,
		struct ipas_ma_m1 *m1, struct ipas_ma_p1 *p1)
{
	// process incoming m1
	if (m1->egid_a != 0) {
		return 1;
	}
	ia->egid_a = m1->egid_a;
	memcpy(&ia->gid_a, &m1->gid_a, sizeof(ia->gid_a));
	memcpy(&ia->pub_a, &m1->pub_a, sizeof(ia->pub_a));

	// get BGroup
	sgx_epid_group_id_t gid = {0};
	// TODO preciso qe_target_info para mais tarde? Colocar em core struct?
	sgx_target_info_t qe_target_info;
	memset(&qe_target_info, 0, sizeof(qe_target_info));
	if (sgx_init_quote(&qe_target_info, &gid)) {
		return 1;
	}
	memcpy(&ia->qe_target_info, &qe_target_info, sizeof(qe_target_info));
	memcpy(&ia->gid_b, &gid, sizeof(gid));
	// memcpy(&m2->gid_b, &gid, sizeof(gid));

	// prepare outgoing p1
	memcpy(&p1->gid_a, &m1->gid_a, sizeof(sgx_epid_group_id_t));
	memcpy(&p1->gid_b, &gid, sizeof(sgx_epid_group_id_t));

	return 0;
}

// Processed by B: in p2, out m2
int ipas_ma_get_m2(struct ipas_attest_st *ia, struct ipas_ma_p2 *p2, struct ipas_ma_m2 *m2)
{
	// process incoming p2
	if (p2->status_a != 200) {
		//TODO caller app uses (a proper, TODO) return value of this function (ipas_attest_get_m3) to find the error and inform the other node (B) that something bad happen and gracefully terminate protocol and connection or whatever.
		return 1;
	}
	if (p2->status_b != 200) {
		// TODO error enum
		return 1;
	}
	ia->length_a = p2->length_a;
	if (p2->length_a) {
		if (p2->length_a > IPAS_SRL_RSP_B_SIZE) {
			// TODO SRL body too large
			return 1;
		}
		memcpy(ia->srl_a, p2->srl_a, p2->length_a);
	}
	ia->length_b = p2->length_b;
	if (p2->length_b) {
		if (p2->length_b > IPAS_SRL_RSP_B_SIZE) {
			// TODO SRL body too large
			return 1;
		}
		memcpy(ia->srl_b, p2->srl_b, p2->length_b);
	}

	// get BExGroup
	uint32_t extended_epid_group_id = 0;
	if (sgx_get_extended_epid_group_id(&extended_epid_group_id)) {
		return 1;
	}
	ia->egid_b = extended_epid_group_id;

	// get BPublic, BNonce
	sgx_status_t ss;
	ipas_status er;
	sgx_ec256_public_t public;
	uint8_t nonce[16];
	// sgx_status_t ss = ipa_m89(ia->eid, &ecall_return, 2, &ia->qe_target_info, &public, nonce, &report);
	sgx_status_t (*f_ipas_ma_create_keys)(sgx_enclave_id_t, ipas_status *, sgx_ec256_public_t *, uint8_t *, uint32_t, int);
	*(void **) (&f_ipas_ma_create_keys) = dlsym(ia->udso, "ipas_ma_create_keys");
	if (!f_ipas_ma_create_keys) {
		LOG("Error: f_ipas_ma_create_keys (%s)\n", dlerror());
		return 1;
	}
	ss = f_ipas_ma_create_keys(ia->eid, &er, &public, nonce, ia->sid, 2);
	if (SGX_SUCCESS != ss || er) {
		LOG("ipas_ma_create_keys: failure (ss=%"PRIx32", er=%"PRIx32")\n", ss, er);
		return 1;
	}
	LOG("ipas_ma_create_keys: success\n");
	memcpy(&ia->pub_b, &public, sizeof(public));

	// prepare outgoing m2
	m2->egid_b = extended_epid_group_id;
	memcpy(&m2->pub_b, &public, sizeof(sgx_ec256_public_t));
	m2->status_a = p2->status_a;
	m2->length_a = p2->length_a;
	memcpy(m2->srl_a, p2->srl_a, p2->length_a);

	return 0;
}

// Processed by A
int ipas_ma_get_m3(struct ipas_attest_st *ia,
		struct ipas_ma_m2 *m2, struct ipas_ma_m3 *m3)
{
	// process incoming m2:

	if (m2->egid_b != 0) {
		return 1;
	}
	ia->egid_b = m2->egid_b;

	memcpy(&ia->pub_b, &m2->pub_b, sizeof(ia->pub_b));

	if (m2->status_a != 200) {
		//TODO throw error and close connection
		return 1;
	}
	ia->length_a = m2->length_a;
	if (m2->length_a) {
		if (m2->length_a > IPAS_SRL_RSP_B_SIZE) {
			// TODO SRL body too large
			return 1;
		}
		memcpy(ia->srl_a, m2->srl_a, m2->length_a);
	}

	// get AReport:

	ipas_status ecall_return;
	// sgx_ec256_public_t public;
	uint8_t nonce[16] = {0};
	sgx_report_t report;
	memset(&report, 0, sizeof(report));
	// sgx_status_t ss = ipa_m1112(ia->eid, &ecall_return, 1, &ia->qe_target_info, nonce, &report);
	sgx_status_t ss = ipas_ma_create_report(ia->eid, &ecall_return, &report, ia->sid, &ia->qe_target_info, &m2->pub_b);
	// TODO tirei o nonce, mas este nonce é o quote_nonce ???? **********
	if (SGX_SUCCESS != ss || ecall_return) {
		LOG("ipas_ma_create_report: failure (ss=%"PRIx32", er=%"PRIx32")\n", ss, ecall_return);
		return 1;
	}
	LOG("ipas_ma_create_report: success\n");

	// get AQuote:

	uint32_t quote_size = 0;
	if (sgx_calc_quote_size(ia->length_a ? ia->srl_a : NULL, ia->length_a, &quote_size)) {
		// TODO error dump: Tenho do SRX?
		return 2;
	}

	// Using fixed-size array to store quote, does it fit?
	if (sizeof(m3->quote_a) < quote_size) {
		return 40;
	}
	fprintf(stderr, "sizeof(m3->quote_a)=%zu, quote_size=%"PRIu32"\n", sizeof(m3->quote_a), quote_size);
	memset(&m3->quote_a, 0, sizeof(m3->quote_a));
	// p3->quote_a = malloc(quote_size);
	// memset(p3->quote_a, 0, quote_size);

	int busy_retry = 5; // must be >0
	const char *s = "** ESCONDIDO **";
	sgx_spid_t spid;
	l1_hstr_to_u8(sizeof(spid.id), spid.id, strlen(s), s);
	//** ESCONDIDO **
	sgx_quote_nonce_t quote_nonce = {0};
	// memcpy(&quote_nonce, nonce, 16); // In enclave ??
	sgx_report_t qe_report;
	memset(&qe_report, 0, sizeof(qe_report));
	do {
		ss = sgx_get_quote(&report, SGX_UNLINKABLE_SIGNATURE, &spid, &quote_nonce, ia->length_a ? ia->srl_a : NULL, ia->length_a, &qe_report, (sgx_quote_t *) m3->quote_a, quote_size);
		if (ss)
			sleep(2);
	} while (ss == SGX_ERROR_BUSY && --busy_retry);
	if (ss) {
		fprintf(stderr, "sgx_status = %"PRIx32"\n", ss);
		return 4;
	}
	m3->size_a = quote_size;

	// prepare outgoing m3:
	// do nothing: quote, and its size, already set above

	return 0;
}

// Processed by B
int ipas_ma_get_p3(struct ipas_attest_st *ia, struct ipas_ma_m3 *m3, struct ipas_ma_p3 *p3)
{
	// process incoming m3
	if (m3->size_a > sizeof(p3->quote_a)) {
		return 40;
	}

	sgx_status_t ss;
	ipas_status er;
	sgx_report_t report;
	memset(&report, 0, sizeof(report));
	sgx_status_t (*f_ipas_ma_create_report)(sgx_enclave_id_t, ipas_status *, sgx_report_t *, uint32_t, sgx_target_info_t *, sgx_ec256_public_t *);
	*(void **) (&f_ipas_ma_create_report) = dlsym(ia->udso, "ipas_ma_create_report");
	if (!f_ipas_ma_create_report) {
		LOG("Error: f_ipas_ma_create_report (%s)\n", dlerror());
		return 1;
	}
	ss = f_ipas_ma_create_report(ia->eid, &er, &report, ia->sid, &ia->qe_target_info, &ia->pub_a);
	if (SGX_SUCCESS != ss || er) {
		LOG("ipas_ma_create_report: failure (ss=%"PRIx32", er=%"PRIx32")\n", ss, er);
		return 1;
	}
	LOG("ipas_ma_create_report: success\n");

	// compute common hash
	// TODO isto é feito dentro enclave (ponto anterior??) por causa nonces gerados lá dentro e evitar ataque aqui fora por atacante? E enclave guarda nonce para future check!!

	// get BQuote
	uint32_t quote_size = 0;
	if (sgx_calc_quote_size(ia->length_b ? ia->srl_b : NULL, ia->length_b, &quote_size)) {
		// TODO error dump: Tenho do SRX?
		return 2;
	}

	// Using fixed-size array to store quote, does it fit?
	if (sizeof(p3->quote_b) < quote_size) {
		return 40;
	}
	memset(&p3->quote_b, 0, sizeof(p3->quote_b));

	int busy_retry = 5; // must be >0
	const char *s = "** ESCONDIDO **";
	sgx_spid_t spid;
	l1_hstr_to_u8(sizeof(spid.id), spid.id, strlen(s), s);
	//** ESCONDIDO **
	sgx_quote_nonce_t quote_nonce = {0};
	// memcpy(&quote_nonce, nonce, 16); // FIXME gerar nonce dentro enclave na ecall anterior? (antes era assim que fazia antes de mudar nome da ecall)
	sgx_report_t qe_report;
	memset(&qe_report, 0, sizeof(qe_report));
	do {
		ss = sgx_get_quote(&report, SGX_UNLINKABLE_SIGNATURE, &spid, &quote_nonce, ia->length_b ? ia->srl_b : NULL, ia->length_b, &qe_report, (sgx_quote_t *) p3->quote_b, quote_size);
		if (ss)
			sleep(2);
	} while (ss == SGX_ERROR_BUSY && --busy_retry);
	if (ss) {
		fprintf(stderr, "sgx_status = %"PRIx32"\n", ss);
		return 4;
	}
	p3->size_b = quote_size;

	// // Debug
	// char t1[8192] = {0};
	// u8_to_str(t1, &report, sizeof(report), "");
	// fprintf(stderr, "\nReport %s\n\n", t1);

	// prepare outgoing p3
	p3->size_a = m3->size_a;
	memcpy(&p3->quote_a, &m3->quote_a, p3->size_a);

	return 0;
}

// Processed by B
int ipas_ma_get_m4(struct ipas_attest_st *ia, struct ipas_ma_p4 *p4, struct ipas_ma_m4 *m4)
{
	// process incoming p4
	m4->status_a = p4->status_a;
	memcpy(m4->rid_a, p4->rid_a, sizeof(m4->rid_a));
	memcpy(m4->sig_a, p4->sig_a, sizeof(m4->sig_a));
	memcpy(m4->cc_a, p4->cc_a, sizeof(m4->cc_a));
	// m4->length_a = p4->length_a;
	// memcpy(m4->report_a, p4->report_a, m4->length_a);
	strcpy(m4->report_a, p4->report_a);
	m4->status_b = p4->status_b;
	memcpy(m4->rid_b, p4->rid_b, sizeof(m4->rid_b));
	memcpy(m4->sig_b, p4->sig_b, sizeof(m4->sig_b));
	memcpy(m4->cc_b, p4->cc_b, sizeof(m4->cc_b));
	// m4->length_b = p4->length_b;
	// memcpy(m4->report_b, p4->report_b, m4->length_b);
	strcpy(m4->report_b, p4->report_b);
	// memcpy(m4->eqs_a, p4->eqs_a, sizeof(m4->eqs_a));
	// memcpy(m4->eqs_b, p4->eqs_b, sizeof(m4->eqs_b));
#if 0
	if (p4->status_a != 200 || p4->status_b != 200) {
		return 0;
	}
#endif

	{
		sgx_status_t (*f_ipas_ma_validate_reports)(sgx_enclave_id_t, ipas_status *, uint32_t, uint32_t, char *, char *, char *, char *, uint32_t, char *, char *, char *, char *);
		*(void **) (&f_ipas_ma_validate_reports) = dlsym(ia->udso, "ipas_ma_validate_reports");
		if (!f_ipas_ma_validate_reports) {
			LOG("Error: f_ipas_ma_validate_reports (%s)\n", dlerror());
			return 1;
		}

		// validate both reports inside enclave
		sgx_status_t ss;
		int r;
		ss = f_ipas_ma_validate_reports(ia->eid, &r, ia->sid,
				p4->status_a, p4->rid_a, p4->sig_a, p4->cc_a,
				p4->report_a,
				p4->status_b, p4->rid_b, p4->sig_b, p4->cc_b,
				p4->report_b);
		if (SGX_SUCCESS != ss) {
			fprintf(stderr, "ecall_return = %d\n", r);
			fprintf(stderr, "sgx_status = %"PRIx32"\n", ss);
			return 1;
		}
		if (r) {
			// LOG("isvEnclaveQuoteStatus is not OK\n");
			LOG("Report validation in B: failure\n"); // Podia ser outro erro...
			return 1;
		}
		LOG("Report validation in B: success\n");
	}

	{
		sgx_status_t (*f_ipas_ma_prepare_m4)(sgx_enclave_id_t, ipas_status *, uint32_t, uint8_t *, uint8_t *);
		*(void **) (&f_ipas_ma_prepare_m4) = dlsym(ia->udso, "ipas_ma_prepare_m4");
		if (!f_ipas_ma_prepare_m4) {
			LOG("Error: f_ipas_ma_prepare_m4 (%s)\n", dlerror());
			return 1;
		}

		sgx_status_t ss;
		int r;
		ss = f_ipas_ma_prepare_m4(ia->eid, &r, ia->sid, m4->data, m4->mac);
		if (SGX_SUCCESS != ss) {
			fprintf(stderr, "ecall_return = %d\n", r);
			fprintf(stderr, "sgx_status = %"PRIx32"\n", ss);
			return 1;
		}
		if (r) {
			LOG("Create response in B: failure\n");
			return 1;
		}
		LOG("Create response in B: success\n");
		// TODO Calcular MAC no enclave, neste momento com chave falsa...
		// Portanto a seguir aos checks em que se gera MK, SK: B chama alguma process m5 para gerar MAC e resposta, e A chama process m6 para confirmar. E em ambos os casos metem o flip bit. Desta forma posso continuar a ter apenas uma função verify reports (até podia invocar as segundas lá de dentro usando IF initiator ou responder, mas melhor nmão, preerível chamadas extra de dentro do enclave). ************* Estas duas funções, +1 nova ***************
		//
	}
	// TODO Entrar no enclave para validar report, e se tudo OK então comunicar com B. Alternativa seria enviar para B, e esperar resultado. Mas um dos peers tem de fazer cálculos primeiro, preferível que seja A ainda que tenha que entrar no enclave. Se alguma coisa errada, terminar conexão e pronto. Ou então enviar na mesma report, mas dar indicação de que existe erro e vai terminar? (Isto para que B termine de forma graciosa.)

	// prepare outgoing m4
	// m4->status_a = p4->status_a;
	// m4->status_b = p4->status_b;
	// m4->length_a = p4->length_a;
	// m4->length_b = p4->length_b;
	// memcpy(m4->report_a, p4->report_a, m4->length_a);
	// memcpy(m4->report_b, p4->report_b, m4->length_b);
	// memcpy(m4->eqs_a, p4->eqs_a, sizeof(m4->eqs_a));
	// memcpy(m4->eqs_b, p4->eqs_b, sizeof(m4->eqs_b));

	// TODO compute MAC over response (and rest of message if any)

	return 0;
}

// Processed by A
int ipas_ma_conclude(struct ipas_attest_st *ia, struct ipas_ma_m4 *m4)
{
	// process incoming m4

	{
		// validate both reports inside enclave
		sgx_status_t ss;
		int r;
		ss = ipas_ma_validate_reports(ia->eid, &r, ia->sid,
				m4->status_a, m4->rid_a, m4->sig_a, m4->cc_a, m4->report_a,
				m4->status_b, m4->rid_b, m4->sig_b, m4->cc_b, m4->report_b);
		if (SGX_SUCCESS != ss) {
			fprintf(stderr, "ecall_return = %d\n", r);
			fprintf(stderr, "sgx_status = %"PRIx32"\n", ss);
			return 1;
		}
		if (r) {
			// LOG("isvEnclaveQuoteStatus is not OK\n");
			LOG("Report validation in A: failure\n"); // Podia ser outro erro...
			return 1;
		}
		LOG("Report validation in A: success\n");
	}

	{
		sgx_status_t ss;
		int r;
		ss = ipas_ma_process_m4(ia->eid, &r, ia->sid, m4->data, m4->mac);
		if (SGX_SUCCESS != ss) {
			fprintf(stderr, "ecall_return = %d\n", r);
			fprintf(stderr, "sgx_status = %"PRIx32"\n", ss);
			return 1;
		}
		if (r) {
			// LOG("isvEnclaveQuoteStatus is not OK\n");
			LOG("Conclusion in A: failure\n"); // Podia ser outro erro...
			return 1;
		}
		LOG("Conclusion in A: success\n");
	}




	// TODO error checking

	// TODO validate MAC

	// if (m6->status) {
	// 	// something went wrong, not successful
	// }

	// TODO wrap up: invocar uma trusted API a dizer que processo terminou e podem-se gerar chaves? Que fazer agora?
	// MK, SK têm de ficar dentro do enclave, e tudo isto tem de ser encerrado.

	return 0;
}

// dumps a GID to a NUL-terminated 9-byte string (maintains LE)
static void gid_to_char(char s[9], sgx_epid_group_id_t gid)
{
	for (size_t i = 0; i < 9; i += 2) {
		snprintf(s+i, 9-i, "%02"PRIx8, gid[i/2]);
	}
}

// Dump uint8_t array to string.
// Invoke with NULL dest to know needed length (excluding NUL).
// Separator is e.g. "" or ":" or " " or etc.
// Returns length of string. (Don't forget to add +1 in cap for NUL.)
static size_t u8_to_str(char *dest, const uint8_t *src, size_t len, const char *sep)
{
	if (len == 0) {
		return 0;
	}

	size_t total = len * 2 + (len - 1) * strlen(sep);

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

// TODO u8 to str in libone

// typedef struct _quote_t
// {
//     uint16_t            version;        /* 0   */
//     uint16_t            sign_type;      /* 2   */
//     sgx_epid_group_id_t epid_group_id;  /* 4   */
//     sgx_isv_svn_t       qe_svn;         /* 8   */
//     sgx_isv_svn_t       pce_svn;        /* 10  */
//     uint32_t            xeid;           /* 12  */
//     sgx_basename_t      basename;       /* 16  */
//     sgx_report_body_t   report_body;    /* 48  */
//     uint32_t            signature_len;  /* 432 */
//     uint8_t             signature[];    /* 436 */
// } sgx_quote_t;

#if 0
struct ipas_ma_m2 {
	uint32_t egid_b;                    // BExGroup
	sgx_ec256_public_t pub_b;           // BPublic

	uint32_t status_a;          // HTTP status (e.g. "200" for OK)
	uint32_t length_a;          // length of SigRL (only when status 200 OK)
	uint8_t srl_a[IPAS_SRL_RSP_B_SIZE]; // ASigRL
};
#endif
char *ipas_ma_m2_to_string(char *dest, size_t cap, struct ipas_ma_m2 *m2)
{
	// size_t size = 128;
	// char s[size];
	size_t size = cap;
	char *p = dest;

	char l1[] = "-------- m2 --------\n";
	char l4[] = "-------- -- --------\n";

	snprintf(p, size, "%s", l1);
	p+=strlen(l1);
	size-=strlen(l1);

	snprintf(p, size, "BExGroup    %08"PRIx32"\n", m2->egid_b);
	p+=21;
	size-=21;

	snprintf(p, size, "BPublic     ");
	p += 12, size -= 12;
	for (size_t i = 0; i < 32; i++, p+=2, size-=2) {
		snprintf(p, size, "%02"PRIx8, m2->pub_b.gx[i]);
	}
	snprintf(p, size, "\n            ");
	p += 13, size -= 13;
	for (size_t i = 0; i < 32; i++, p+=2, size-=2) {
		snprintf(p, size, "%02"PRIx8, m2->pub_b.gy[i]);
	}
	snprintf(p, size, "\n");
	p += 1, size -= 1;

	snprintf(p, size, "AStatus     %8"PRIu32"\n", m2->status_a);
	p+=21;
	size-=21;

	if (m2->length_a + 1 + strlen(l4) + 1 > size) {
		snprintf(dest, cap, "Error in ipas_ma_m2_to_string, not enough capacity\n");
		return dest;
	}
	snprintf(p, size, "ASigRL      ");
	p += 12, size -= 12;
	for (size_t i = 0; i < m2->length_a; i++, p+=2, size-=2) {
		snprintf(p, size, "%02"PRIx8, m2->srl_a[i]);
	}
	snprintf(p, size, "\n");
	p += 1, size -= 1;

	// char gid[9] = {0};
	// gid_to_char(gid, m2->gid_b);
	// snprintf(p, size, "BGroup      %s LE\n", gid);
	// p+=24;
	// size-=24;

	snprintf(p, size, "%s", l4);
	p+=strlen(l4);
	size-=strlen(l4);

	// fprintf(stderr, "%s", s);
	return dest;
}

void ipas_ma_m2_dump(struct ipas_ma_m2 *m2)
{
	size_t size = 512;
	char s[512] = {0};
	ipas_ma_m2_to_string(s, size, m2);
	fprintf(stderr, "%s", s);
}

// void ipas_attest_dump_m3(struct ipas_attest_m3 *m3)
// TODO Utilizar funções to_string dadas pelo usgx ou semelhante: sgx_print.h/c
// void ipas_ma_p1_to_string(struct ipas_ma_p1 *p1)
void ipas_ma_dump_p1(struct ipas_ma_p1 *p1)
{
	size_t size = 128;
	char s[size];
	char *p = s;

	char l1[] = "-------- p1 --------\n";
	char l4[] = "-------- -- --------\n";

	snprintf(p, size, "%s", l1);
	p+=strlen(l1);
	size-=strlen(l1);

	char gid[9];
	gid_to_char(gid, p1->gid_a);
	snprintf(p, size, "AGroup      %s LE\n", gid);
	p+=24;
	size-=24;
	gid_to_char(gid, p1->gid_b);
	snprintf(p, size, "BGroup      %s LE\n", gid);
	p+=24;
	size-=24;

	snprintf(p, size, "%s", l4);
	p+=strlen(l4);
	size-=strlen(l4);

	fprintf(stderr, "%s", s);
}

// FIXME decrementar size_t (o size) vai rodar se ficar negativo

void ipas_ma_dump_p2(struct ipas_ma_p2 *p2)
{
	size_t size = 2048;
	char s[size];

	char l1[] = "-------- p2 --------";
	char l4[] = "-------- -- --------";

	char srl_a[768] = {0};
	char srl_b[768] = {0};
	u8_to_str(srl_a, p2->srl_a, p2->length_a, " ");
	u8_to_str(srl_b, p2->srl_b, p2->length_b, " ");

	snprintf(s, size,
			"%s\n"
			"AStatus     %"PRIu32"\n"
			"BStatus     %"PRIu32"\n"
			"ALength     %"PRIu32"\n"
			"BLength     %"PRIu32"\n"
			"ASigRL      %s\n"
			"BSigRL      %s\n"
			"%s\n",
			l1,
			p2->status_a,
			p2->status_b,
			p2->length_a,
			p2->length_b,
			srl_a,
			srl_b,
			l4);

	fprintf(stderr, "%s", s);
}

void ipas_ma_dump_m3(struct ipas_ma_m3 *m3)
{
	size_t size = 1024;
	char s[size];

	char l1[] = "-------- m3 --------";
	char l4[] = "-------- -- --------";

	// // destination needs to accommodate twice length plus (len-1)*separator
	// char gx[SGX_ECP256_KEY_SIZE * 3] = {0};
	// char gy[SGX_ECP256_KEY_SIZE * 3] = {0};
	// u8_to_str(gx, &m3->pub_a.gx, SGX_ECP256_KEY_SIZE, " ");
	// u8_to_str(gy, &m3->pub_a.gy, SGX_ECP256_KEY_SIZE, " ");
	// char nonce_a[16 * 3] = {0};
	// u8_to_str(nonce_a, m3->nonce_a, 16, " ");
	// char srl_b[768] = {0};
	// u8_to_str(srl_b, m3->srl_b, m3->length_b, " ");
	//
	// snprintf(s, size,
	// 		"%s\n"
	// 		"APublic     %s\n"
	// 		"            %s\n"
	// 		"ANonce      %s\n"
	// 		"BLength     %"PRIu32"\n"
	// 		"BSigRL      %s\n"
	// 		"%s\n",
	// 		l1,
	// 		gx,
	// 		gy,
	// 		nonce_a,
	// 		m3->length_b,
	// 		srl_b,
	// 		l4);

	fprintf(stderr, "%s", s);
}

// Dumps `struct ipas_ma_p3` to `stderr`.
void ipas_ma_p3_dump(struct ipas_ma_p3 *p3)
{
	char quote_a[4096 * 2] = {0};
	char quote_b[4096 * 2] = {0};

	const char l1[] = "-------- p3 --------";
	const char l4[] = "-------- -- --------";

	sgx_quote_to_str(quote_a, sizeof(quote_a), (sgx_quote_t *) p3->quote_a);
	sgx_quote_to_str(quote_b, sizeof(quote_b), (sgx_quote_t *) p3->quote_b);
	fprintf(stderr,
			"%s\n"
			"$quote_a = %s\n"
			"$quote_b = %s\n"
			"%s\n",
			l1, quote_a, quote_b, l4);

	// // for CLI curl to IAS
	// char s1[8192] = {0};
	// u8_to_str(s1, p3->quote_a, p3->size_a, "");
	// char s2[16384] = {0};
	// u8_to_str(s2, p3->quote_b, p3->size_b, "");
	// fprintf(stderr, "\nAQuote: %s\n\nBQuote %s\n\n", s1, s2);
}

void ipas_ma_dump_m4(struct ipas_ma_m4 *m4)
{
	size_t size = 4096 * 3 + 1024;
	char s[size];

	char l1[] = "-------- m4 --------";
	char l4[] = "-------- -- --------";

	// // destination needs to accommodate twice length plus (len-1)*separator
	// char gx[SGX_ECP256_KEY_SIZE * 3] = {0};
	// char gy[SGX_ECP256_KEY_SIZE * 3] = {0};
	// u8_to_str(gx, &m4->pub_b.gx, SGX_ECP256_KEY_SIZE, " ");
	// u8_to_str(gy, &m4->pub_b.gy, SGX_ECP256_KEY_SIZE, " ");
	// char nonce_b[16 * 3] = {0};
	// u8_to_str(nonce_b, m4->nonce_b, 16, " ");
	// // char quote_b[4096 * 3] = {0};
	// // u8_to_str(quote_b, m4->quote_b, m4->size_b, " ");
	// // TODO proper quote dump
	// char quote_b[4096 * 3] = {0};
	// sgx_quote_to_str_0(4096 * 3, quote_b, (sgx_quote_t *) m4->quote_b);
	//
	// snprintf(s, size,
	// 		"%s\n"
	// 		"BPublic     %s\n"
	// 		"            %s\n"
	// 		"BNonce      %s\n"
	// 		"BSize       %"PRIu32"\n"
	// 		"BQuote:\n%s\n"
	// 		"%s\n",
	// 		l1,
	// 		gx,
	// 		gy,
	// 		nonce_b,
	// 		m4->size_b,
	// 		quote_b,
	// 		l4);

	snprintf(s, size,
			"%s\n"
			"AStatus     %"PRIu32"\n"
			"BStatus     %"PRIu32"\n"
			"%s\n",
			l1,
			m4->status_a,
			m4->status_b,
			l4);

	fprintf(stderr, "%s", s);
}

// void ipas_ma_dump_m6(struct ipas_ma_m6 *m6)
// {
// 	size_t size = 512;
// 	char s[size];
//
// 	char l1[] = "-------- m6 --------";
// 	char l4[] = "-------- --- --------";
//
// 	char data[64 * 2 + (64 - 1) + 1] = {0};
// 	u8_to_str(data, m6->data, 64, " ");
//
// 	snprintf(s, size,
// 			"%s\n"
// 			"ipas_status %s\n"
// 			"%s\n",
// 			l1,
// 			data,
// 			l4);
//
// 	fprintf(stderr, "%s", s);
// }







void usgx_ocall_print(int stream, const char *str)
{
}




/*
int ipas_attest_initiator(uint8_t *mk, uint8_t *sk, int (*read)(void *, size_t), int (*write)(void *, size_t))
{
	return 0;
}

int ipas_attest_responder(uint8_t *mk, uint8_t *sk, int (*read)(void *, size_t), int (*write)(void *, size_t))
{
	return 0;
}
*/
