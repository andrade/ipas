#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <inttypes.h>
#include <stdbool.h>

#include <sgx_quote.h>
#include <sgx_trts.h>
#include <sgx_tcrypto.h>
#include <sgx_utils.h>

#include <usgx/c/bytes.h>
#include <usgx/libc/stdio.h>

#include "ipas/debug.h"
#include "ipas/errors.h"
#include "ipas/t/attestation.h"

#include "cdecode.h"
#include "cJSON.h"
#include "perdec.h"
#include "x509.h"

/** Attestation Report Signing CA Certificate given by Intel. */
static const char ROOT[] =
		"-----BEGIN CERTIFICATE-----\n"
		"MIIFSzCCA7OgAwIBAgIJANEHdl0yo7CUMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNV\n"
		"BAYTAlVTMQswCQYDVQQIDAJDQTEUMBIGA1UEBwwLU2FudGEgQ2xhcmExGjAYBgNV\n"
		"BAoMEUludGVsIENvcnBvcmF0aW9uMTAwLgYDVQQDDCdJbnRlbCBTR1ggQXR0ZXN0\n"
		"YXRpb24gUmVwb3J0IFNpZ25pbmcgQ0EwIBcNMTYxMTE0MTUzNzMxWhgPMjA0OTEy\n"
		"MzEyMzU5NTlaMH4xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJDQTEUMBIGA1UEBwwL\n"
		"U2FudGEgQ2xhcmExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0aW9uMTAwLgYDVQQD\n"
		"DCdJbnRlbCBTR1ggQXR0ZXN0YXRpb24gUmVwb3J0IFNpZ25pbmcgQ0EwggGiMA0G\n"
		"CSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQCfPGR+tXc8u1EtJzLA10Feu1Wg+p7e\n"
		"LmSRmeaCHbkQ1TF3Nwl3RmpqXkeGzNLd69QUnWovYyVSndEMyYc3sHecGgfinEeh\n"
		"rgBJSEdsSJ9FpaFdesjsxqzGRa20PYdnnfWcCTvFoulpbFR4VBuXnnVLVzkUvlXT\n"
		"L/TAnd8nIZk0zZkFJ7P5LtePvykkar7LcSQO85wtcQe0R1Raf/sQ6wYKaKmFgCGe\n"
		"NpEJUmg4ktal4qgIAxk+QHUxQE42sxViN5mqglB0QJdUot/o9a/V/mMeH8KvOAiQ\n"
		"byinkNndn+Bgk5sSV5DFgF0DffVqmVMblt5p3jPtImzBIH0QQrXJq39AT8cRwP5H\n"
		"afuVeLHcDsRp6hol4P+ZFIhu8mmbI1u0hH3W/0C2BuYXB5PC+5izFFh/nP0lc2Lf\n"
		"6rELO9LZdnOhpL1ExFOq9H/B8tPQ84T3Sgb4nAifDabNt/zu6MmCGo5U8lwEFtGM\n"
		"RoOaX4AS+909x00lYnmtwsDVWv9vBiJCXRsCAwEAAaOByTCBxjBgBgNVHR8EWTBX\n"
		"MFWgU6BRhk9odHRwOi8vdHJ1c3RlZHNlcnZpY2VzLmludGVsLmNvbS9jb250ZW50\n"
		"L0NSTC9TR1gvQXR0ZXN0YXRpb25SZXBvcnRTaWduaW5nQ0EuY3JsMB0GA1UdDgQW\n"
		"BBR4Q3t2pn680K9+QjfrNXw7hwFRPDAfBgNVHSMEGDAWgBR4Q3t2pn680K9+Qjfr\n"
		"NXw7hwFRPDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgwBgEB/wIBADANBgkq\n"
		"hkiG9w0BAQsFAAOCAYEAeF8tYMXICvQqeXYQITkV2oLJsp6J4JAqJabHWxYJHGir\n"
		"IEqucRiJSSx+HjIJEUVaj8E0QjEud6Y5lNmXlcjqRXaCPOqK0eGRz6hi+ripMtPZ\n"
		"sFNaBwLQVV905SDjAzDzNIDnrcnXyB4gcDFCvwDFKKgLRjOB/WAqgscDUoGq5ZVi\n"
		"zLUzTqiQPmULAQaB9c6Oti6snEFJiCQ67JLyW/E83/frzCmO5Ru6WjU4tmsmy8Ra\n"
		"Ud4APK0wZTGtfPXU7w+IBdG5Ez0kE1qzxGQaL4gINJ1zMyleDnbuS8UicjJijvqA\n"
		"152Sq049ESDz+1rRGc2NVEqh1KaGXmtXvqxXcTB+Ljy5Bw2ke0v8iGngFBPqCTVB\n"
		"3op5KBG3RjbF6RRSzwzuWfL7QErNC8WEy5yDVARzTA5+xmBc388v9Dm21HGfcC8O\n"
		"DD+gT9sSpssq0ascmvH49MOgjt1yoysLtdCtJW/9FZpoOypaHx0R+mJTLwPXVMrv\n"
		"DaVzWh5aiEx+idkSGMnX\n"
		"-----END CERTIFICATE-----\n";


// ------------------ Internal structure for contexts ------------------

struct {
	uint32_t id;                             // data: ID
	int role;                           // 1 for initiator, 2 for responder

	sgx_ecc_state_handle_t ecc_handle;  // data: handle
	sgx_ec256_public_t public;          // my public key
	sgx_ec256_private_t private;        // my private key
	uint8_t nonce[16];                  // my nonce

	sgx_ec256_public_t peer_pub;        // public key of peer

	sgx_report_data_t rd;               // hash(ipub||rpub||VK)

	sgx_cmac_128bit_key_t kdk;          // key derivation key, shared
	sgx_cmac_128bit_key_t smk;

	sgx_cmac_128bit_key_t mk;           // returned to App TC
	sgx_aes_gcm_128bit_key_t sk;        // returned to App TC

	bool are_reports_ok;                // both reports validated successfully
	bool is_ma_complete;                // MA protocol is complete, keys ready

	//bool are_keys_ready;                // shared secret keys have been computed
	//bool is_ma_verified;                // MA protocol is complete, keys ready
	// bool is_peer_happy;
	// bool is_ma_complete;

	int is_set;                              // 0 if entry is considered empty
} session[5];

// Returns the maximum number of sessions supported.
static uint32_t get_max_sessions()
{
	return sizeof(session) / sizeof(session[0]);
}

// TODO reset Session ID structure
//      (útil caso ocorra erro) Invocado por caller, se quiser, não pela TC

// ---------------------------------------------------------------------

// output should be large enough to accomodate the decoded input
// returns the length of the output
static int base64_decode(char *output, const char *input, int length)
{
	assert(output && input);

	base64_decodestate s;
	base64_init_decodestate(&s);
	return base64_decode_block(input, length, output, &s);
}

// void usgx_ecall_dummy()
// {
// }

void *ipas_ma_get_key(uint32_t sid, int key_id)
{
	if (sid >= get_max_sessions()) {
		return NULL;
	}

	if (!session[sid].are_reports_ok || !session[sid].is_ma_complete) {
		return NULL;
	}

	switch (key_id) {
		case 1:
			return &session[sid].mk;
		case 2:
			return &session[sid].sk;
		default:
			return NULL;
	}
}




int ipas_ma(uint8_t mk[static 16], uint8_t sk[static 16])
{
	// TODO Como sei para onde enviar as mensagens? Um passo inicial a passar um file descriptor para um túnel, talvez caller tem que implementar funções leitura/escrita? Temos função setup para isso? Talvez se entregue apenas a localização?
	//
	// Preciso assumir também, que do outro lado pode haver um protocolo complexo. Pelo que o ideal é entregarmos a mensagem a uma entidade controlada pelo caller, e depois o caller faz a entrega e vai buscar o resultado, e entrega-nos a nós o resultado. E depois esta função vai repetindo o processo até terminal.
	// Assim havendo protocolo de comunicação complexo, ou que pode ser cleartext, TLS, etc; ou com diferentes formas de serialização, sabemos sempre que o caller lida com essa parte.
	// E aqui temos duas partes: lidar com serialização de ipas_ma para ipas_ma, e aqui podemos fazer nós isso, e depois lidar com rede. Melhor é caller lidar com ambos os processors, e esta função e descendentes lidarem apenas com estruturas C e SGX; depois caller que se amanhe com serialização e rede. Para o projecto faço serialização/rede na mesma, mas assim fica mais flexível.
	// De qualquer forma, serialização e rede não são tratados *dentro* do enclave, apenas no UC, pelo que esta função não lida com essa parte.
	//
	// Se endereços IP, etc, forem colocados no enclave.config.xml, pode-se ir lá buscar a info para a rede. Mas não é muito flexível.
	// Talvez haja estrutura do IPAS com esta info, usada num setup inicial e passada a funções que tratam da rede.
	return 0;
}



//
// TODO convert all functions to correct naming with `_process_m3` etc
// TODO switch to using internal `sessions` instead of ds.ch
//
// Acho que é suposto ipa_m67, etc, serem invocadas pelo IPAS UC de forma a esconder to utilizador.
// Assim sendo, também devo esconder o ipas_ma_process_m5, etc? Teria wrapper ou que fosse preciso no IPAS UC. Assim caller tinha de criar enclave, mas nunca lidava directamente com funções do IPAS TC, era tudo feito via IPAS UC.
// Update: Já está feito assim, as funções TC com process são invocadas por UC!
//

// Q: O que é guardado dentro do enclave, e o que é guardado em ia?



// /**
// ** Generates a key pair and a nonce for A.
// **
// ** [i]  sid:       Session ID
// **
// ** [o]  pub:       public key of A
// ** [o]  nonce:     nonce of A
// **
// ** Returns zero on success, non-zero otherwise.
// ** Status: IPAS_SUCCESS       all good
// **         IPAS_BAD_SID       Session ID out of bounds
// **         IPAS_FAILURE       internal error
// **/
// ipas_status ipa_m67(uint32_t sid, sgx_ec256_public_t *pub, uint8_t nonce[16])
// {
// 	if (sid >= get_max_sessions()) {
// 		return IPAS_BAD_SID;
// 	}
//
// 	if (sgx_ecc256_open_context(&session[sid].ecc_handle)) {
// 		return IPAS_FAILURE;
// 	}
// 	if (sgx_ecc256_create_key_pair(&session[sid].private, &session[sid].public, session[sid].ecc_handle)) {
// 		sgx_ecc256_close_context(session[sid].ecc_handle);
// 		return IPAS_FAILURE;
// 	}
//
// 	if (sgx_read_rand(session[sid].nonce, 16)) {
// 		sgx_ecc256_close_context(session[sid].ecc_handle);
// 		return IPAS_FAILURE;
// 	}
//
// 	memcpy(pub, &session[sid].public, sizeof(sgx_ec256_public_t));
// 	memcpy(nonce, session[sid].nonce, 16);
//
// 	return IPAS_SUCCESS;
// }
//
// // FIXME estou a guardar stack na DB, fix this! usar DB diretamente
//
// // Called in B
// // get report, need QE target?
// /**
// ** Generates a key pair and a nonce for B. Computes report for LA.
// **
// ** [i]  sid:       Session ID
// **
// ** [o]  pub:       public key of A
// ** [o]  nonce:     nonce of A
// **
// ** Returns zero on success, non-zero otherwise.
// ** Status: IPAS_SUCCESS       all good
// **         IPAS_BAD_SID       Session ID out of bounds
// **         IPAS_FAILURE       internal error
// **/
// ipas_status ipa_m89(uint32_t sid, sgx_target_info_t *qe_target_info, sgx_ec256_public_t *pub, uint8_t nonce[16], sgx_report_t *report)
// {
// 	if (sid >= get_max_sessions()) {
// 		return IPAS_BAD_SID;
// 	}
//
// 	if (sgx_ecc256_open_context(&session[sid].ecc_handle)) {
// 		return IPAS_FAILURE;
// 	}
// 	if (sgx_ecc256_create_key_pair(&session[sid].private, &session[sid].public, session[sid].ecc_handle)) {
// 		sgx_ecc256_close_context(session[sid].ecc_handle);
// 		return IPAS_FAILURE;
// 	}
//
// 	if (sgx_read_rand(session[sid].nonce, 16)) {
// 		sgx_ecc256_close_context(session[sid].ecc_handle);
// 		return IPAS_FAILURE;
// 	}
//
// 	memcpy(pub, &session[sid].public, sizeof(sgx_ec256_public_t));
// 	memcpy(nonce, session[sid].nonce, 16);
//
// 	// get report for B:
//
// 	sgx_report_data_t report_data = {0};
//
// 	if (sgx_create_report(qe_target_info, &report_data, report)) {
// 		sgx_ecc256_close_context(session[sid].ecc_handle);
// 		return IPAS_FAILURE;
// 	}
//
// 	return IPAS_SUCCESS;
// }



/**
** Generates key pair and nonce.
**
** [i]  sid:       Session ID
** [i]  role:      role is 1 for initiator, or 2 for responder
**
** [o]  pub:       public key of A
** [o]  nonce:     nonce of A
**
** Returns zero on success, non-zero otherwise.
** Status: IPAS_SUCCESS       all good
**         IPAS_BAD_SID       Session ID out of bounds
**         IPAS_FAILURE       internal error
**/
ipas_status ipas_ma_create_keys(sgx_ec256_public_t *pub, uint8_t *nonce, uint32_t sid, int role)
{
	if (sid >= get_max_sessions()) {
		return IPAS_BAD_SID;
	}

	if (sgx_ecc256_open_context(&session[sid].ecc_handle)) {
		return IPAS_FAILURE;
	}
	if (sgx_ecc256_create_key_pair(&session[sid].private, &session[sid].public, session[sid].ecc_handle)) {
		sgx_ecc256_close_context(session[sid].ecc_handle);
		return IPAS_FAILURE;
	}

	if (sgx_read_rand(session[sid].nonce, 16)) {
		sgx_ecc256_close_context(session[sid].ecc_handle);
		return IPAS_FAILURE;
	}

	memcpy(pub, &session[sid].public, sizeof(sgx_ec256_public_t));
	memcpy(nonce, session[sid].nonce, 16);

	session[sid].role = role;

	return IPAS_SUCCESS;
}

// Compute the KDK based on self private key and peer public key
static int compute_kdk(uint32_t sid)
{
	sgx_status_t ss;

	sgx_ec256_dh_shared_t shared_key;
	ss = sgx_ecc256_compute_shared_dhkey(&session[sid].private, &session[sid].peer_pub, &shared_key, session[sid].ecc_handle);
	if (ss) {
		return 1;
	}

	sgx_cmac_128bit_key_t cmac_key = {0};
	sgx_cmac_128bit_tag_t cmac_tag = {0};
	ss = sgx_rijndael128_cmac_msg(&cmac_key, (uint8_t *) &shared_key, sizeof(shared_key), &cmac_tag);
	if (ss) {
		return 1;
	}
	memcpy(&session[sid].kdk, &cmac_tag, sizeof(cmac_tag));

	return 0;
}

/**
** Derivation sequence used with KDK to derive other shared keys.
**
** [o] output: the derivation sequence
** [i] label:  null-terminated label
**
** Returns length of derivation sequence.
** Use NULL `output` to find required capacity.
**/
static size_t compute_derivation_sequence(uint8_t *output, const char *label)
{
	size_t length = 1 + strlen(label) + 3;

	// caller can find capacity required
	if (!output)
		return length;

	memset(output, 0, length);

	output[0] = 0x01;
	memcpy(output + 1, label, strlen(label));
	output[1 + strlen(label)] = 0x00;
	output[2 + strlen(label)] = 0x80;
	output[3 + strlen(label)] = 0x00;

	return length;
}

/**
** Derives a session key based on the KDK and a label.
** These session keys are SMK, VK, MK, SK.
** The output key is always 16 bytes.
** Returns zero on success, non-zero otherwise.
**/
static int derive_session_key(uint8_t key[16], const char *label, const sgx_cmac_128bit_key_t *cmac_key)
{
	size_t length = compute_derivation_sequence(NULL, label);
	uint8_t *sequence = malloc(length);
	compute_derivation_sequence(sequence, label);

	sgx_cmac_128bit_tag_t cmac_tag = {0};
	if (sgx_rijndael128_cmac_msg(cmac_key, sequence, length, &cmac_tag)) {
		free (sequence);
		return 1;
	}
	memcpy(key, &cmac_tag, sizeof(cmac_tag));

	free(sequence);

	return 0;
}

static int compute_report_data(sgx_report_data_t *report_data, uint32_t sid)
{
	if (compute_kdk(sid)) {
		return 1;
	}

	// derive SMK
	if (derive_session_key((uint8_t *) &session[sid].smk, "SMK", &session[sid].kdk)) {
		return 1;
	}

	// prepare sequence for report data
	size_t size = sizeof(sgx_ec256_public_t) * 2 + 16;
	uint8_t data[size];
	// uint8_t vk[16] = {0};
	if (derive_session_key(&data[sizeof(sgx_ec256_public_t) * 2], "VK", &session[sid].kdk)) {
		return 1;
	}
	sgx_ec256_public_t *initiator, *responder;
	switch (session[sid].role) {
		case 1:
			initiator = &session[sid].public;
			responder = &session[sid].peer_pub;
			break;
		case 2:
			initiator = &session[sid].peer_pub;
			responder = &session[sid].public;
			break;
		default:
			return 1;
	}
	memcpy(&data[0], initiator, sizeof(*initiator));
	memcpy(&data[sizeof(*initiator)], responder, sizeof(*responder));
	// FIXME assim aparece trocado, não pode ser peer pub no lado B..
	// FIXME Talvez receber o role initiator ou responder...?  *******
	// Está fixed, verificar primeiro (ainda não faço o memcpy, e onde!?) e depois apagar estes comentários e tick box na janela do lado.

	// compute hash for report data
	sgx_sha256_hash_t hash = {0};
	if (sgx_sha256_msg(data, size, &hash)) {
		return 1;
	}
	memcpy(report_data, &hash, sizeof(hash));

	return 0;
}

/**
** Computes report for LA.
**
** Peer public key, peer_pub, is saved internally.
**
** [o]  report:         report for QE

** [i]  sid:            Session ID
** [i]  qe_target_info: identifies verifier (QE in this case)
** [i]  peer_pub:       public key of peer
**
** Returns zero on success, non-zero otherwise.
** Status: IPAS_SUCCESS       all good
**         IPAS_BAD_SID       Session ID out of bounds
**         IPAS_FAILURE       internal error
**/
ipas_status ipas_ma_create_report(sgx_report_t *report, uint32_t sid, sgx_target_info_t *qe_target_info, sgx_ec256_public_t *peer_pub)
{
	if (sid >= get_max_sessions()) {
		return IPAS_BAD_SID;
	}

	// save peer public key internally
	memcpy(&session[sid].peer_pub, peer_pub, sizeof(*peer_pub));

	int r = compute_report_data(&session[sid].rd, sid);
	if (r) {
		return IPAS_FAILURE;
	}

	if (sgx_create_report(qe_target_info, &session[sid].rd, report)) {
		return IPAS_FAILURE;
	}

	return IPAS_SUCCESS;
}



// // Called in A
// // get report
// int ipa_m1112(uint32_t sid, sgx_target_info_t *qe_target_info, uint8_t nonce[16], sgx_report_t *report)
// {
// 	if (sid >= get_max_sessions()) {
// 		return IPAS_BAD_SID;
// 	}
//
// 	// retrieve key pair and nonce for A:
//
// 	sgx_ec256_public_t *public = get_public(sid);
// 	memcpy(nonce, get_nonce(sid), 16);
//
// 	// get report for A:
//
// 	sgx_report_data_t report_data = {0};
//
// 	if (sgx_create_report(qe_target_info, &report_data, report)) {
// 		return 6;
// 	}
//
// 	return 0;
// }
// // WIP *******************
//
// // int ipas_attest_initiator(uint8_t *mk, uint8_t *sk, int (*read)(void *, size_t), int (*write)(void *, size_t))
// // {
// // 	return 0;
// // }
// //
// // int ipas_attest_responder(uint8_t *mk, uint8_t *sk, int (*read)(void *, size_t), int (*write)(void *, size_t))
// // {
// // 	return 0;
// // }



// int test_rap_get_report(sgx_target_info_t *qe_target, sgx_report_t *report)
// {
// 	// sgx_report_data_t report_data = {0};
// 	//
// 	// if (sgx_create_report(qe_target, &report_data, report)) {
// 	// 	return 6;
// 	// }
// 	//
// 	// return 0;
// 	return sgx_create_report(qe_target, NULL, report);
// }




/**
** Validates fields of a single report from IAS.
**
** [i]  report:         report received from IAS
** [i]  sid:            Session ID
**
** Returns zero on success (when the report is valid), or non-zero otherwise.
** Status: IPAS_SUCCESS       all good
**         IPAS_BAD_QUOTE_STATUS unacceptable enclave quote status
**         IPAS_BAD_RD        report data received does not match original one
**         IPAS_FAILURE       internal error
**/
static int validate_report(const char *report, uint32_t sid)
{
	assert(sid < get_max_sessions());

	char buffer[2048];

	cJSON *json = cJSON_Parse(report);
	if (!json) {
		LOG("Error: parsing JSON in report\n");
		return IPAS_FAILURE;
	}

	{
		const cJSON *json_eqs = cJSON_GetObjectItemCaseSensitive(json,
				"isvEnclaveQuoteStatus");
		if (!cJSON_IsString(json_eqs) || !json_eqs->valuestring) {
			cJSON_Delete(json);
			return IPAS_FAILURE;
		}
		const char *eqs = json_eqs->valuestring;
		LOG("Report.isvEnclaveQuoteStatus: %s\n", eqs);

		// TEMP Estou a usar GROUP_OUT_OF_DATE por causa do meu processador.
		//      Mas devia ser apenas OK.
		if (strcmp(eqs, "OK") && strcmp(eqs, "GROUP_OUT_OF_DATE")) {
		// if (strcmp(eqs, "OK")) {
			cJSON_Delete(json);
			return IPAS_BAD_QUOTE_STATUS;
		}
	}

	{
		const cJSON *json_eqb = cJSON_GetObjectItemCaseSensitive(json,
				"isvEnclaveQuoteBody");
		if (!cJSON_IsString(json_eqb) || !json_eqb->valuestring) {
			cJSON_Delete(json);
			return IPAS_FAILURE;
		}
		const char *eqb = json_eqb->valuestring;
		// LOG("eqb (base64): %s\n", eqb);

		char body[1024];
		int len = base64_decode(body, eqb, strlen(eqb));
		// LOG("eqb: %s\n", b2s(buffer, sizeof(buffer), body, len, NULL));

		sgx_quote_t quote = {0};
		memcpy(&quote, body, len);
		LOG("GID: %s LE\n", b2s(buffer, sizeof(buffer),
				&quote.epid_group_id, sizeof(sgx_epid_group_id_t), NULL));
		LOG("RD: %s\n", b2s(buffer, sizeof(buffer),
				&quote.report_body.report_data,
				sizeof(sgx_report_data_t), NULL));

		// ensure report data is correct
		sgx_report_data_t *original = &session[sid].rd;
		sgx_report_data_t *received = &quote.report_body.report_data;
		if (memcmp(original, received, sizeof(sgx_report_data_t))) {
			cJSON_Delete(json);
			return IPAS_BAD_RD;
		}
	}

	cJSON_Delete(json);
	return IPAS_SUCCESS;
}

/**
** Verifies IAS signature and validates reports.
**
** During attestation the IAS returns a signed AVR (Attestation
** Verification Report). This function validates the certificate
** chain and ensures its trust anchor is correct; verifies the
** IAS signature over the report; and validates the report fields.
** This is done for the reports of both initiator and responder.
**
** [i]  sid:            Session ID
**
** Returns zero on success (when validation is OK), or non-zero otherwise.
** Status: IPAS_SUCCESS       all good
**         IPAS_BAD_SID       Session ID out of bounds
**         IPAS_BAD_SIG       invalid signature over report
**         IPAS_BAD_QUOTE_STATUS unacceptable enclave quote status
**         IPAS_BAD_RD        report data received does not match original one
**         IPAS_FAILURE       internal error
**/
int ipas_ma_validate_reports(uint32_t sid,
		uint32_t status_a, char *rid_a, char *sig_a, char *cc_a, char *report_a,
		uint32_t status_b, char *rid_b, char *sig_b, char *cc_b, char *report_b)
{
	if (sid >= get_max_sessions()) {
		return IPAS_BAD_SID;
	}

	LOG("Response status A: %"PRIu32"\n", status_a);
	LOG("Response status B: %"PRIu32"\n", status_b);
	LOG("Request ID A: %s\n", rid_a);
	LOG("Request ID B: %s\n", rid_b);
	// LOG("Signature over A's report (base64): %s\n", sig_a);
	// LOG("Signature over B's report (base64): %s\n", sig_b);
	// LOG("Certificate chain of A (url-encoded): %s\n", cc_a);
	// LOG("Certificate chain of B (url-encoded): %s\n", cc_b);
	// LOG("AReport (%zu): %s\n", strlen(report_a), report_a);
	// LOG("BReport (%zu): %s\n", strlen(report_b), report_b);


	percent_decode(cc_a, cc_a);
	percent_decode(cc_b, cc_b);

	if (verify_cert(ROOT, strlen(ROOT), cc_a, strlen(cc_a))) {
		LOG("Invalid initiator certificate chain ✗\n");
		return 1;
	}
	LOG("Validated initiator certificate chain ✓\n");

	if (verify_cert(ROOT, strlen(ROOT), cc_b, strlen(cc_b))) {
		LOG("Invalid responder certificate chain ✗\n");
		return 2;
	}
	LOG("Validated responder certificate chain ✓\n");


	char signature[1024]; // decoded signature
	int siglen;
	int r;

	siglen = base64_decode(signature, sig_a, strlen(sig_a));
	r = verify_sig(cc_a, strlen(cc_a), signature, siglen, report_a, strlen(report_a));
	if (r) {
		if (r == 11) {
			LOG("Invalid initiator signature ✗\n");
			return IPAS_BAD_SIG;
		}
		return IPAS_FAILURE;
	}
	LOG("Verified initiator signature over report ✓\n");

	siglen = base64_decode(signature, sig_b, strlen(sig_b));
	r = verify_sig(cc_b, strlen(cc_b), signature, siglen, report_b, strlen(report_b));
	if (r) {
		if (r == 11) {
			LOG("Invalid responder signature ✗\n");
			return IPAS_BAD_SIG;
		}
		return IPAS_FAILURE;
	}
	LOG("Verified responder signature over report ✓\n");

	if (r = validate_report(report_a, sid)) {
		LOG("AReport is invalid ✗\n");
		return r;
	}
	LOG("AReport is valid ✓\n");

	if (r = validate_report(report_b, sid)) {
		LOG("BReport is invalid ✗\n");
		return r;
	}
	LOG("BReport is valid ✓\n");

	session[sid].are_reports_ok = true;

	return 0;
}


// computes MK, SK; other keys are computed in previous steps
static int compute_shared_secret_keys(uint32_t sid)
{
	if (derive_session_key((uint8_t *) &session[sid].mk, "MK", &session[sid].kdk)) {
		return 1;
	}

	if (derive_session_key((uint8_t *) &session[sid].sk, "SK", &session[sid].kdk)) {
		return 1;
	}

	return 0;
}


/**
** Creates response to return to initiator, and computes shared secret keys.
**
** [i]  sid:       Session ID
**
** [o]  data:      contains response for peer
** [o]  tag:       MAC over data using SMK
**
** Returns zero on success, non-zero otherwise.
** Status: IPAS_SUCCESS       all good
**         IPAS_BAD_SID       Session ID out of bounds
**         IPAS_FAILURE       internal error
**/
ipas_status ipas_ma_prepare_m4(uint32_t sid, uint8_t *data, uint8_t *tag)
{
	if (sid >= get_max_sessions()) {
		return IPAS_BAD_SID;
	}

	// Validar directamente a partir do interior, em vez de duas ecalls?
	// if (ipas_ma_validate_reports(sid, eqs_a, eqs_b)) {
	// 	return 403; // Instead of 403, return failure status to peer?
	// }

	// prepare decision
	ipas_status decision = IPAS_FAILURE;
	if (session[sid].are_reports_ok) {
		decision = IPAS_SUCCESS;
	}
	memset(data, 0, 64);
	memcpy(data, &decision, sizeof(decision));

	// compute MAC
	if (sgx_rijndael128_cmac_msg(&session[sid].smk, data, 64, (sgx_cmac_128bit_tag_t *) tag)) {
		return IPAS_FAILURE;
	}

	// compute shared secret keys
	if (compute_shared_secret_keys(sid)) {
		return IPAS_FAILURE;
	}

	session[sid].is_ma_complete = true;

	return IPAS_SUCCESS;
}

// TODO Need nonce in the exchange, sent with REQ and checked when back here?

/**
** Verify MAC and validate response, then compute shared secret keys.
**
** [i]  sid:       Session ID
** [i]  data:      contains peer's response
** [i]  tag:       MAC over data using SMK
**
** Returns zero on success, non-zero otherwise.
** Status: IPAS_SUCCESS       all good
**         IPAS_BAD_SID       Session ID out of bounds
**         IPAS_BAD_TAG       response tag is wrong
**         IPAS_PEER_VETO     peer failure during MA
**         IPAS_FAILURE       internal error
**/
ipas_status ipas_ma_process_m4(uint32_t sid, uint8_t *data, uint8_t *tag)
{
	if (sid >= get_max_sessions()) {
		return IPAS_BAD_SID;
	}

	// verify MAC
	uint8_t temp_tag[16];
	if (sgx_rijndael128_cmac_msg(&session[sid].smk, data, 64, &temp_tag)) {
		return IPAS_FAILURE;
	}
	if (memcmp(tag, temp_tag, 16)) {
		return IPAS_BAD_TAG;
	}

	// validate response
	ipas_status status;
	memcpy(&status, data, sizeof(status));
	if (status != IPAS_SUCCESS) {
		session[sid].is_ma_complete = false;
		return IPAS_PEER_VETO;
	}

	// compute shared secret keys
	if (compute_shared_secret_keys(sid)) {
		return IPAS_FAILURE;
	}

	session[sid].is_ma_complete = true;

	return IPAS_SUCCESS;
}
