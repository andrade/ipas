#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <inttypes.h>
#include <stdbool.h>

#include <usgx/libc/stdio.h> // import from stdio.h with usgx prefix
// // #include <usgx/t/util.h> // import from stdio.h with usgx prefix
// // #include <usgx/usgx.h>
// #include "sealing_t.h"

#include <sgx_trts.h>
#include <sgx_tcrypto.h>
#include <sgx_tseal.h>
#include <sgx_utils.h>

#include "ipas/errors.h"
#include "ipas/t/attestation.h"
#include "ipas/t/sealing.h"

#include "../c/debug.h"

/** Length in bytes of part of ipas_seal_data to use as part of AD. **/
static const uint32_t const SD_FIRST_BLOCK = 692;

static uint8_t SEALING_NONCE[16];
static uint8_t UNSEALING_NONCE[16];

static uint8_t csk[16]; // client secret key
static bool is_key_set; // has the client secret key been generated / retrieved

static bool is_s_ok; // was sealing protocol successful, and is CSK available?
static bool is_u_ok; // was unsealing protocol successful, is CSK available?

static uint8_t sealed_key[640]; // S2

static char *b2s(char *dest, size_t cap, const void *src, size_t len,
		const char *prefix,
		const char *sep,
		const char *suffix)
{
	if (dest == NULL)
		return "";

	if (!prefix)
		prefix = "";
	if (!sep)
		sep = "";
	if (!suffix)
		suffix = "";
	size_t required = len * 2
			+ len * strlen(prefix)
			+ (len - 1) * strlen(sep)
			+ len * strlen(suffix)
			+ 1;

	if (required > cap) {
		return NULL;
	}

	if (len == 0 || src == NULL) {
		dest[0] = '\0';
		return dest;
	}

	char *next_pos = dest;
	const size_t chunk = 2 + strlen(prefix) + strlen(sep) + strlen(suffix);
	const uint8_t *_src = src;

	for (size_t i = 0; i < len - 1; i++, next_pos += chunk) {
		snprintf(next_pos, cap - i * chunk,
				"%s%02"PRIx8"%s%s",
				prefix, _src[i], suffix, sep);
	}
	snprintf(next_pos, cap - (len - 1) * chunk - 2,
			"%s%02"PRIx8"%s",
			prefix, _src[len - 1], suffix);

	return dest;
}

/**
** Generates a secret key to encrypt client data.
**
** Encrypts the secret key, K, using SK from MA.
**
** Returns zero on success, non-zero otherwise.
** Status: IPAS_SUCCESS         all good
**         IPAS_NO_KEY          required key, SK, not available
**         IPAS_FAILURE         internal error
**/
ipas_status ipas_s_get_sealing_key(
	uint8_t iv[12],     // out: for ciphertext in m1
	uint8_t ct[16+16],  // out: ciphertext is nonce(16)||K(16)
	uint8_t tag[16],    // out: for ciphertext in m1
	uint32_t sid        // in: Session ID for MA library when retrieving SK
)
{
	if (sgx_read_rand(iv, 12)) {
		return IPAS_FAILURE;
	}

	uint8_t plaintext[16 + 16] = {0}; // nonce(16)||key(16)
	if (sgx_read_rand(plaintext, sizeof(plaintext))) {
		return IPAS_FAILURE;
	}

	// Ter variável conhecida com a chave. Se a chave estiver vazia, posso até ter outro bit, simplesmente gerar aqui uma. Ideia era que enclave até podia fazer cifra e tudo, e só no final invocar em App UC -> IPAS UC o protocolo seal para guardar chave K; e depois guardava logo directamente disco sem entrar no enclave. Mas se enclave precisar validar resposta, tem lá nonce na mesma (ainda que host possa fazer discard porque fora da TCB).
	// MA completed successfully, or this call fails
	sgx_aes_gcm_128bit_key_t *sk = ipas_ma_get_key(sid, 2);
	if (sk == NULL) {
		return IPAS_NO_KEY;
	}

	if (sgx_rijndael128GCM_encrypt(sk, plaintext, sizeof(plaintext), ct, iv, 12, iv, 12, (sgx_aes_gcm_128bit_tag_t *) tag)) {
		return IPAS_FAILURE;
	}

	// save client secret key for later
	memcpy(csk, &plaintext[16], 16);

	// save nonce for verification in ipas_s_process_m2
	memcpy(SEALING_NONCE, plaintext, 16);

	return IPAS_SUCCESS;
}

/**
** Decrypts client data, returns sealed K for m2
**
** Decrypts the secret key, K, using SK from MA.
** Computes MAC over sealed K and received nonce using MK from MA.
**
** Returns zero on success, non-zero otherwise.
** Status: IPAS_SUCCESS         all good
**         IPAS_NO_KEY          required key, SK or MK, not available
**         IPAS_CAPACITY        output buffer not large enough (size is set)
**         IPAS_FAILURE         internal error
**/
ipas_status ipas_s_process_m1(
	void *data,                 // out: sealed data
	uint32_t *size,             // out: sealed data size
	sgx_cmac_128bit_tag_t *mac, // out: computed over data plus nonce
	uint32_t sid,               // in
	uint8_t iv[12],             // in: IV for decryption of ciphertext
	uint8_t ct[32],             // in: ciphertext to decrypt
	sgx_aes_gcm_128bit_tag_t *tag // in: tag for decryption of ciphertext
)
{
	// decrypt blob, create pointers for structures
	sgx_aes_gcm_128bit_key_t *sk = ipas_ma_get_key(sid, 2);
	if (sk == NULL) {
		return IPAS_NO_KEY;
	}
	uint8_t plaintext[32] = {0};
	if (sgx_rijndael128GCM_decrypt(sk, ct, 32, plaintext, iv, 12, iv, 12, tag)) {
		return IPAS_FAILURE;
	}
	// nonce(16)||K(16)
	uint8_t *nonce = plaintext + 0;
	uint8_t *key = plaintext + 16;

	// seal K
	*size = sgx_calc_sealed_data_size(0, 16);
	if (0xffffffff == *size) {
		return IPAS_FAILURE;
	}
	if (*size > 640) {
		return IPAS_CAPACITY;
	}
#ifdef IPAS_STRICT_MR
	sgx_status_t ss = sgx_seal_data_ex(SGX_KEYPOLICY_MRENCLAVE,
			(sgx_attributes_t){.flags=0xFF0000000000000B, .xfrm=0xF0000000},
			0xF0000000,
			0, NULL, 16, key, *size, data);
#else
	sgx_status_t ss = sgx_seal_data(0, NULL, 16, key, *size, data);
#endif
	if (ss) {
		LOG("Error: sealing data=%#x\n", ss);
		return IPAS_FAILURE;
	}
	LOG("Sealed client data\n");

	// compute MAC over nonce||data but no need to send nonce, A already has it
	sgx_cmac_128bit_key_t *cmac_key = ipas_ma_get_key(sid, 1);
	if (cmac_key == NULL) {
		return IPAS_NO_KEY;
	}
	// if (sgx_rijndael128_cmac_msg(cmac_key, data, *size, mac)) {
	// 	return IPAS_FAILURE;
	// }
	sgx_cmac_state_handle_t cmac_handle = {0};
	if (sgx_cmac128_init(cmac_key, &cmac_handle)) {
		return IPAS_FAILURE;
	}
	if (sgx_cmac128_update(nonce, 16, cmac_handle)
			|| sgx_cmac128_update(data, *size, cmac_handle)
			|| sgx_cmac128_final(cmac_handle, mac)) {
		sgx_cmac128_close(cmac_handle);
		return IPAS_FAILURE;
	}
	sgx_cmac128_close(cmac_handle);

	return IPAS_SUCCESS;
}

/**
** Verifies MAC over nonce||data; concludes IPAS-S protocol.
**
** Returns zero on success, non-zero otherwise.
** Status: IPAS_SUCCESS         all good
**         IPAS_NO_KEY          required key, SK or MK, not available
**         IPAS_FAILURE         internal error
**         IPAS_BAD_TAG         response tag is wrong
**         IPAS_CAPACITY        internal sealed key buffer not large enough
**/
ipas_status ipas_s_process_m2(
		uint32_t sid,                           // in
		const void *data, uint32_t size,        // in
		const sgx_cmac_128bit_tag_t *mac        // in
)
{
	sgx_cmac_128bit_key_t *mk = ipas_ma_get_key(sid, 1);
	if (mk == NULL) {
		return IPAS_NO_KEY;
	}

	char tb[512] = {0};
	printf("$mk = {%s}\n", b2s(tb, sizeof(tb), mk, sizeof(*mk), "", ":", ""));

	sgx_cmac_state_handle_t cmac_handle = {0};
	sgx_cmac_128bit_tag_t temp_mac = {0};
	if (sgx_cmac128_init(mk, &cmac_handle)) {
		return IPAS_FAILURE;
	}
	if (sgx_cmac128_update(SEALING_NONCE, 16, cmac_handle)
			|| sgx_cmac128_update(data, size, cmac_handle)
			|| sgx_cmac128_final(cmac_handle, &temp_mac)) {
		sgx_cmac128_close(cmac_handle);
		return IPAS_FAILURE;
	}
	sgx_cmac128_close(cmac_handle);

	printf("Received MAC = {%s}\n", b2s(tb, sizeof(tb), mac, sizeof(sgx_cmac_128bit_tag_t), NULL, ":", NULL));

	printf("Computed MAC = {%s}\n", b2s(tb, sizeof(tb), &temp_mac, sizeof(sgx_cmac_128bit_tag_t), NULL, ":", NULL));

	if (memcmp(mac, &temp_mac, 16)) {
		return IPAS_BAD_TAG;
	}

	// is_key_set = true;

	if (size > sizeof(sealed_key)) {
		return IPAS_CAPACITY;
	}
	memset(sealed_key, 0, sizeof(sealed_key));
	memcpy(sealed_key, data, size);

	is_s_ok = true;

	return IPAS_SUCCESS;
}

const void *ipas_s_get_key()
{
	if (!is_s_ok) {
		return NULL;
	}

	return csk;
}

// Computes MAC over nonce||data using MK, in A, to send B
ipas_status ipas_u_preprocess_m1(
	uint8_t nonce[16],          // out
	sgx_cmac_128bit_tag_t *mac, // out: computed over nonce plus sealed data
	uint32_t sid,               // in
	void *data,                 // in: sealed data containing K
	uint32_t size               // in: sealed data size
)
{
	if (sgx_read_rand(nonce, 16)) {
		return IPAS_FAILURE;
	}

	sgx_cmac_128bit_key_t *mk = ipas_ma_get_key(sid, 1);
	if (mk == NULL) {
		return IPAS_NO_KEY;
	}
	sgx_cmac_state_handle_t cmac_handle = {0};
	if (sgx_cmac128_init(mk, &cmac_handle)) {
		return IPAS_FAILURE;
	}
	if (sgx_cmac128_update(nonce, 16, cmac_handle)
			|| sgx_cmac128_update(data, size, cmac_handle)
			|| sgx_cmac128_final(cmac_handle, mac)) {
		sgx_cmac128_close(cmac_handle);
		return IPAS_FAILURE;
	}
	sgx_cmac128_close(cmac_handle);

	// save for verification in ipas_u_process_m2
	memcpy(UNSEALING_NONCE, nonce, 16);

	return IPAS_SUCCESS;
}

// Verifies MAC over nonce||data; unseals data obtaining K; encrypts for A
ipas_status ipas_u_process_m1(
	uint8_t iv[12],             // out
	uint8_t ct[16],             // out
	uint8_t tag[16],            // out

	uint32_t sid,               // in
	uint8_t nonce[16],          // in
	const void *data,           // in: sealed data containing K
	uint32_t size,              // in: sealed data size
	sgx_cmac_128bit_tag_t *mac  // in: computed over nonce plus sealed data
)
{
	// verify MAC
	sgx_cmac_128bit_key_t *mk = ipas_ma_get_key(sid, 1);
	if (mk == NULL) {
		return IPAS_NO_KEY;
	}
	sgx_cmac_state_handle_t cmac_handle = {0};
	sgx_cmac_128bit_tag_t temp_mac;
	if (sgx_cmac128_init(mk, &cmac_handle)) {
		return IPAS_FAILURE;
	}
	if (sgx_cmac128_update(nonce, 16, cmac_handle)
			|| sgx_cmac128_update(data, size, cmac_handle)
			|| sgx_cmac128_final(cmac_handle, &temp_mac)) {
		sgx_cmac128_close(cmac_handle);
		return IPAS_FAILURE;
	}
	sgx_cmac128_close(cmac_handle);
	if (memcmp(mac, temp_mac, 16)) {
		return IPAS_BAD_TAG;
	}

	// unseal K
	// We don't compute required buffer length because this is already known
	uint8_t plaintext[16] = {0};
	uint32_t length = 16;
	sgx_status_t ss = sgx_unseal_data(data, NULL, 0, plaintext, &length);
	if (ss) {
		LOG("Error: sgx_unseal_data=%#x\n", ss);
		return IPAS_FAILURE;
	}
	LOG("Unsealed client data\n");
	// First 16 bytes of plaintext are for return ANonce, second 16 bytes for K.
	// memcpy(plaintext, nonce, 16);

	// encrypt K
	sgx_aes_gcm_128bit_key_t *sk = ipas_ma_get_key(sid, 2);
	if (sk == NULL) {
		return IPAS_NO_KEY;
	}
	if (sgx_read_rand(iv, 12)) {
		return IPAS_FAILURE;
	}
	uint8_t ad[16+12] = {0}; // additional data is nonce||IV
	memcpy(ad, nonce, 16);
	memcpy(&ad[16], iv, 12);
	if (sgx_rijndael128GCM_encrypt(sk, plaintext, sizeof(plaintext), ct, iv, 12, ad, sizeof(ad), (sgx_aes_gcm_128bit_tag_t *) tag)) {
		return IPAS_FAILURE;
	}

	return IPAS_SUCCESS;
}

// Decrypts data from peer obtaining K.
ipas_status ipas_u_process_m2(
	uint32_t sid,               // in
	uint8_t iv[12],             // in
	uint8_t ct[16],             // in
	uint8_t tag[16]             // in
)
{
	sgx_aes_gcm_128bit_key_t *sk = ipas_ma_get_key(sid, 2);
	if (sk == NULL) {
		return IPAS_NO_KEY;
	}
	uint8_t plaintext[16] = {0}; // this is K
	uint8_t ad[16+12] = {0}; // additional data is nonce||IV
	memcpy(ad, UNSEALING_NONCE, 16);
	memcpy(&ad[16], iv, 12);
	if (sgx_rijndael128GCM_decrypt(sk, ct, 16, plaintext, iv, 12, ad, sizeof(ad), (sgx_aes_gcm_128bit_tag_t *) tag)) {
		return IPAS_FAILURE;
	}
	// nonce sent in m1 is part of AD, no need to receive it encrypted

	// save client secret key for later
	memcpy(csk, plaintext, 16);
	is_u_ok = true;

	return IPAS_SUCCESS;
}

const void *ipas_u_get_key()
{
	if (!is_u_ok) {
		return NULL;
	}

	return csk;
}

/**
** Seals data using AEAD.
**
** Returns zero on success, non-zero otherwise.
** Status: IPAS_SUCCESS         all good
**         IPAS_NO_KEY          required client encryption key, K, not available
**         IPAS_INVALID         bad argument: AD
**         IPAS_FAILURE         internal error
**/
int ipas_seal_data(const uint32_t pt_len, const uint8_t *pt, const uint32_t ad_len, const uint8_t *ad, const uint32_t sd_len, struct ipas_sealed_data *sd)
{
	const void *key = ipas_s_get_key();
	if (!key) {
		return IPAS_NO_KEY;
	}

	if (ad == NULL && ad_len > 0) {
		return IPAS_INVALID;
	}

	if (sgx_read_rand(sd->key_id, sizeof(sd->key_id))) {
		return IPAS_FAILURE;
	}
	memcpy(sd->sealed_key, sealed_key, 640);

	sd->ad_size = ad_len;
	sd->pt_size = pt_len;
	memset(sd->mac, 0, sizeof(sd->mac));
	memcpy(sd->payload, ad, ad_len); // client AD

	// payload = ad||ct

	uint8_t mac[SGX_AESGCM_MAC_SIZE] = {0};

	const uint8_t iv[12] = {0};
	sgx_status_t ss = sgx_rijndael128GCM_encrypt(key, pt, pt_len, sd->payload + ad_len, &iv, 12, sd, SD_FIRST_BLOCK + ad_len, mac);
	if (ss) {
		return IPAS_FAILURE;
	}

	memcpy(sd->mac, &mac, sizeof(mac));

	return 0;
}
// Calcular sobre toda a estrutura, com MAC a zeros, e sobre primeira parte de payload que corresponde ao AD (copiado previamente).

// TODO: Afinar lib sealing por causa da manha do MAC, acho que não vale a pena porque complica o unsealing. Melhor não considerar MAC no SD_FIRST_BLOCK e ter de calcular buffer temporário.

int ipas_unseal_data(uint32_t *pt_len, uint8_t *pt, uint32_t *ad_len, uint8_t *ad, const uint32_t sd_len, const struct ipas_sealed_data *sd)
{
	const void *key = ipas_u_get_key();
	if (!key) {
		return IPAS_NO_KEY;
	}

	uint8_t mac[SGX_AESGCM_MAC_SIZE] = {0};
	memcpy(&mac, sd->mac, sizeof(mac));
	memset(sd->mac, 0, sizeof(sd->mac));

	const uint8_t iv[12] = {0};
	sgx_status_t ss = sgx_rijndael128GCM_decrypt(key, sd->payload + sd->ad_size, sd->pt_size, pt, &iv, 12, sd, SD_FIRST_BLOCK + sd->ad_size, mac);
	if (ss) {
		return IPAS_FAILURE;
	}

	*pt_len = sd->pt_size;
	*ad_len = sd->ad_size;
	memcpy(ad, sd->payload, sd->ad_size);

	return 0;
}

uint32_t ipas_calc_sealed_data_size(const uint32_t pt_len, const uint32_t ad_len)
{
	if (ad_len > UINT32_MAX - pt_len) {
		return UINT32_MAX;
	}

	if (ad_len + pt_len > UINT32_MAX - sizeof(struct ipas_sealed_data)) {
		return UINT32_MAX;
	}

	return ad_len + pt_len + sizeof(struct ipas_sealed_data);
}
