#pragma once

// TODO Use key request (and inner key_id) when integrating with SDK.
//      atm just using it as IV for AES-GCM.
// AD' = First 692+AD bytes of this struct (with zeroed MAC)
struct ipas_sealed_data {
	//sgx_key_request_t key_request;      // For obtaining the sealing key
	uint8_t key_id[SGX_KEYID_SIZE];     // 000 Key wear-out protection
	uint8_t sealed_key[640];            // 032 S2

	uint32_t ad_size;                   // 672 Size of the additional data
	uint32_t pt_size;                   // 676 Size of the encrypted data
	uint8_t mac[SGX_AESGCM_MAC_SIZE];   // 680
	uint8_t payload[];                  // 692 ad||ct
};

int ipas_seal_data(const uint32_t pt_len, const uint8_t *pt,
		const uint32_t ad_len, const uint8_t *ad,
		const uint32_t sd_len, struct ipas_sealed_data *sd);

int ipas_unseal_data(uint32_t *pt_len, uint8_t *pt,
		uint32_t *ad_len, uint8_t *ad,
		const uint32_t sd_len, const struct ipas_sealed_data *sd);

// Returns 0xFFFFFFFF on error.
uint32_t ipas_calc_sealed_data_size(const uint32_t pt_len, const uint32_t ad_len);

/**
** Gets client secret key generated during IPAS-S.
**
** Returns the 16-byte key on success, NULL otherwise.
**/
const void *ipas_s_get_key();

/**
** Gets client secret key generated during IPAS-U.
**
** Returns the 16-byte key on success, NULL otherwise.
**/
const void *ipas_u_get_key();
