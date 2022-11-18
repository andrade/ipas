#include <stdint.h>

#include <sgx_trts.h>
#if defined (SGX_SEALING)
#include <sgx_tseal.h>
#endif

#include "enclave_t.h"

/**
** Seal some data.
**
** [o]  data:           sealed data
** [i]  capacity:       size of the sealed data destination buffer
** [o]  size:           actual size of sealed data
** [i]  toseal:         the data to seal
** [i]  toseal_size:    the size of the data to seal
**
** Returns zero on success, non-zero otherwise.
**/
int ecall_seal_data(void *data, uint32_t capacity, uint32_t *size,
		const void *toseal, uint32_t toseal_size)
{
#if !defined (SGX_SEALING)
	uint32_t sd_len = ipas_calc_sealed_data_size(toseal_size, 0);
	if (sd_len == UINT32_MAX) {
		return 1;
	}

	struct ipas_sealed_data *sd = malloc(sd_len);
	if (!sd) {
		return 2;
	}
	if (ipas_seal_data(toseal_size, toseal, 0, NULL, sd_len, sd)) {
		return 3;
	}

	if (sd_len > capacity) {
		return 4;
	}

	memcpy(data, sd, sd_len);
	*size = sd_len;

	free(sd);
#else
	uint32_t sd_len = sgx_calc_sealed_data_size(0, toseal_size);
	if (sd_len == 0xFFFFFFFF) {
		return 1;
	}

	sgx_sealed_data_t *sd = malloc(sd_len);
	if (!sd) {
		return 2;
	}
	if (sgx_seal_data(0, NULL, toseal_size, toseal, sd_len, sd)) {
		return 3;
	}

	if (sd_len > capacity) {
		return 4;
	}

	memcpy(data, sd, sd_len);
	*size = sd_len;

	free(sd);
#endif

	return 0;
}

/**
** Unseal some data.
**
** [o]  pt:             the unsealed data
** [i]  pt_cap:         the capacity of the unsealed data destination buffer
** [o]  pt_len:         the length of the unsealed data
** [i]  data:           the sealed data
** [i]  size:           the size of the sealed data
**
** Returns zero on success, non-zero otherwise.
**/
int ecall_unseal_data(void *pt, uint32_t pt_cap, uint32_t *pt_len,
		const void *data, uint32_t size)
{
	// uint32_t pt_len = 0;
	uint32_t ad_len = 0;
	// uint8_t pt[32] = {0};
	uint8_t ad[32] = {0};

#if !defined (SGX_SEALING)
	// return ipas_unseal_data(&pt_len, pt, &ad_len, ad, size, data);
	if (ipas_unseal_data(pt_len, pt, &ad_len, ad, size, data)) {
		return 3;
	}
#else
	*pt_len = size; // function uses this variable as in, out
	if (sgx_unseal_data(data, ad, &ad_len, pt, pt_len)) {
		return 3;
	}
#endif

	return 0;
}
