#include <stdint.h>

#include <sgx_trts.h>

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

	// return ipas_unseal_data(&pt_len, pt, &ad_len, ad, size, data);
	if (ipas_unseal_data(pt_len, pt, &ad_len, ad, size, data)) {
		return 3;
	}

	return 0;
}
