#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <dlfcn.h>
#include <inttypes.h>
#include <unistd.h>

#include <sgx_error.h>

#include "ipas/errors.h"
#include "ipas/u/sealing.h"

#include "sealing_u.h"
#include "debug.h"

int ipas_s_get_m1(sgx_enclave_id_t eid, uint32_t sid, struct ipas_s_m1 *m1)
{
	ipas_status is;
	sgx_status_t ss = ipas_s_get_sealing_key(eid, &is, m1->iv, m1->ct, m1->tag, sid);
	if (ss || is) {
		LOG("ipas_s_get_sealing_key: failure (ss=%"PRIx32", is=%"PRIx32")\n", ss, is);
		return 1;
	}
	LOG("ipas_s_get_sealing_key: success\n");

	return 0;
}

int ipas_s_get_m2(sgx_enclave_id_t eid, const void *uh, uint32_t sid, struct ipas_s_m1 *m1, struct ipas_s_m2 *m2)
{
	sgx_status_t (*f_ipas_s_process_m1)(sgx_enclave_id_t, ipas_status *, void *, uint32_t *, sgx_cmac_128bit_tag_t *, uint32_t, uint8_t [], uint8_t [], sgx_aes_gcm_128bit_tag_t *);
	*(void **) (&f_ipas_s_process_m1) = dlsym(uh, "ipas_s_process_m1");
	if (!f_ipas_s_process_m1) {
		LOG("Error: f_ipas_s_process_m1 (%s)\n", dlerror());
		return 1;
	}

	ipas_status is;
	sgx_status_t ss = f_ipas_s_process_m1(eid, &is,
			m2->data, &m2->size, (sgx_cmac_128bit_tag_t *) m2->mac,
			sid, m1->iv, m1->ct, (sgx_aes_gcm_128bit_tag_t *) &m1->tag);
	LOG("sealed data size=%"PRIu32"\n", m2->size);
	if (ss || is) {
		LOG("ipas_s_process_m1: failure (ss=%"PRIx32", is=%"PRIu32")\n", ss, is);
		return 1;
	}
	LOG("ipas_s_process_m1: success\n");

	return 0;
}

int ipas_s_conclude(sgx_enclave_id_t eid, uint32_t sid, struct ipas_s_m2 *m2)
{
	ipas_status is;
	sgx_status_t ss;

	ss = ipas_s_process_m2(eid, &is,
			sid, m2->data, m2->size, (sgx_cmac_128bit_tag_t *) m2->mac);
	if (ss || is) {
		LOG("ipas_s_process_m2: failure (ss=%"PRIx32", is=%"PRIu32")\n", ss, is);
		return 1;
	}
	LOG("ipas_s_process_m2: success\n");

	return 0;
}

int ipas_u_get_m1(sgx_enclave_id_t eid, uint32_t sid, struct ipas_u_m1 *m1, void *data, size_t size)
{
	ipas_status is;
	sgx_status_t ss = ipas_u_preprocess_m1(eid, &is,
			m1->nonce, (sgx_cmac_128bit_tag_t *) m1->mac,
			sid, data, size);
	if (ss || is) {
		LOG("ipas_u_preprocess_m1: failure (ss=%"PRIx32", is=%"PRIu32")\n", ss, is);
		return 1;
	}
	LOG("ipas_u_preprocess_m1: success\n");

	memcpy(m1->data, data, size);
	m1->size = size;

	return 0;
}

int ipas_u_get_m2(sgx_enclave_id_t eid, const void *uh, uint32_t sid, struct ipas_u_m1 *m1, struct ipas_u_m2 *m2)
{
	sgx_status_t (*f_ipas_u_process_m1)(sgx_enclave_id_t, ipas_status *, uint8_t *, uint8_t *, uint8_t *, uint32_t, uint8_t *, const void *, uint32_t, sgx_cmac_128bit_tag_t *);
	*(void **) (&f_ipas_u_process_m1) = dlsym(uh, "ipas_u_process_m1");
	if (!f_ipas_u_process_m1) {
		LOG("Error: f_ipas_u_process_m1 (%s)\n", dlerror());
		return 1;
	}

	ipas_status is;
	sgx_status_t ss = f_ipas_u_process_m1(eid, &is,
			m2->iv, m2->ct, m2->tag,
			sid, m1->nonce, m1->data, m1->size, (sgx_cmac_128bit_tag_t *) m1->mac);
	if (ss || is) {
		LOG("ipas_u_process_m1: failure (ss=%"PRIx32", is=%"PRIu32")\n", ss, is);
		return 1;
	}
	LOG("ipas_u_process_m1: success\n");

	return 0;
}

int ipas_u_conclude(sgx_enclave_id_t eid, uint32_t sid, struct ipas_u_m2 *m2)
{
	ipas_status is;
	sgx_status_t ss;

	ss = ipas_u_process_m2(eid, &is, sid, m2->iv, m2->ct, m2->tag);
	if (ss || is) {
		LOG("Process m2: failure (ss=%"PRIx32", is=%"PRIu32")\n", ss, is);
		return 1;
	}
	LOG("Process m2: success\n");

	return 0;
}
