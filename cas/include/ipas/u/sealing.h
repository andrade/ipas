#pragma once

#include <stdint.h>

#include <sgx_urts.h>

// Message 1
// sent from A to B
struct ipas_s_m1 {
	uint8_t iv[12];             // initialization vector for encrypted data
	uint8_t ct[32];             // encrypted data
	uint8_t tag[16];
};

// Message 2
// sent from B to A
struct ipas_s_m2 {
	uint8_t nonce[16];          // nonce for freshness // TODO Remove this!

	uint8_t data[640];          // returned by B, to append to encrypted data
	uint32_t size;              // size of data

	uint8_t mac[16];            // MAC over message: nonce||data
};

// Message 1
// sent from A to B
struct ipas_u_m1 {
	uint8_t nonce[16];          // nonce for freshness of message round trip

	uint8_t data[640];          // sealed data
	uint32_t size;              // size of sealed data

	uint8_t mac[16];            // MAC over message: nonce||data
};

// Message 2
// sent from B to A
struct ipas_u_m2 {
	uint8_t iv[12];             // initialization vector for encrypted data
	uint8_t ct[16];             // encrypted data
	uint8_t tag[16];            // encrypted data tag
};

int ipas_s_get_m1(sgx_enclave_id_t eid, uint32_t sid, struct ipas_s_m1 *m1);

int ipas_s_get_m2(sgx_enclave_id_t eid, const void *uh, uint32_t sid, struct ipas_s_m1 *m1, struct ipas_s_m2 *m2);

int ipas_s_conclude(sgx_enclave_id_t eid, uint32_t sid, struct ipas_s_m2 *m2);

int ipas_u_get_m1(sgx_enclave_id_t eid, uint32_t sid, struct ipas_u_m1 *m1, void *data, size_t size);

int ipas_u_get_m2(sgx_enclave_id_t eid, const void *uh, uint32_t sid, struct ipas_u_m1 *m1, struct ipas_u_m2 *m2);

int ipas_u_conclude(sgx_enclave_id_t eid, uint32_t sid, struct ipas_u_m2 *m2);
