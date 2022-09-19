#ifndef CAS_SERIALIZATION_H
#define CAS_SERIALIZATION_H

#include <stddef.h>
#include <stdint.h>

/**
** Serializes CSS message m1.
**
** [o]  output      serialized data
** [i]  output_cap  max capacity of output buffer
** [o]  output_len  length of serialized data in output buffer
**
** [i]  enclave     the enclave (enclave.signed.so) read from disk
** [i]  e_size      the enclave size in bytes
** [i]  untrusted   the untrusted code (untrusted.so) read from disk
** [i]  u_size      the untrusted DSO size in bytes
** [i]  aeg         the Extended Group ID of A
** [i]  aeg_size
** [i]  ag          the Group ID of A
** [i]  ag_size
** [i]  apub        the public key of A
** [i]  apub_size   the size of the public key of A in bytes
**
** Returns zero on success, or non-zero on error.
**/
int encode_m1(uint8_t *output, size_t output_cap, uint32_t *output_len,
		const uint8_t *enclave, size_t e_size,
		const uint8_t *untrusted, size_t u_size,
		const uint8_t *aeg, size_t aeg_size,
		const uint8_t *ag, size_t ag_size,
		const uint8_t *apub, size_t apub_size);

int decode_m2(struct ipas_ma_m2 *m2, const uint8_t *ibuf, size_t ilen);

int encode_m3(uint8_t *output, size_t output_cap, uint32_t *output_len,
		const uint8_t *quote, size_t size);

/**
** Deserializes message 4 from a buffer `ibuf`.
** Returns zero on success.
**/
int decode_m4(struct ipas_ma_m4 *m4, const uint8_t *ibuf, size_t ilen);

int encode_m11(uint8_t *obuf, size_t ocap, uint32_t *olen,
		const struct ipas_s_m1 *m1);

int decode_m12(struct ipas_s_m2 *m2, const uint8_t *ibuf, size_t ilen);

int encode_m21(uint8_t *obuf, size_t ocap, uint32_t *olen,
		const struct ipas_u_m1 *m1);

int decode_m22(struct ipas_u_m2 *m2, const uint8_t *ibuf, size_t ilen);

#endif
