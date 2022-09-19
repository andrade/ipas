#ifndef RAP_SERIALIZATION_H
#define RAP_SERIALIZATION_H

#include <stddef.h>
#include <stdint.h>

#include <sgx_quote.h>

#include "ra_types.h"

// TEMP
char *sgx_epid_group_id_to_str(char *dest, size_t cap, sgx_epid_group_id_t *gid);


/**
** Serializes a SigRL request.
**
** [o]  a           serialized data
** [i]  cap         max capacity of output buffer
** [o]  n           length of serialized data in output buffer
**
** [i]  data        structure holding request fields; it is not modified
**
** Returns zero on success, or non-zero on error.
**/
int rap_encode_request_sigrl(uint8_t *a, size_t cap, uint32_t *n, struct ra_sigrl *data);

/**
** Deserializes a SigRL response.
**
** [o]  data        holds response fields; only response fields are modified
**                  See `struct rap_report` reply fields for details.
**
** [i]  a           serialized data
** [i]  n           length of serialized data in input buffer
**
** Returns zero on success, or non-zero on error.
**/
int rap_decode_reply_sigrl(struct ra_sigrl *data, const uint8_t *a, size_t n);

/**
** Serializes an attestation request.
**
** [o]  output      serialized data
** [i]  output_cap  max capacity of output buffer
** [o]  output_len  length of serialized data in output buffer
**
** [i]  report      structure holding request fields; it is not modified
**
** Returns zero on success, or non-zero on error.
**/
int rap_encode_request_report(uint8_t *output, size_t output_cap, uint32_t *output_len, const struct ra_report *report);

/**
** Deserializes an attestation response.
**
** [o]  report      holds response fields; only response fields are modified
**                  See `struct rap_report` reply fields for details.
**
** [i]  input       serialized data
** [i]  input_len   length of serialized data in input buffer
**
** Returns zero on success, or non-zero on error.
**/
int rap_decode_reply_report(struct ra_report *report, const uint8_t *input, size_t input_len);

#endif
