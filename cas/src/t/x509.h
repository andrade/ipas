#pragma once

#include <stddef.h>

// #include <openssl/x509.h>
//
// X509 *cert_from_buf(const void *data, size_t size);

int verify_cert(const void *cacert, size_t n1, const void *cert, size_t n2);

int verify_sig(const void *cert, size_t certlen,
		const void *sig, size_t siglen, const void *data, size_t size);
