#include <assert.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

// NULL on failure
// on success: caller is responsible for invoking X509_free(x)
static X509 *cert_from_buf(const void *data, size_t size)
{
	// write data to memory buffer
	BIO *mem = BIO_new(BIO_s_mem());
	if (!mem) {
		return NULL;
	}
	if (size > INT_MAX) {
		BIO_free(mem);
		return NULL;
	}
	for (int written = 1, remaining = size; written > 0 && remaining > 0; remaining -= written) {
		const void *chunk = (uint8_t *) data + (size - remaining);
		written = BIO_write(mem, chunk, remaining);
	}

	X509 *cert = PEM_read_bio_X509_AUX(mem, NULL, NULL, NULL);
	BIO_free(mem);

	return cert;
}

int verify_cert(const void *cacert, size_t n1, const void *cert, size_t n2)
{
	// read CA certificate and target certificate into X509 OpenSSL structures
	X509 *root = cert_from_buf(cacert, n1);
	if (!root) {
		return 1;
	}
	X509 *leaf = cert_from_buf(cert, n2);
	if (!leaf) {
		X509_free(root);
		return 2;
	}

	X509_STORE_CTX *ctx = X509_STORE_CTX_new();
	if (!ctx) {
		X509_free(root);
		X509_free(leaf);
		return 3;
	}

	// setup trusted certificate
	X509_STORE *store = X509_STORE_new();
	if (!store) {
		X509_free(root);
		X509_free(leaf);
		X509_STORE_CTX_free(ctx);
		return 4;
	}
	// flags adicionais...
	if (1 != X509_STORE_set_flags(store,
			X509_V_FLAG_X509_STRICT |
			X509_V_FLAG_POLICY_CHECK |
			X509_V_FLAG_CHECK_SS_SIGNATURE)) {
		X509_free(root);
		X509_free(leaf);
		X509_STORE_CTX_free(ctx);
		X509_STORE_free(store);
		return 5;
	}
	if (1 != X509_STORE_add_cert(store, root)) {
		X509_free(root);
		X509_free(leaf);
		X509_STORE_CTX_free(ctx);
		X509_STORE_free(store);
		return 6;
	}

	if (1 != X509_STORE_CTX_init(ctx, store, leaf, NULL)) {
		X509_free(root);
		X509_free(leaf);
		X509_STORE_CTX_free(ctx);
		X509_STORE_free(store);
		return 7;
	}

	if (1 != X509_verify_cert(ctx)) {
		X509_free(root);
		X509_free(leaf);
		X509_STORE_CTX_free(ctx);
		X509_STORE_free(store);
		return 8;
	}

	// TODO null is okay below, refactor

	X509_free(root);
	X509_free(leaf);
	X509_STORE_CTX_free(ctx);
	X509_STORE_free(store);

	return 0;
}

// returns zero if signature verified correctly, non-zero otherwise (11 bad sig)
int verify_sig(const void *cert, size_t certlen,
		const void *sig, size_t siglen, const void *data, size_t size)
{
	assert(cert);
	assert(sig);
	assert(data);

	X509 *certificate = cert_from_buf(cert, certlen);
	if (!certificate) {
		return 1;
	}
	EVP_PKEY *key = X509_get0_pubkey(certificate);
	if (!key) {
		X509_free(certificate);
		return 1;
	}

	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	if (!ctx) {
		X509_free(certificate);
		return 1;
	}

	if (1 != EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, key)) {
		X509_free(certificate);
		EVP_MD_CTX_free(ctx);
		return 1;
	}

	int ret = EVP_DigestVerify(ctx, sig, siglen, data, size);
	X509_free(certificate);
	EVP_MD_CTX_free(ctx);
	if (0 == ret) {
		return 11;
	}
	if (1 != ret) {
		return 1;
	}

	return 0;
}
