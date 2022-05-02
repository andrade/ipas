#pragma once

#include <stdarg.h>
#include <stdint.h>

#include <sgx_urts.h>
#include <sgx_quote.h>
#include <sgx_tcrypto.h>

#include "ipas/errors.h"

#define IPAS_SRL_RSP_B_SIZE     4096    // SRL response body

enum role {
	ROLE_INITIATOR              = 1,
	ROLE_RESPONDER              = 2,
};

struct ipas_attest_st {
	uint32_t sid;
	sgx_enclave_id_t eid;
	void *udso; // dlopen handle for the untrusted DSO
	enum role role;

	sgx_target_info_t qe_target_info;

	uint32_t egid_a;
	uint32_t egid_b;
	sgx_epid_group_id_t gid_a;
	sgx_epid_group_id_t gid_b;
	sgx_ec256_public_t pub_a;
	sgx_ec256_public_t pub_b;

	uint32_t length_a;
	uint32_t length_b;
	uint8_t srl_a[IPAS_SRL_RSP_B_SIZE];
	uint8_t srl_b[IPAS_SRL_RSP_B_SIZE];

	// sgx_ec256_public_t pub_a;
	// sgx_ec256_public_t pub_b;
	// acho que não preciso guardar cá fora estes dois! Se for preciso acrescenta-se!
};

// Message 1
// sent from A to B
struct ipas_ma_m1 {
	uint32_t egid_a;                    // AExGroup
	sgx_epid_group_id_t gid_a;          // AGroup
	sgx_ec256_public_t pub_a;           // APublic
};

// sent from B to AS
struct ipas_ma_p1 {
	sgx_epid_group_id_t gid_a;          // AGroup
	sgx_epid_group_id_t gid_b;          // BGroup
};

// sent from AS to B
struct ipas_ma_p2 {
	uint32_t status_a;          // HTTP status (e.g. "200" for OK)
	uint32_t status_b;
	uint32_t length_a;          // length of SigRL (only when status 200 OK)
	uint32_t length_b;
	uint8_t srl_a[IPAS_SRL_RSP_B_SIZE]; // ASigRL
	uint8_t srl_b[IPAS_SRL_RSP_B_SIZE]; // BSigRL

	// Single flexible array member? (usando lengths para posições)
	// Mas arrays estáticos mais fácil descartar.
	// uint8_t srl[];              // ASigRL||BSigRL
};

// Message 2
// sent from B to A
struct ipas_ma_m2 {
	uint32_t egid_b;                    // BExGroup
	sgx_ec256_public_t pub_b;           // BPublic

	uint32_t status_a;          // HTTP status (e.g. "200" for OK)
	uint32_t length_a;          // length of SigRL (only when status 200 OK)
	uint8_t srl_a[IPAS_SRL_RSP_B_SIZE]; // ASigRL
};

// Message 3
// sent from A to B
struct ipas_ma_m3 {
	uint32_t size_a;                    // size of AQuote
	uint8_t quote_a [4096];             // AQuote
};

// sent from B to AS
// Storing quote in fixed-size array to avoid dynamic allocation
// Must check during runtime whether quote_size exceeds `sizeof(quote_a)`
struct ipas_ma_p3 {
	uint32_t size_a;                    // size of AQuote
	uint8_t quote_a [4096];             // AQuote
	uint32_t size_b;                    // size of BQuote
	uint8_t quote_b[4096];              // BQuote
};
// struct ipas_ma_p3 {
// 	uint32_t size_a;                    // size of AQuote
// 	sgx_quote_t *quote_a;               // AQuote
// 	uint32_t size_b;                    // size of BQuote
// 	sgx_quote_t *quote_b;               // BQuote
// };

// sent from AS to B
struct ipas_ma_p4 {
	uint32_t status_a;
	char rid_a[64];
	char sig_a[1024];
	char cc_a[4096];
	char report_a[4096];                // AReport

	uint32_t status_b;
	char rid_b[64];
	char sig_b[1024];
	char cc_b[4096];
	char report_b[4096];                // BReport

	// char eqs_a[64];
	// char eqs_b[64];
};
// fields as returned by IAS

// Message 4
// sent from B to A
struct ipas_ma_m4 {
	uint32_t status_a;
	char rid_a[64];
	char sig_a[1024];
	char cc_a[4096];
	char report_a[4096];                // AReport

	uint32_t status_b;
	char rid_b[64];
	char sig_b[1024];
	char cc_b[4096];
	char report_b[4096];                // BReport

	// char eqs_a[64];
	// char eqs_b[64];

	uint8_t data[64];           // em vez de status, mais flexível
	// uint32_t size;  // sem size porque passo *sempre* os 64 bytes
	uint8_t mac[16];            // MAC over message
};
// struct ipas_ma_m4 {
// 	sgx_ec256_public_t pub_b[32];       // BPublic
// 	uint8_t nonce_b[32];                // BNonce
// 	uint32_t size_b;                    // size of BQuote
// 	sgx_quote_t quote_b;                // BQuote
// };


// alocar recursos para IPA, tentar ter tudo estático
int ipas_ma_init(struct ipas_attest_st *ia, uint32_t sid, sgx_enclave_id_t eid, void *uh, enum role role);

// release recursos, mas apenas se for preciso (tiver coisas dinâmicas, ou open)
int ipas_ma_free(struct ipas_attest_st *ia);

// se conseguir utilizar estruturas estáticas que não precisem free!



/**
** Get message 1 in A to send to peer.
**
**     m1 = {AExGroup, AGroup, APublic}
**
** Returns zero on success, non-zero otherwise.
**/
int ipas_ma_get_m1(struct ipas_attest_st *ia, struct ipas_ma_m1 *m1);

/**
** Get proxy message 1 in B to send to RAP.
**
**     p1 = {AGroup / BGroup}
**
** Returns zero on success, non-zero otherwise.
**/
int ipas_ma_get_p1(struct ipas_attest_st *ia, struct ipas_ma_m1 *m1, struct ipas_ma_p1 *p1);

/**
** Get message 2 in B to send to peer.
** Receives and processes proxy message 2 from RAP.
**
**     m2 = {BExGroup, BPublic, ASigRL}
**
** Returns zero on success, non-zero otherwise.
**/
int ipas_ma_get_m2(struct ipas_attest_st *ia, struct ipas_ma_p2 *p2, struct ipas_ma_m2 *m2);

/**
** Get message 3 in A to send to peer. Receives and processes message 2.
**
**     m3 = {AQuote}
**
** Returns zero on success, non-zero otherwise.
**/
int ipas_ma_get_m3(struct ipas_attest_st *ia, struct ipas_ma_m2 *m2, struct ipas_ma_m3 *m3);

/**
** Get proxy message 3 in B to send to RAP.
**
**     p3 = {AReport / BReport}
**
** Returns zero on success, non-zero otherwise.
**/
int ipas_ma_get_p3(struct ipas_attest_st *ia, struct ipas_ma_m3 *m3, struct ipas_ma_p3 *p3);

/**
** Get message 4 in B to send to peer.
** Receives and processes proxy message 4 from RAP.
**
**     m4 = {AReport, BReport, data, MAC}
**
** Returns zero on success, non-zero otherwise.
**/
int ipas_ma_get_m4(struct ipas_attest_st *ia, struct ipas_ma_p4 *p4, struct ipas_ma_m4 *m4);

/**
** Concludes MA protocol.
**
** Returns zero on success, non-zero otherwise.
**/
int ipas_ma_conclude(struct ipas_attest_st *ia, struct ipas_ma_m4 *m4);



char *ipas_ma_m2_to_string(char *dest, size_t cap, struct ipas_ma_m2 *m2);
void ipas_ma_m2_dump(struct ipas_ma_m2 *m2);

// void ipas_ma_p1_to_string(struct ipas_ma_p1 *p1);
void ipas_ma_dump_p1(struct ipas_ma_p1 *p1);

// void ipas_attest_dump_m6(struct ipas_attest_m6 *m6);

void ipas_ma_dump_m3(struct ipas_ma_m3 *m3);

void ipas_ma_dump_m4(struct ipas_ma_m4 *m4);

// void ipas_attest_dump_m13(struct ipas_attest_m13 *m13);





/*
int ipas_attest_initiator(uint8_t *mk, uint8_t *sk, int (*read)(void *, size_t), int (*write)(void *, size_t));

int ipas_attest_responder(uint8_t *mk, uint8_t *sk, int (*read)(void *, size_t), int (*write)(void *, size_t));
*/




// A forma como esta biblioteca é feita até podia ser usada no mesmo programa simulando ambos os lados... LA problemática? Aqui ideia é que se foca apenas no protocolo deixando serialização e transporte para outros resolverem.

// Quando possível, e fizer sentido, utilizar tipos do SGX.
