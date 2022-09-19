#ifndef RA_TYPES_H
#define RA_TYPES_H

/**
** Defines types for use in the remote attestation process.
**
** These follow the types exchanged with IAS, except
** when there is a more appropriate data type (from SGX).
** For example, the nonce exchanged with IAS has type string
** but here we give it the SGX type `sgx_quote_nonce_t`
** (leaving the conversion to and from string to the library
** mediating the communication between client and proxy service).
** This is meant to make the developer's life easier.
**
** Types do not require dynamic allocation.
**/


struct ra_sigrl {
	sgx_epid_group_id_t gid;    // request, mandatory

	uint32_t code;              // reply, mandatory
	char rid[32+1];             // reply

	uint8_t srl[512];           // reply, set only when status code is 200
	uint32_t srl_len;           // and may not exist for gid
};


// Attestation Evidence Payload
struct ra_aep {
	// sgx_quote_t quote;          // request, mandatory
	uint8_t quote[2048];        // request, mandatory
	uint32_t quote_size;
	sgx_quote_nonce_t nonce;    // request, optional
};

// Attestation Verification Report
struct ra_avr {
	char report_id[96];         // reply, mandatory
	char timestamp[128];        // reply, mandatory
	uint32_t version;           // reply, mandatory
	char quote_status[64];      // reply, mandatory
	char quote_body[532];       // reply, mandatory

	uint32_t revocation_reason; // reply, optional
	char pib[64];               // reply, optional
	sgx_quote_nonce_t nonce;    // reply, optional
	char epid_pseudonym[128+1]; // reply, optional
	char advisory_url[256];     // reply, optional
	char advisory_ids[384];     // reply, optional
};
// advisory_ids is an array, a library can have a function to parse it

struct ra_report {
	struct ra_aep aep;          // request, mandatory

	uint32_t code;              // reply, mandatory
	char rid[32+1];             // reply
	char signature[256];        // reply, set only when status code is 200
	char certificates[1024];    // reply, set only when status code is 200

	struct ra_avr avr;          // reply, set only when status code is 200
};

#endif
