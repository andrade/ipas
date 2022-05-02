#ifndef RAP_CORE_H
#define RAP_CORE_H

#include <stddef.h>
#include <stdint.h>

#include <sgx_quote.h>

int get_sigrl(uint32_t *code, int fd_ignored, sgx_epid_group_id_t *gid);

int get_report(uint32_t *code,
		char *rid, size_t rid_cap,
		char *sig, size_t sig_cap,
		char *cc, size_t cc_cap,
		char *report, size_t report_cap,
		// char *quote_status,
		int fd_ignored, sgx_quote_t *quote, uint32_t quote_size);

#endif
