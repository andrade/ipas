#include <sgx_trts.h>

// #include "usgx/t/util.h"

#include "enclave_t.h"

int ecall_root()
{
	dump_str("some strin dump in enclave");
	return 0;
}
