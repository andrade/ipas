/**
** Implements the untrusted functions of the interface.
**/

#include <stdio.h>

#include "enclave_u.h"

void dump_str(const char *str)
{
	printf("print_u: %s\n", str);
}
