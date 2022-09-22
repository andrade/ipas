## Building and Installation

### Prerequisites

- An [Intel SGX](https://github.com/intel/linux-sgx) development environment including [Intel SGX SSL](https://github.com/intel/intel-sgx-ssl)

- An [IPAS](https://github.com/andrade/ipas) development environment

- OpenSSL 1.1.1 (from Ubuntu 18.04 repositories will do)

- usgx

### Compiling

* Compile the library with `$ make`
* Clean all generated files with with `$ make clean`

Compile IPS with `$ make IPAS_STRICT_MR=1` to bind the sealing key to MRENCLAVE (default off, binds to MRSIGNER).
