## Building and Installation

### Prerequisites

- An [Intel SGX](https://github.com/intel/linux-sgx) development environment including [Intel SGX SSL](https://github.com/intel/intel-sgx-ssl)

- An [IPAS](https://github.com/andrade/ipas) development environment

- OpenSSL 1.1.1 (from Ubuntu 18.04 repositories will do)

- usgx

### Compiling

* Compile the library with `$ make`
* Clean all generated files with with `$ make clean`

### Installing

TODO

### Using

<!-- To use the library ~~without installing it~~: -->

TODO

## Project Layout

```
ipa/
├── src
│   ├── t                               # trusted source code
│       ├── *.c                         # implementation of trusted code
│       └── *.h                         # internal trusted headers
│   └── u                               # untrusted source code
│       ├── *.c                         # implementation of untrusted code
│       └── *.h                         # internal untrusted headers
├── Makefile
└── README.md                           # this file
```
