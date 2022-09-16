## Building and Installation

### Prerequisites

* Intel SGX SDK and respective toolchain (needs `sgx_edger8r`)
	* The path to the framework (`$SGX_SDK`) should be set
* A C development environment
	* For compiling the source code and creating the library using the makefile

### Compiling

* Compile the library with `$ make`
* Clean all generated files with with `$ make clean`

NOTE: IPS is independent of the rest so must be compiled and cleaned on its own.

Compile IPS with `$ make IPAS_STRICT_MR=1` to bind the sealing key to MRENCLAVE (default off, binds to MRSIGNER).

### Installing

TODO

### Using

To use the library ~~without installing it~~:

TODO

## Project Layout

```
cas/
├── include
│   └── ipas                            # public API
│       ├── t                           # trusted headers
│           ├── attestation.h
│           └── sealing.h
│       ├── u                           # untrusted headers
│           ├── attestation.h
│           └── sealing.h
│       ├── *.edl                       # EDL interfaces
│       └── *.h                         # common interfaces
│
├── src
│   ├── ips/                            # IPS library, TODO: move outside CAS
│   ├── t                               # trusted source code
│       ├── *.c                         # implementation of trusted code
│       └── *.h                         # internal trusted headers
│   └── u                               # untrusted source code
│       ├── *.c                         # implementation of untrusted code
│       └── *.h                         # internal untrusted headers
├── Makefile
└── README.md                           # this file
```

## License

TODO
