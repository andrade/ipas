# Inter-Processor Attestation and Sealing

Intel SGX sealed data is traditionally bound to the processor that sealed that data.

IPAS provides a set of libraries enabling mutual attestation and sharing of sealed data between enclaves running on different processors. This is achieved with the support of two untrusted services: the Cloud Storage Service (CSS) and the Remote Attestation Proxy (RAP).

## Building

### Prerequisites

- A subscription key for the Intel Attestation Service (IAS)

- An [Intel SGX](https://github.com/intel/linux-sgx) development environment including [Intel SGX SSL](https://github.com/intel/intel-sgx-ssl)

- Ubuntu 18.04

- OpenSSL 1.1.1

The testing environment uses OpenSSL 1.1.1 available in the repositories of Ubuntu 18.04, Intel SGX SDK 2.17.1, Intel SGX SSL w/ OpenSSL 1.1.1o, ...

In addition, it requires foossl which is a wrapper around OpenSSL for establishing TLS connections (for CSS and sample apps, not libraries) and usgx which provides utility functions for enclaves.

The environment variables `SGX_SDK`, `SGX_SSL`, `FOOSSL_INCLUDE`, `FOOSSL_LIBRARY`, and `USGX_HOME` must be set.

### Compiling

At `$IPAS_HOME` run:

```
$ source environment
$ make build

(...)

$ make clean
```

Instead of `make build` can compile things individually, first the attestation and sealing libraries, then CSS and sample applications. In this case it is still necessary to do `source environment` and don't forget to have `$SGX_SDK` and company in your path.

## Using

TODO: See some-app for an example.

## Project Layout

```
ipas/
├── css
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
├── sample                              # sample applications using IPAS
│
├── src
│   ├── ipa                             # attestation library
│   └── ips                             # sealing (and unsealing) library
│
├── environment
├── Makefile
└── README.md                           # this file
```

## License

TBD
