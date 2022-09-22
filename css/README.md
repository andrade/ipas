# Cloud Storage Service

The Cloud Storage Service (CSS) enables an enclave to unseal data that was previously sealed by the same enclave on a different processor.

## Building

### Prerequisites

- A subscription key for the Intel Attestation Service (IAS)

- An [Intel SGX](https://github.com/intel/linux-sgx) development environment including [Intel SGX SSL](https://github.com/intel/intel-sgx-ssl)

- An [IPAS](https://github.com/andrade/ipas) development environment

- Ubuntu 18.04

- OpenSSL 1.1.1

The testing environment uses OpenSSL 1.1.1 available in the repositories of Ubuntu 18.04, Intel SGX SDK 2.17.1, Intel SGX SSL w/ OpenSSL 1.1.1o, ...

In addition, it requires foossl which is a wrapper around OpenSSL for establishing TLS connections and usgx which provides utility functions for enclaves.

The environment variables `SGX_SDK`, `SGX_SSL`, `FOOSSL_INCLUDE`, `FOOSSL_LIBRARY`, and `USGX_HOME` must be set. `IPAS_HOME` must be set as well.

### Compiling

At `IPAS_HOME/css` do:

```
$ make

(...)

$ make clean
```

## Running

Run the service with:

```
$ ./css --spid=<your spid here>
```

## License

TBD
