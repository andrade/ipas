# sample application hello

This enclaved application uses the functionality provided by IPAS.

The application *hello* communicates with the CSS to perform mutual attestation and afterwards seal and unseal data in such a way it can be unsealed in future iterations even when *hello* executes on a different processor.

## Building

### Prerequisites

- A subscription key for the Intel Attestation Service (IAS)

- An [Intel SGX](https://github.com/intel/linux-sgx) development environment including [Intel SGX SSL](https://github.com/intel/intel-sgx-ssl)

- An [IPAS](https://github.com/andrade/ipas) development environment

- Ubuntu 18.04

- OpenSSL 1.1.1

The testing environment uses OpenSSL 1.1.1 available in the repositories of Ubuntu 18.04, Intel SGX SDK 2.17.1, Intel SGX SSL w/ OpenSSL 1.1.1o, ...

In addition, it requires foossl which is a wrapper around OpenSSL for establishing TLS connections and usgx which provides utility functions for enclaves.

The environment variables `SGX_SDK`, `SGX_SSL`, `FOOSSL_INCLUDE`, `FOOSSL_LIBRARY`, `USGX_HOME` and `IPAS_HOME` must be set.

### Compiling

```
$ make

(...)

$ make clean
```

## Running

Run the application with:

```
$ ./hello [command] [options]

$ ./hello ma -s <spid>

$ ./hello seal -s <spid> -m <message to seal>

$ ./hello unseal -s <spid>

$ ./hello help
```

Where `ma` mutual attests with the CSS, `seal` seals the provided text with the support of the CSS, `unseal` unseals a previously sealed text with the support of the CSS, and `help` displays the full options available to the application.

## License

TBD
