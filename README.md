# Some Title

At `$IPAS_HOME` run:

```
$ source environment
$ make build

(...)

$ make clean
```

Instead of `make build` can compile things individually, first the attestation and sealing libraries, then client and CSS applications. In this case it is still necessary to run `source environment` and don't forget to have `$SGX_SDK` and company in your path (do `source ${sgx-sdk-install-path}/environment` for that as per Intel SGX SDK instructions).

# License

TODO
