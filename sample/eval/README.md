# Evaluation client application

This enclaved application uses the functionality provided by IPAS. The application communicates with the CSS which in turn communicates with the RAP which in turn communicates with the IAS.

---

For performance evaluation, compile with

```
$ make SGX_MODE=HW SGX_DEBUG=0 SGX_PRERELEASE=1
```

The IPAS libraries should also be compiled with debug mode disabled.

---

For testing, generate an input file with random data:

```
$ dd if=/dev/urandom of=x.input bs=1M count=5
```

Then invoke the `eval` app with this file as input:

```
$ ./eval -s <SPID> -i x.input -m x.sealed -o x.output
```

For large files may need to increase max heap. Currently set to 512 MiB.
