Example use of the libraries in `secure-token-phone`. This sample consists of a minimal client and a minimal server, where the GNU/Linux client calls functions that may require authorization via the ST.

Consider using this to demonstrate most, if not all, functionality available by the libraries. (TODO: Create a `sample-pst-minimal` with a hello world version.)

## Compiling

1. First source the environment variables, set the `SGX_KEY`, and compile the SRX library (see top-level README).
2. Then compile this application:
	- For pre-release with `make SGX_MODE=HW  SGX_DEBUG=0 SGX_PRERELEASE=1`, or
	- For development with `make SGX_MODE=SIM  SGX_DEBUG=1 SGX_PRERELEASE=0` (= `$ make`).

## Running

Calling `$ ./app_ex` without arguments displays the help menu.
