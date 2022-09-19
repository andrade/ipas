all:
	$(info [          -          ] use make build or make clean)

build:
	$(MAKE) -C src/ipa/
	$(MAKE) -C src/ips/
	#$(MAKE) -C sample/ipas/ SGX_MODE=HW
	$(MAKE) -C css/ SGX_MODE=HW
	$(MAKE) -C sample/hello/ SGX_MODE=HW

clean:
	$(MAKE) -C sample/hello/ clean
	$(MAKE) -C css/ clean
	#$(MAKE) -C sample/ipas/ clean
	$(MAKE) -C src/ips/ clean
	$(MAKE) -C src/ipa/ clean
