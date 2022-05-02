all:
	$(info [          -          ] use make build or make clean)

build:
	$(MAKE) -C cas/src/ips/
	$(MAKE) -C cas/
	#$(MAKE) -C sample/ipas/ SGX_MODE=HW
	$(MAKE) -C ipas-css/ SGX_MODE=HW
	$(MAKE) -C ipas-app-hello/ SGX_MODE=HW

clean:
	$(MAKE) -C ipas-app-hello/ clean
	$(MAKE) -C ipas-css/ clean
	#$(MAKE) -C sample/ipas/ clean
	$(MAKE) -C cas/ clean
	$(MAKE) -C cas/src/ips/ clean
