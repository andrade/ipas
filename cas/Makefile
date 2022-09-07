CC := gcc
EDGER := sgx_edger8r

PROJ_DIR = $(CURDIR)
$(info [PROJ_DIR] "$(PROJ_DIR)")

SGX_SDK ?= $(HOME)/.local/lib/x86_64-linux-gnu/sgxsdk
$(info [SGX_SDK ] "$(SGX_SDK)")

SGX_DEBUG ?= 1
$(info [SGX_DEBUG] "$(SGX_DEBUG)")

USGX_HOME ?=
$(info [USGX_HOME] "$(USGX_HOME)")

define GOOD
	@echo -n $1
	@tput setaf 6
	@echo -n $2
	@tput sgr0
	@echo $3
endef

define EVIL
	@echo -n $1
	@tput setaf 3
	@echo -n $2
	@tput sgr0
	@echo $3
endef

$(info ------------------------------------------------------------------------)

CPPFLAGS := -I./include -I$(USGX_HOME)/include
CFLAGS := -m64 -Wall -Wextra -std=c11

ifeq ($(SGX_DEBUG),1)
	CFLAGS += -Og -g
	CFLAGS += -DDEBUG
else
	CFLAGS += -O2
	CFLAGS += -UDEBUG
endif

TLIB_IPATHS := -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc \
		-I$(SGX_SDK)/include/epid
TLIB_CFLAGS := $(CPPFLAGS) $(CFLAGS) \
		-Wno-implicit-function-declaration -nostdinc -fpie -fstack-protector \
		-fno-builtin-printf $(TLIB_IPATHS)

ULIB_CFLAGS := $(CPPFLAGS) $(CFLAGS) -I$(SGX_SDK)/include -fPIC -Wno-attributes

all: libipas-attestation-normal.a libipas-attestation-secure.a
	@echo "MAKE  ·  $^"

#                           UNTRUSTED                           #

src/u/attestation_u.c src/u/attestation_u.h: include/ipas/attestation.edl
	@$(EDGER) --untrusted $< --untrusted-dir src/u \
			--search-path $(USGX_HOME)/include \
			--search-path $(SGX_SDK)/include
	@echo "GEN   ·  $^  >  $@"

src/u/attestation.o: include/ipas/u/attestation.h src/u/attestation_u.h
#src/u/rap.capnp.c src/u/rap.capnp.h src/u/serialization.[ch]
#src/u/attestation.o: src/u/attestation_u.h

#src/u/rap.capnp.o: src/u/rap.capnp.c src/u/rap.capnp.h

src/u/%.o: src/u/%.c
	@$(CC) $(ULIB_CFLAGS) -c $< -o $@
	@echo "CC    ·  $^  >  $@"

libipas-attestation-normal.a: src/u/attestation.o src/u/attestation_u.o src/u/one.o src/u/sgx_print.o
#src/u/rap.capnp.o src/u/cencode.o src/u/cdecode.o src/u/base64.o src/u/serialization.o src/u/network.o
	@ar rcs $@ $^
	$(call GOOD,,"GEN   ·  ","$^  >  $@")

#                            TRUSTED                            #

src/t/attestation_t.c src/t/attestation_t.h: include/ipas/attestation.edl
	@$(EDGER) --trusted $< --trusted-dir src/t \
			--search-path $(USGX_HOME)/include \
			--search-path $(SGX_SDK)/include
	@echo "GEN   ·  $^  >  $@"

src/t/attestation.o: src/t/attestation_t.h

src/t/%.o: src/t/%.c
	@$(CC) $(TLIB_CFLAGS) -c $< -o $@
	@echo "CC    ·  $^  >  $@"

libipas-attestation-secure.a: src/t/attestation.o src/t/attestation_t.o
	@ar rcs $@ $^
	$(call GOOD,,"GEN   ·  ","$^  >  $@")

#                            Cap'n Proto                            #

#src/u/rap.capnp.c src/u/rap.capnp.h: schema/rap.capnp
#	capnp compile -o c schema/rap.capnp
#	mv schema/rap.capnp.[ch] src/u/

#                          MAINTENANCE                          #

.PHONY: clean

TRASH := \
		src/u/rap.capnp.[ch] \
		src/u/attestation_u.h src/u/attestation_u.c src/u/attestation_u.o \
		src/u/one.o src/u/sgx_print.o \
		src/u/rap.capnp.o \
		src/u/cencode.o src/u/cdecode.o src/u/base64.o \
		src/u/serialization.o src/u/network.o \
		src/u/attestation.o \
		libipas-attestation-normal.a \
		src/t/attestation_t.h src/t/attestation_t.c src/t/attestation_t.o \
		src/t/attestation.o \
		libipas-attestation-secure.a

clean:
	@rm -rf $(TRASH)
	$(call EVIL,"CLEAN ·  Remove: ",$(TRASH),)
