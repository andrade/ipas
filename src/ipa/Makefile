CC := gcc
EDGER := sgx_edger8r

PROJ_DIR = $(CURDIR)
$(info [PROJ_DIR] "$(PROJ_DIR)")

SGX_SDK ?= $(HOME)/.local/lib/x86_64-linux-gnu/sgxsdk
SGX_SSL ?= $(HOME)/.local/lib/x86_64-linux-gnu/sgxssl
$(info [SGX_SDK ] "$(SGX_SDK)")
$(info [ SSL_DIR] "$(SGX_SSL)")

SGX_DEBUG ?= 1
$(info [SGX_DEBUG] "$(SGX_DEBUG)")

USGX_HOME ?=
$(info [USGX_HOME] "$(USGX_HOME)")

$(info [  HOME  ] "$(IPAS_HOME)")
IPAS_LIB_DIR := $(IPAS_HOME)/lib
IPAS_INC_DIR := $(IPAS_HOME)/include
IPAS_SRC_DIR := $(IPAS_HOME)/src/ipa

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

CPPFLAGS := -I$(IPAS_INC_DIR) -I$(USGX_HOME)/include
CFLAGS := -m64 -Wall -Wextra -std=c11

ifeq ($(SGX_DEBUG),1)
	CFLAGS += -Og -g
	CFLAGS += -DDEBUG
else
	CFLAGS += -O2
	CFLAGS += -UDEBUG
endif

TLIB_IPATHS := \
		-I$(SGX_SSL)/include \
		-I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc
TLIB_CFLAGS := $(CPPFLAGS) $(CFLAGS) $(TLIB_IPATHS) \
		-Wno-implicit-function-declaration -nostdinc -fpie -fstack-protector \
		-fno-builtin-printf

ULIB_IPATHS := -I$(SGX_SSL)/include -I$(SGX_SDK)/include
ULIB_CFLAGS := $(CPPFLAGS) $(CFLAGS) $(ULIB_IPATHS) \
		-fPIC -Wno-attributes

all: libipas-attestation-normal.a libipas-attestation-secure.a | $(IPAS_LIB_DIR)
	@echo "MAKE  ·  $^"
	cp libipas-attestation-normal.a $(IPAS_LIB_DIR)
	cp libipas-attestation-secure.a $(IPAS_LIB_DIR)

$(IPAS_LIB_DIR):
	mkdir $(IPAS_LIB_DIR)

#                           UNTRUSTED                           #

src/u/attestation_u.c src/u/attestation_u.h: $(IPAS_INC_DIR)/ipas/attestation.edl
	@$(EDGER) --untrusted $< --untrusted-dir src/u \
			--search-path $(USGX_HOME)/include \
			--search-path $(SGX_SSL)/include \
			--search-path $(SGX_SDK)/include
	@echo "GEN   ·  $^  >  $@"

src/u/attestation.o: $(IPAS_INC_DIR)/ipas/u/attestation.h src/u/attestation_u.h

src/u/%.o: src/u/%.c
	@$(CC) $(ULIB_CFLAGS) -c $< -o $@
	@echo "CC    ·  $^  >  $@"

libipas-attestation-normal.a: src/u/attestation.o src/u/attestation_u.o src/u/one.o src/u/sgx_print.o
	@ar rcs $@ $^
	$(call GOOD,,"GEN   ·  ","$^  >  $@")

#                            TRUSTED                            #

src/t/attestation_t.c src/t/attestation_t.h: $(IPAS_INC_DIR)/ipas/attestation.edl
	@$(EDGER) --trusted $< --trusted-dir src/t \
			--search-path $(USGX_HOME)/include \
			--search-path $(SGX_SSL)/include \
			--search-path $(SGX_SDK)/include
	@echo "GEN   ·  $^  >  $@"

src/t/attestation.o: $(IPAS_INC_DIR)/ipas/t/attestation.h src/t/attestation_t.h
src/t/cdecode.o: src/t/cdecode.h
src/t/cJSON.o: src/t/cJSON.h
src/t/perdec.o: src/t/perdec.h
src/t/x509.o: src/t/x509.h

src/t/%.o: src/t/%.c
	@$(CC) $(TLIB_CFLAGS) -c $< -o $@
	@echo "CC    ·  $^  >  $@"

libipas-attestation-secure.a: src/t/attestation.o src/t/attestation_t.o src/t/cdecode.o src/t/cJSON.o src/t/perdec.o src/t/x509.o
	@ar rcs $@ $^
	$(call GOOD,,"GEN   ·  ","$^  >  $@")

#                          MAINTENANCE                          #

.PHONY: clean

TRASH := \
		src/u/attestation_u.h src/u/attestation_u.c src/u/attestation_u.o \
		src/u/one.o src/u/sgx_print.o \
		src/u/cencode.o src/u/cdecode.o src/u/base64.o \
		src/u/serialization.o src/u/network.o \
		src/u/attestation.o \
		libipas-attestation-normal.a \
		$(IPAS_LIB_DIR)/libipas-attestation-normal.a \
		src/t/attestation_t.h src/t/attestation_t.c src/t/attestation_t.o \
		src/t/attestation.o \
		src/t/cdecode.o src/t/cJSON.o src/t/perdec.o src/t/x509.o \
		libipas-attestation-secure.a \
		$(IPAS_LIB_DIR)/libipas-attestation-secure.a

clean:
	@rm -rf $(TRASH)
	$(call EVIL,"CLEAN ·  Remove: ",$(TRASH),)
