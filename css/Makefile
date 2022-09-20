CC := gcc
EDGER := sgx_edger8r
SIGNER := sgx_sign

PROJ_DIR = $(CURDIR)
$(info [PROJ_DIR] "$(PROJ_DIR)")

SGX_SDK ?= $(HOME)/.local/lib/x86_64-linux-gnu/sgxsdk
SGX_SSL ?= $(HOME)/.local/lib/x86_64-linux-gnu/sgxssl
$(info [ SGX_DIR] "$(SGX_SDK)")
$(info [ SSL_DIR] "$(SGX_SSL)")

# root dir pode vir de variável, ou de ficheiro buildenv.mk na root?
IPAS_HOME ?=
ifndef IPAS_HOME
$(error IPAS_HOME is not set)
endif
$(info [  HOME  ] "$(IPAS_HOME)")
IPAS_LIB_DIR := $(IPAS_HOME)/lib
IPAS_INC_DIR := $(IPAS_HOME)/include

# FIXME set pelo utilizador, pelo top-level make, ou pelo environment file
FOOSSL_INCLUDE ?= $(HOME)/vc/foossl/include
FOOSSL_LIBRARY ?= $(HOME)/vc/foossl/static

USGX_HOME ?= $(HOME)/vc/usgx
$(info [USGX_HOME] "$(USGX_HOME)")

# SRX_API ?=
# ifndef SRX_API
# $(error SRX_API is not set)
# endif
#
# SRX_SDK ?=
# ifndef SRX_SDK
# $(error SRX_SDK is not set)
# endif
#
# SRX_OPENSSL ?=
# ifndef SRX_OPENSSL
# $(error Environment variable `SRX_OPENSSL` is not set)
# endif
# $(info [SRX_OPENSSL] "$(SRX_OPENSSL)")

## Additional include paths for EDL (define via CLI when calling make)
#EDL_INC_PATH ?=
## Additional library paths for EDL (define via CLI when calling make)
#EDL_LIB_PATH ?=
#CHANGED  use $(SRX_USGX) instead with or without include/ as necessary

SGX_MODE ?= SIM
SGX_DEBUG ?= 1
SGX_PRERELEASE ?= 0

$(info [SGX_MODE] "$(SGX_MODE)")
$(info [SGX_DEBUG] "$(SGX_DEBUG)")
$(info [SGX_PRERELEASE] "$(SGX_PRERELEASE)")

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

ifeq ($(SGX_MODE),HW)
	SGX_TRTS := sgx_trts
	SGX_TSERVICE := sgx_tservice
	#SGX_UAE_SERVICE := sgx_uae_service
	SGX_URTS := sgx_urts
	SGX_LAUNCH := sgx_launch
	SGX_EPID := sgx_epid
else
	SGX_TRTS := sgx_trts_sim
	SGX_TSERVICE := sgx_tservice_sim
	SGX_UAE_SERVICE := sgx_uae_service_sim
	SGX_URTS := sgx_urts_sim
endif

# in SIM: sgx_uae_service_sim
# but HW: sgx_launch + sgx_epid

CFLAGS := -m64 -std=c11 -Wall -Wextra

ifeq ($(SGX_DEBUG),1)
	CFLAGS += -O0 -g
	CFLAGS += -DDEBUG -UNDEBUG -UEDEBUG
else
	CFLAGS += -O2
ifeq ($(SGX_PRERELEASE),1)
	CFLAGS += -UDEBUG -DNDEBUG -DEDEBUG
else
	CFLAGS += -UDEBUG -DNDEBUG -UEDEBUG
endif # SGX_PRERELEASE
endif

ifeq ($(SGX_PRERELEASE),1)
	CFLAGS += -O2
	CFLAGS += -UDEBUG -DNDEBUG -DEDEBUG
else
endif
# TODO Verificar flags com prerelease, etc

TLIB_IPATHS := -I$(SGX_SDK)/include \
		-I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/epid
TLIB_CFLAGS := $(CFLAGS) -std=c11 \
		-Wno-implicit-function-declaration -nostdinc -fpie -fstack-protector \
		-fno-builtin-printf $(TLIB_IPATHS)

ENC_IPATHS := \
		-I$(USGX_HOME)/include \
		-I$(IPAS_ATTESTATION_LIB)/include \
		-I$(SGX_SDK)/include \
		-I$(SGX_SDK)/include/tlibc \
		-I$(SGX_SDK)/include/stlport
ENC_CFLAGS := $(CFLAGS) -fPIC -Wno-implicit-function-declaration \
		-std=c11 -nostdinc -fvisibility=hidden \
		-fpie -fstack-protector -fno-builtin-printf \
		$(ENC_IPATHS)
ENC_LDFLAGS := $(CFLAGS) \
		-nostdlib -nodefaultlibs -nostartfiles \
		-L$(SGX_SDK)/lib64 \
		-L$(USGX_HOME) \
		-L$(IPAS_ATTESTATION_LIB) -L$(IPAS_LIB_DIR)
ENC_LDLIBS := \
		-lipas-attestation-secure \
		-lipas-sealing-secure \
		-lusgx-secure \
		-Wl,--no-undefined \
		-Wl,--whole-archive -l$(SGX_TRTS) -Wl,--no-whole-archive \
		-Wl,--start-group -lsgx_tstdc -lsgx_tcrypto -l$(SGX_TSERVICE) -Wl,--end-group \
		-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined -Wl,-pie,-eenclave_entry -Wl,--export-dynamic \
		-Wl,--defsym,__ImageBase=0 -Wl,--version-script=enclave.lds
#-Wl,--start-group -lsgx_tstdc -lsgx_tstdcxx -lsgx_tcrypto -lsgx_tservice_sim -Wl,--end-group

APP_CFLAGS := $(CFLAGS) \
		-I. \
		-I$(IPAS_HOME)/include \
		-I$(USGX_HOME)/include \
		-I$(FOOSSL_INCLUDE) \
		-I$(SGX_SSL)/include \
		-I$(SGX_SDK)/include -fPIC -Wno-attributes
APP_LDFLAGS := \
		-L$(IPAS_HOME)/lib \
		-L$(USGX_HOME) \
		-L$(FOOSSL_LIBRARY) \
		-L$(SGX_SSL)/lib64 \
		-L$(SGX_SDK)/lib64
		#-Wl,-rpath,$(SGX_SDK)/sdk_libs,--disable-new-dtags
ifeq ($(SGX_MODE),HW)
APP_LDLIBS := \
		-lipas-attestation-normal \
		-lipas-sealing-normal \
		-lusgx-normal \
		-lsgx_usgxssl \
		-lfoossl_server -lfoossl_common \
		-l$(SGX_URTS) -l$(SGX_LAUNCH) -l$(SGX_EPID) \
		-ldl -lssl -lcrypto \
		-lpthread -lc -lzmq -lcapnp_c -ljansson
else
APP_LDLIBS := \
		-lipas-attestation-normal \
		-lipas-sealing-normal \
		-lusgx-normal \
		-lsgx_usgxssl \
		-lfoossl_server -lfoossl_common \
		-l$(SGX_URTS) -l$(SGX_UAE_SERVICE) \
		-ldl -lssl -lcrypto \
		-lpthread -lc -lzmq -lcapnp_c -ljansson
endif

# EDL_SEARCH_PATHS := .:$(SRX_API):$(SGX_SDK)/include:$(SGX_SSL)/include:$(SRX_USGX)/include


all: css
	$(call GOOD,,"[  MAKE  ] ","$(notdir $^)")

################################################################
################################ MANAGEMENT
################################################################

.PHONY: clean

################################################################
################################ CRYPTO
################################################################

KEY_PR := key.pem

genkey:
	@openssl genrsa -3 -out $(KEY_PR) 3072
	$(call GOOD,,"[ GENKEY ] ","$^  >  $@")
	$(info [ GENKEY ] Enclave private key is left untouched by clean.)
	$(info [ GENKEY ] Explicitly use delkey to delete it.)

delkey:
	@rm -f $(KEY_PR)
	$(call EVIL,,"[ DELKEY ] ","$^  >  $@")

$(KEY_PR):
	$(call GOOD,"[ KEY_PR ] Create private key with ","make genkey",)
	$(call EVIL,"[ KEY_PR ] Delete private key with ","make delkey",)

################################################################
################################ TLS
################################################################

gentls:
	@mkdir -p tls
	@openssl req -x509 -newkey rsa:4096 \
			-keyout tls/key.pem -out tls/cert.pem \
			-subj '/C=PT/CN=ipas-css.ipas.fake' \
			-days 365 -nodes

deltls:
	@rm -f tls/key.pem tls/cert.pem
	@rmdir --ignore-fail-on-non-empty tls 2> /dev/null | true

################################################################
################################ TRUSTED CODE
################################################################

#enclave_t.c enclave_t.h: enclave.edl $(SRX_API)/srx.edl
#	@$(EDGER) --trusted enclave.edl --search-path $(EDL_SEARCH_PATHS)
#	$(info [  GEN   ] $^  >  $@)

enclave_t.c enclave_t.h: enclave.edl
	@$(EDGER) --trusted enclave.edl \
			--search-path $(USGX_HOME)/include \
			--search-path $(IPAS_ATTESTATION_LIB)/include
	$(info [  GEN   ] $^  >  $@)

enclave_t.o: enclave_t.c
	@$(CC) $(ENC_CFLAGS) -c $< -o $@
	$(info [   CC   ] $^  >  $@)

%.o: %.c enclave_t.h
	@ $(CC) $(ENC_CFLAGS) -c $< -o $@
	$(info [   CC   ] $^  >  $@)

enclave.so: enclave_t.o enclave.o
	@ $(CC) $(ENC_CFLAGS) $(ENC_LDFLAGS) -o $@ $^ $(ENC_LDLIBS)
	$(info [  GEN   ] $^  >  $@)

enclave.signed.so: enclave.so \
		enclave.config.xml $(KEY_PR)
	@$(SIGNER) sign -key $(KEY_PR) -enclave enclave.so -out enclave.signed.so -config enclave.config.xml
	$(info [  SIGN  ] $^  >  $@)

################################################################
################################ UNTRUSTED CODE
################################################################

#enclave_u.c enclave_u.h: enclave.edl $(SRX_API)/srx.edl
#	@$(EDGER) --untrusted $< --search-path $(EDL_SEARCH_PATHS)
#	$(info [  GEN   ] $^  >  $@)

#enclave_u.c enclave_u.h: enclave.edl
#	@$(EDGER) --untrusted $< \
#			--search-path $(USGX_HOME)/include \
#			--search-path $(IPAS_ATTESTATION_LIB)/include
#	$(info [  GEN   ] $^  >  $@)

#enclave_u.o: enclave_u.c enclave_u.h

# mainapp.o: mainapp.c enclave_u.h

#support.o: support.c enclave_u.h
rap/rap.capnp.o: rap/rap.capnp.c rap/rap.capnp.h
rap/base64.o: rap/base64.c rap/base64.h
rap/cencode.o: rap/cencode.c rap/cencode.h
rap/cdecode.o: rap/cdecode.c rap/cdecode.h
rap/serialization.o: rap/serialization.c rap/serialization.h
rap/network.o: rap/network.c rap/network.h
rap/rap.o: rap/rap.c rap/rap.h rap/rap.capnp.o
ssl.o: ssl.c ssl.h
css.capnp.o: css.capnp.c css.capnp.h
main.o: main.c css.capnp.o rap/rap.capnp.o rap/rap.capnp.h rap/rap.[ch] ssl.o
#main.c enclave_u.h rap.capnp.o

#CLIENT_NORMAL_OBJS := enclave_u.o mainapp.o support.o network.o disk.o
# enclave_u.o main.o support.o
CLIENT_NORMAL_OBJS := main.o css.capnp.o rap/rap.capnp.o rap/cencode.o rap/cdecode.o rap/base64.o rap/rap.o rap/serialization.o rap/network.o ssl.o

$(CLIENT_NORMAL_OBJS):
	@ $(CC) $(APP_CFLAGS) -c $< -o $@
	$(info [   CC   ] $^  >  $@)

#enclave.signed.so
css: $(CLIENT_NORMAL_OBJS)
	@$(CC) $(APP_CFLAGS) -o $@ $^ $(APP_LDFLAGS) $(APP_LDLIBS)
	$(info [  LINK  ] $^  >  $@)

################################################################
################################ Cap'n Proto
################################################################

css.capnp.c css.capnp.h: css.capnp
	capnp compile -o c css.capnp

rap/rap.capnp.c rap/rap.capnp.h: rap/rap.capnp
	capnp compile -o c rap/rap.capnp

################################################################
################################ MAINTENANCE
################################################################

TRASH := css \
		rap/network.o ssl.o support.o \
		rap/rap.capnp.h rap/rap.capnp.c rap/rap.capnp.o \
		rap/base64.o rap/cencode.o rap/cdecode.o rap/serialization.o \
		rap/network.o rap/rap.o \
		css.capnp.h css.capnp.c css.capnp.o \
		temp_untrusted.so \
		main.o
clean:
	@rm -rf $(TRASH)
	$(call EVIL,,"[   RM   ] ",$(TRASH))
