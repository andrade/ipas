CC := gcc
EDGER := sgx_edger8r
SIGNER := sgx_sign

PROJ_DIR = $(CURDIR)
$(info [PROJ_DIR] "$(PROJ_DIR)")

SGX_SDK ?= $(HOME)/.local/lib/x86_64-linux-gnu/sgxsdk
SGX_SSL ?= $(HOME)/.local/lib/x86_64-linux-gnu/sgxssl
$(info [ SGX_DIR] "$(SGX_SDK)")
$(info [ SSL_DIR] "$(SGX_SSL)")

IPAS_ATTESTATION_LIB ?=
ifndef IPAS_ATTESTATION_LIB
$(error IPAS_ATTESTATION_LIB is not set)
endif
$(info [IPAS_ATT] "$(IPAS_ATTESTATION_LIB)")
# FIXME provavelmente remover depois de reestruturar repositório ipas-lib

# root dir pode vir de variável, ou de ficheiro buildenv.mk na root?
IPAS_HOME ?=
ifndef IPAS_HOME
$(error IPAS_HOME is not set)
endif
$(info [  HOME  ] "$(IPAS_HOME)")
IPAS_LIB_DIR := $(IPAS_HOME)/lib
IPAS_INC_DIR := $(IPAS_HOME)/include
# IPAS_SRC_DIR
# IPAS_INC_DIR
# FIXME depois de reestruturar repositório ipas-lib

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
	SGX_UAE_SERVICE := sgx_uae_service
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
		-I$(IPAS_ATTESTATION_LIB)/include \
		-I$(USGX_HOME)/include \
		-I$(SGX_SSL)/include \
		-I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc
ENC_CFLAGS := $(CFLAGS) $(ENC_IPATHS) \
		-fPIC -Wno-implicit-function-declaration \
		-nostdinc -fvisibility=hidden \
		-fpie -fstack-protector -fno-builtin-printf
ENC_LDFLAGS := $(CFLAGS) \
		-nostdlib -nodefaultlibs -nostartfiles \
		-L$(USGX_HOME) \
		-L$(IPAS_ATTESTATION_LIB) \
		-L$(IPAS_LIB_DIR) \
		-L$(SGX_SSL)/lib64 \
		-L$(SGX_SDK)/lib64
ENC_LDLIBS := \
		-lipas-attestation-secure \
		-lipas-sealing-secure \
		-lusgx-secure \
		-Wl,--no-undefined \
		-Wl,--whole-archive -lsgx_tsgxssl -Wl,--no-whole-archive \
		-lsgx_tsgxssl_crypto -lsgx_pthread \
		-Wl,--whole-archive -l$(SGX_TRTS) -Wl,--no-whole-archive \
		-Wl,--start-group -lsgx_tstdc -lsgx_tcxx -lsgx_tcrypto -l$(SGX_TSERVICE) -Wl,--end-group \
		-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined -Wl,-pie,-eenclave_entry -Wl,--export-dynamic \
		-Wl,--defsym,__ImageBase=0 -Wl,--version-script=enclave.lds

ULIB_CPPFLAGS := -I. \
		-I$(USGX_HOME)/include \
		-I$(IPAS_ATTESTATION_LIB)/include \
		-I$(SGX_SSL)/include \
		-I$(SGX_SDK)/include
ULIB_CFLAGS := $(CFLAGS) -fPIC -Wno-attributes
ULIB_LDFLAGS := -shared \
		-L$(USGX_HOME) \
		-L$(IPAS_ATTESTATION_LIB) \
		-L$(IPAS_LIB_DIR) \
		-L$(SGX_SSL)/lib64 \
		-L$(SGX_SDK)/lib64
ULIB_LDLIBS := \
		-lipas-attestation-normal \
		-lipas-sealing-normal \
		-lusgx-normal \
		-lsgx_usgxssl \
		-l$(SGX_URTS) -l$(SGX_UAE_SERVICE) \
		-lpthread -lc -ldl

APP_CFLAGS := $(CFLAGS) \
		-fPIC -Wno-attributes \
		-I$(USGX_HOME)/include \
		-I$(IPAS_ATTESTATION_LIB)/include \
		-I$(FOOSSL_INCLUDE) \
		-I$(SGX_SSL)/include \
		-I$(SGX_SDK)/include
APP_LDFLAGS := \
		-L$(USGX_HOME) \
		-L$(IPAS_ATTESTATION_LIB) \
		-L$(IPAS_LIB_DIR) \
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
		-lfoossl_client -lfoossl_common \
		-l$(SGX_URTS) -l$(SGX_LAUNCH) -l$(SGX_EPID) \
		-lssl -lcrypto \
		-lpthread -lc -ldl -lzmq -lcapnp_c -ljansson
else
APP_LDLIBS := \
		-lipas-attestation-normal \
		-lipas-sealing-normal \
		-lusgx-normal \
		-lsgx_usgxssl \
		-lfoossl_client -lfoossl_common \
		-l$(SGX_URTS) -l$(SGX_UAE_SERVICE) \
		-lssl -lcrypto \
		-lpthread -lc -ldl -lzmq -lcapnp_c -ljansson
endif

# EDL_SEARCH_PATHS := .:$(SRX_API):$(SGX_SDK)/include:$(SGX_SSL)/include:$(SRX_USGX)/include

TLIB := enclave.signed.so
ULIB := untrusted.so
APP := hello

all: $(TLIB) $(ULIB) $(APP)
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
################################ TRUSTED LIBRARY
################################################################

#enclave_t.c enclave_t.h: enclave.edl $(SRX_API)/srx.edl
#	@$(EDGER) --trusted enclave.edl --search-path $(EDL_SEARCH_PATHS)
#	$(info [  GEN   ] $^  >  $@)

enclave_t.c enclave_t.h: enclave.edl
	@$(EDGER) --trusted enclave.edl \
			--search-path $(USGX_HOME)/include \
			--search-path $(IPAS_ATTESTATION_LIB)/include \
			--search-path $(SGX_SSL)/include \
			--search-path $(SGX_SDK)/include
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

$(TLIB): enclave.so enclave.config.xml $(KEY_PR)
	@$(SIGNER) sign -key $(KEY_PR) -enclave enclave.so -out $(TLIB) -config enclave.config.xml
	$(info [  SIGN  ] $^  >  $@)

################################################################
################################ UNTRUSTED LIBRARY
################################################################

enclave_u.c enclave_u.h: enclave.edl
	@$(EDGER) --untrusted $< \
			--search-path $(USGX_HOME)/include \
			--search-path $(IPAS_ATTESTATION_LIB)/include \
			--search-path $(SGX_SSL)/include \
			--search-path $(SGX_SDK)/include
	$(info [  GEN   ] $^  >  $@)

enclave_u.o: enclave_u.c enclave_u.h

support.o: support.c enclave_u.h

ULIB_OBJS := enclave_u.o support.o

$(ULIB_OBJS):
	@ $(CC) $(ULIB_CPPFLAGS) $(ULIB_CFLAGS) -c -o $@ $<
	$(info [   CC   ] $^  >  $@)

$(ULIB): $(ULIB_OBJS)
	@ $(CC) $(ULIB_CPPFLAGS) $(ULIB_CFLAGS) -o $@ $^ $(ULIB_LDFLAGS) $(ULIB_LDLIBS)
	$(info [  LINK  ] $^  >  $@)

################################################################
################################ APPLICATION
################################################################

#enclave_u.c enclave_u.h: enclave.edl $(SRX_API)/srx.edl
#	@$(EDGER) --untrusted $< --search-path $(EDL_SEARCH_PATHS)
#	$(info [  GEN   ] $^  >  $@)

enclave_u.c enclave_u.h: enclave.edl
	@$(EDGER) --untrusted $< \
			--search-path $(USGX_HOME)/include \
			--search-path $(IPAS_ATTESTATION_LIB)/include \
			--search-path $(SGX_SSL)/include \
			--search-path $(SGX_SDK)/include
	$(info [  GEN   ] $^  >  $@)

enclave_u.o: enclave_u.c enclave_u.h

# mainapp.o: mainapp.c enclave_u.h

support.o: support.c enclave_u.h
css.capnp.o: css.capnp.c css.capnp.h
cencode.o: cencode.c cencode.h
cdecode.o: cdecode.c cdecode.h
base64.o: base64.c base64.h
serialization.o: serialization.c serialization.h
network.o: network.c network.h

# network.o: network.c network.h enclave_u.h

disk.o: disk.c disk.h

main.o: main.c enclave_u.h css.capnp.o css.capnp.h serialization.[ch]

#CLIENT_NORMAL_OBJS := enclave_u.o mainapp.o support.o network.o disk.o
CLIENT_NORMAL_OBJS := enclave_u.o main.o support.o disk.o css.capnp.o cencode.o cdecode.o base64.o serialization.o network.o

$(CLIENT_NORMAL_OBJS):
	@ $(CC) $(APP_CFLAGS) -c $< -o $@
	$(info [   CC   ] $^  >  $@)

$(APP): $(CLIENT_NORMAL_OBJS) $(TLIB)
	@$(CC) $(APP_CFLAGS) -o $@ $^ $(APP_LDFLAGS) $(APP_LDLIBS)
	$(info [  LINK  ] $^  >  $@)

################################################################
################################ Cap'n Proto
################################################################

css.capnp.c css.capnp.h: css.capnp
	capnp compile -o c css.capnp

################################################################
################################ MAINTENANCE
################################################################

TRASH := $(APP) \
		enclave_t.h enclave_t.c enclave_t.o \
		enclave.o enclave.so $(TLIB) \
		$(ULIB_OBJS) $(ULIB) \
		enclave_u.h enclave_u.c enclave_u.o \
		disk.o network.o support.o \
		css.capnp.h css.capnp.c css.capnp.o \
		cencode.o cdecode.o base64.o serialization.o network.o \
		main.o
clean:
	@rm -rf $(TRASH)
	$(call EVIL,,"[   RM   ] ",$(TRASH))
