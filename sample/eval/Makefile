CC := gcc
EDGER := sgx_edger8r
SIGNER := sgx_sign

PROJ_DIR = $(CURDIR)
$(info [PROJ_DIR] "$(PROJ_DIR)")

SGX_SDK ?= $(HOME)/.local/lib/x86_64-linux-gnu/sgxsdk
SGX_SSL ?= $(HOME)/.local/lib/x86_64-linux-gnu/sgxssl

FOOSSL_INCLUDE ?=
FOOSSL_LIBRARY ?=

USGX_HOME ?=
IPAS_HOME ?=
IPAS_LIB_DIR := $(IPAS_HOME)/lib
IPAS_INC_DIR := $(IPAS_HOME)/include

$(info [ SGX_SDK] "$(SGX_SDK)")
$(info [ SGX_SSL] "$(SGX_SSL)")
$(info [  USGX  ] "$(USGX_HOME)")
$(info [  HOME  ] "$(IPAS_HOME)")

ifndef SGX_SDK
$(error SGX_SDK is not set)
endif

ifndef SGX_SSL
$(error SGX_SSL is not set)
endif

ifndef FOOSSL_INCLUDE
$(error FOOSSL_INCLUDE is not set)
endif

ifndef FOOSSL_LIBRARY
$(error FOOSSL_LIBRARY is not set)
endif

ifndef USGX_HOME
$(error USGX_HOME is not set)
endif

ifndef IPAS_HOME
$(error IPAS_HOME is not set)
endif

SGX_MODE ?= HW
SGX_DEBUG ?= 1
SGX_PRERELEASE ?= 0
EVALUATE ?= 0

$(info [SGX_MODE] $(SGX_MODE))
$(info [SGX_DEBUG] $(SGX_DEBUG))
$(info [SGX_PRERELEASE] $(SGX_PRERELEASE))
$(info [EVALUATE] $(EVALUATE))

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
	SGX_URTS := sgx_urts
	SGX_LAUNCH := sgx_launch
	SGX_EPID := sgx_epid
else
	SGX_TRTS := sgx_trts_sim
	SGX_TSERVICE := sgx_tservice_sim
	SGX_URTS := sgx_urts_sim
	SGX_LAUNCH := sgx_launch_sim
	SGX_EPID := sgx_epid_sim
endif

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

ifeq ($(EVALUATE),1)
	CFLAGS += -DEVALUATE -DEVAL_MA -DEVAL_SEALING -DEVAL_UNSEALING
else
	CFLAGS += -UEVALUATE -UEVAL_MA -UEVAL_SEALING -UEVAL_UNSEALING
endif

ENC_IPATHS := \
		-I$(IPAS_INC_DIR) \
		-I$(USGX_HOME)/include \
		-I$(SGX_SSL)/include \
		-I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc
ENC_CFLAGS := $(ENC_IPATHS) $(CFLAGS) \
		-fPIC -Wno-implicit-function-declaration \
		-nostdinc -fvisibility=hidden \
		-fpie -fstack-protector -fno-builtin-printf
ENC_LDFLAGS := \
		-nostdlib -nodefaultlibs -nostartfiles \
		-L$(IPAS_LIB_DIR) \
		-L$(USGX_HOME) \
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
		-I$(IPAS_INC_DIR) \
		-I$(USGX_HOME)/include \
		-I$(SGX_SSL)/include \
		-I$(SGX_SDK)/include
ULIB_CFLAGS := $(CFLAGS) -fPIC -Wno-attributes
ULIB_LDFLAGS := -shared \
		-L$(IPAS_LIB_DIR) \
		-L$(USGX_HOME) \
		-L$(SGX_SSL)/lib64 \
		-L$(SGX_SDK)/lib64
ULIB_LDLIBS := \
		-lipas-attestation-normal \
		-lipas-sealing-normal \
		-lusgx-normal \
		-lsgx_usgxssl \
		-l$(SGX_URTS) -l$(SGX_LAUNCH) -l$(SGX_EPID) \
		-lc -ldl

APP_CFLAGS := $(CFLAGS) \
		-fPIC -Wno-attributes \
		-I$(IPAS_INC_DIR) \
		-I$(USGX_HOME)/include \
		-I$(FOOSSL_INCLUDE) \
		-I$(SGX_SSL)/include \
		-I$(SGX_SDK)/include
APP_LDFLAGS := \
		-L$(IPAS_LIB_DIR) \
		-L$(USGX_HOME) \
		-L$(FOOSSL_LIBRARY) \
		-L$(SGX_SSL)/lib64 \
		-L$(SGX_SDK)/lib64
ifeq ($(SGX_MODE),HW)
APP_LDLIBS := \
		-lipas-attestation-normal \
		-lipas-sealing-normal \
		-lusgx-normal \
		-lsgx_usgxssl \
		-lfoossl_client -lfoossl_common \
		-l$(SGX_URTS) -l$(SGX_LAUNCH) -l$(SGX_EPID) \
		-ldl -lssl -lcrypto \
		-lc -lcapnp_c -ljansson
else
APP_LDLIBS := \
		-lipas-attestation-normal \
		-lipas-sealing-normal \
		-lusgx-normal \
		-lsgx_usgxssl \
		-lfoossl_client -lfoossl_common \
		-l$(SGX_URTS) -l$(SGX_LAUNCH) -l$(SGX_EPID) \
		-ldl -lssl -lcrypto \
		-lc -lcapnp_c -ljansson
endif

TLIB := enclave.signed.so
ULIB := untrusted.so
APP := eval

all: $(TLIB) $(ULIB) $(APP)
	$(call GOOD,,"[  MAKE  ] ","$(notdir $^)")

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
################################ TRUSTED LIBRARY
################################################################

enclave_t.c enclave_t.h: enclave.edl
	@$(EDGER) --trusted enclave.edl \
			--search-path $(IPAS_INC_DIR) \
			--search-path $(USGX_HOME)/include \
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
################################ UNTRUSTED COMMON: lib and app
################################################################

enclave_u.c enclave_u.h: enclave.edl
	@$(EDGER) --untrusted $< \
			--search-path $(IPAS_INC_DIR) \
			--search-path $(USGX_HOME)/include \
			--search-path $(SGX_SSL)/include \
			--search-path $(SGX_SDK)/include
	$(info [  GEN   ] $^  >  $@)

enclave_u.o: enclave_u.c enclave_u.h
support.o: support.c enclave_u.h

################################################################
################################ UNTRUSTED LIBRARY
################################################################

# done above in untrusted common:
#enclave_u.c enclave_u.h: enclave.edl
#enclave_u.o: enclave_u.c enclave_u.h
#support.o: support.c enclave_u.h

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

# done above in untrusted common:
#enclave_u.c enclave_u.h: enclave.edl
#enclave_u.o: enclave_u.c enclave_u.h
#support.o: support.c enclave_u.h

css.capnp.o: css.capnp.c css.capnp.h
cencode.o: cencode.c cencode.h
cdecode.o: cdecode.c cdecode.h
base64.o: base64.c base64.h
serialization.o: serialization.c serialization.h
network.o: network.c network.h
disk.o: disk.c disk.h
main.o: main.c enclave_u.h css.capnp.o css.capnp.h serialization.[ch]

CLIENT_NORMAL_OBJS := enclave_u.o support.o css.capnp.o cencode.o cdecode.o base64.o serialization.o network.o disk.o main.o

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

.PHONY: clean

TRASH := \
		$(TLIB) enclave.so enclave.o \
		enclave_t.o enclave_t.c enclave_t.h \
		$(ULIB) $(ULIB_OBJS) \
		enclave_u.o enclave_u.c enclave_u.h \
		$(APP) $(CLIENT_NORMAL_OBJS) \
		css.capnp.o css.capnp.c css.capnp.h
clean:
	@rm -rf $(TRASH)
	$(call EVIL,,"[   RM   ] ",$(TRASH))
