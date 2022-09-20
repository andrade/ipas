CC := gcc

PROJ_DIR = $(CURDIR)
$(info [PROJ_DIR] "$(PROJ_DIR)")

SGX_SDK ?= $(HOME)/.local/lib/x86_64-linux-gnu/sgxsdk
SGX_SSL ?= $(HOME)/.local/lib/x86_64-linux-gnu/sgxssl

FOOSSL_INCLUDE ?= $(HOME)/vc/foossl/include
FOOSSL_LIBRARY ?= $(HOME)/vc/foossl/static

USGX_HOME ?= $(HOME)/vc/usgx
IPAS_HOME ?=
#IPAS_LIB_DIR := $(IPAS_HOME)/lib
#IPAS_INC_DIR := $(IPAS_HOME)/include

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

$(info [SGX_MODE] $(SGX_MODE))
$(info [SGX_DEBUG] $(SGX_DEBUG))
$(info [SGX_PRERELEASE] $(SGX_PRERELEASE))

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
	SGX_URTS := sgx_urts
	SGX_LAUNCH := sgx_launch
	SGX_EPID := sgx_epid
else
	SGX_URTS := sgx_urts_sim
	SGX_LAUNCH := sgx_launch_sim
	SGX_EPID := sgx_epid_sim
endif

CFLAGS := -m64 -std=c11 -Wall -Wextra -I.

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

APP_CFLAGS := $(CFLAGS) \
		-I$(IPAS_HOME)/include \
		-I$(USGX_HOME)/include \
		-I$(FOOSSL_INCLUDE) \
		-I$(SGX_SSL)/include \
		-I$(SGX_SDK)/include \
		-fPIC -Wno-attributes
APP_LDFLAGS := \
		-L$(IPAS_HOME)/lib \
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
		-lfoossl_server -lfoossl_common \
		-l$(SGX_URTS) -l$(SGX_LAUNCH) -l$(SGX_EPID) \
		-ldl -lssl -lcrypto \
		-lc -lcapnp_c -ljansson
else
APP_LDLIBS := \
		-lipas-attestation-normal \
		-lipas-sealing-normal \
		-lusgx-normal \
		-lsgx_usgxssl \
		-lfoossl_server -lfoossl_common \
		-l$(SGX_URTS) -l$(SGX_LAUNCH) -l$(SGX_EPID) \
		-ldl -lssl -lcrypto \
		-lc -lcapnp_c -ljansson
endif

all: css
	$(call GOOD,,"[  MAKE  ] ","$(notdir $^)")

################################################################
################################ MANAGEMENT
################################################################

.PHONY: clean

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
################################ APPLICATION
################################################################

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

OBJS := main.o css.capnp.o ssl.o rap/rap.o rap/network.o rap/serialization.o rap/cdecode.o rap/cencode.o rap/base64.o rap/rap.capnp.o

$(OBJS):
	@ $(CC) $(APP_CFLAGS) -c $< -o $@
	$(info [   CC   ] $^  >  $@)

css: $(OBJS)
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
		rap/rap.capnp.h rap/rap.capnp.c rap/rap.capnp.o \
		rap/base64.o rap/cencode.o rap/cdecode.o \
		rap/serialization.o rap/network.o rap/rap.o \
		ssl.o \
		css.capnp.h css.capnp.c css.capnp.o \
		main.o
clean:
	@rm -rf $(TRASH)
	$(call EVIL,,"[   RM   ] ",$(TRASH))
