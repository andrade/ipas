CC := gcc
EDGER := sgx_edger8r

# root dir pode vir de variável, ou de ficheiro buildenv.mk na root?
IPAS_HOME ?=
ifndef IPAS_HOME
$(error IPAS_HOME is not set)
endif
$(info [  HOME  ] "$(IPAS_HOME)")
IPAS_LIB_DIR := $(IPAS_HOME)/lib

PROJ_DIR = $(CURDIR)
$(info [PROJ_DIR] "$(PROJ_DIR)")

SGX_SDK ?= $(HOME)/.local/x86_64-linux-gnu/sgxsdk
$(info [SGX_SDK ] "$(SGX_SDK)")

SGX_DEBUG ?= 1
$(info [SGX_DEBUG] "$(SGX_DEBUG)")

USGX_HOME ?= $(HOME)/vc/usgx
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

CPPFLAGS := -I$(IPAS_HOME)/include -I$(USGX_HOME)/include
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

all: $(IPAS_LIB_DIR)/libipas-sealing-normal.a $(IPAS_LIB_DIR)/libipas-sealing-secure.a
	@echo "MAKE  ·  $^"

#                           UNTRUSTED                           #

u/sealing_u.c u/sealing_u.h: $(IPAS_HOME)/include/ipas/sealing.edl
	@$(EDGER) --untrusted $< --untrusted-dir u \
			--search-path $(USGX_HOME)/include \
			--search-path $(SGX_SDK)/include
	@echo "GEN   ·  $^  >  $@"

u/sealing.o: $(IPAS_HOME)/include/ipas/u/sealing.h u/sealing_u.h

u/%.o: u/%.c
	@$(CC) $(ULIB_CFLAGS) -c $< -o $@
	@echo "CC    ·  $^  >  $@"

$(IPAS_LIB_DIR)/libipas-sealing-normal.a: u/sealing.o u/sealing_u.o
	@mkdir -p $(IPAS_LIB_DIR)
	@ar rcs $@ $^
	$(call GOOD,,"GEN   ·  ","$^  >  $@")

#                            TRUSTED                            #

t/sealing_t.c t/sealing_t.h: $(IPAS_HOME)/include/ipas/sealing.edl
	@$(EDGER) --trusted $< --trusted-dir t \
			--search-path $(USGX_HOME)/include \
			--search-path $(SGX_SDK)/include
	@echo "GEN   ·  $^  >  $@"

t/sealing.o: t/sealing_t.h

t/%.o: t/%.c
	@$(CC) $(TLIB_CFLAGS) -c $< -o $@
	@echo "CC    ·  $^  >  $@"

$(IPAS_LIB_DIR)/libipas-sealing-secure.a: t/sealing.o t/sealing_t.o
	@mkdir -p $(IPAS_LIB_DIR)
	@ar rcs $@ $^
	$(call GOOD,,"GEN   ·  ","$^  >  $@")

#                          MAINTENANCE                          #

.PHONY: clean

TRASH := \
		u/sealing_u.h u/sealing_u.c u/sealing_u.o \
		u/sealing.o \
		$(IPAS_LIB_DIR)/libipas-sealing-normal.a \
		t/sealing_t.h t/sealing_t.c t/sealing_t.o \
		t/sealing.o \
		$(IPAS_LIB_DIR)/libipas-sealing-secure.a

clean:
	@rm -rf $(TRASH)
	@rmdir --ignore-fail-on-non-empty $(IPAS_LIB_DIR) 2> /dev/null || true
	$(call EVIL,"CLEAN ·  Remove: ",$(TRASH),)
