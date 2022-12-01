ROOT_DIR := $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
BIN_DIR := bin
SUBMODULE_DIR := $(realpath $(ROOT_DIR)/submodules)

ifneq (,$(DEBUG))
  DEBUG_CFLAGS = -g -O0
endif

CFLAGS += $(DEBUG_CFLAGS) -Wall -pedantic -Wextra
#CFLAGS += -Wno-unused-variable -Wno-unused-function

LDFLAGS += -L lib
MBEDTLS_LIBS = -lmbedtls -lmbedx509 -lmbedcrypto
NANOCBOR_LIBS = -lencoder -ldecoder

all: c509 c509conv common mbedtls_ecp_compression

-include c509/Makefile.include
-include c509/Makefile.dep
-include common/Makefile.include
-include common/Makefile.dep
-include mbedtls_ecp_compression/Makefile.include
-include mbedtls_ecp_compression/Makefile.dep

include app/c509conv/Makefile
include c509/Makefile
include common/Makefile
include mbedtls_ecp_compression/Makefile

clean:
	rm -rf $(BIN_DIR)
