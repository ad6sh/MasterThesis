APPLICATION = c509_encoder
#modules for wolfssl
USEPKG += wolfssl

USEMODULE += wolfssl
USEMODULE += wolfssl_socket

USEMODULE += wolfcrypt  
USEMODULE += wolfcrypt_ecc 
USEMODULE += wolfcrypt_asn

# Specify the mandatory networking modules for IPv6 and UDP
USEMODULE += gnrc_ipv6_default
USEMODULE += sock_udp
USEMODULE += gnrc_sock_udp

#modules for riot shell
USEMODULE += shell
USEMODULE += shell_commands
USEMODULE += ps

#modules for cbor encoding
USEPKG += tinycbor
USEMODULE += tinycbor_float

CFLAGS += -DDEBUG_ASSERT_VERBOSE
CFLAGS += -DDEBUG_WOLFSSL


ifneq ($(BOARD),native)
  CFLAGS += -DBENCH_EMBEDDED
endif

RIOTBASE ?= $(CURDIR)/../..
include $(RIOTBASE)/Makefile.include
