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

CFLAGS += -DWOLFSSL_CERT_REQ #needed other wise pem  to der doesnt work ?
CFLAGS += -DWOLFSSL_CERT_GEN
CFLAGS += -DHAVE_ECC 
#CFLAGS += -DOPENSSL_EXTRA_X509_SMALL  #wolfcrypt/types.h:497:31: error: implicit declaration of function ‘snprintf’
CFLAGS += -DWOLFSSL_TEST_CERT #for InitDecodedCert,ParseCert etc

# A larger stack size is required if using ECC or RSA
CFLAGS += -DTHREAD_STACKSIZE_MAIN=2*THREAD_STACKSIZE_LARGE
CFLAGS += -Wno-unused-parameter -Wno-unused-variable
CFLAGS += -DNO_VERIFY_OID

#WOLF_INSTALL_DIR ?= $(CURDIR)/../../build/pkg/wolfssl/wolfssl
#CFLAGS += -I$(WOLF_INSTALL_DIR)/include -Wall


ifneq ($(BOARD),native)
  CFLAGS += -DBENCH_EMBEDDED
endif

RIOTBASE ?= $(CURDIR)/../..
include $(RIOTBASE)/Makefile.include
