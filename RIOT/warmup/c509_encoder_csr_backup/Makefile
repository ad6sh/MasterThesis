APPLICATION = c509_encoder

#CFLAGS += -DTHREAD_STACKSIZE_MAIN=2*THREAD_STACKSIZE_LARGE
#modules for wolfssl
USEPKG += wolfssl

USEMODULE += wolfssl
USEMODULE += wolfssl_socket
USEMODULE += wolfssl_crl
USEMODULE += wolfssl_all


USEMODULE += wolfcrypt  
USEMODULE += wolfcrypt_ecc 
USEMODULE += wolfcrypt_asn

USEMODULE += wolfcrypt-test
#USEMODULE += wolfcrypt_ed25519


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

CFLAGS += -DWOLFSSL_CERT_REQ #needed other wise pem  to der doesnt work ?
#CFLAGS += -DWOLFSSL_TEST_CERT

#CFLAGS += -DWOLFSSL_CERT_GEN
#CFLAGS += -DWOLFSSL_KEY_GEN
#CFLAGS += -DWOLFSSL_SP_MATH
#CFLAGS += -DWOLFSSL_CERT_EXT

#CFLAGS += -DHAVE_ED25519
CFLAGS += -DDEBUG_WOLFSSL

#CFLAGS += -DWOLFSSL_USER_SETTINGS

#CFLAGS += -DWOLFSSL_PUBLIC_MP
#CFLAGS += -DOPENSSL_EXTRA
#CFLAGS  +=  -DWOLFSSL_DEBUG_ASN_TEMPLATE
#CFLAGS  +=  -DWOLFSSL_ASN_TEMPLATE
#CFLAGS  +=  -DWOLFSSL_NO_TRUSTED_CERTS_VERIFY
#CFLAGS  +=  -DIGNORE_NAME_CONSTRAINTS



ifneq ($(BOARD),native)
  CFLAGS += -DBENCH_EMBEDDED
endif

RIOTBASE ?= $(CURDIR)/../..
include $(RIOTBASE)/Makefile.include
