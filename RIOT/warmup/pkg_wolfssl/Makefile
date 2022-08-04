#include ../Makefile.tests_common

APPLICATION = wolfssl_parse_test
# This is an optimized stack value based on testing, if you observe
# a segmentation fault please increase this stack size.
CFLAGS += -DTHREAD_STACKSIZE_MAIN=2*THREAD_STACKSIZE_LARGE

USEPKG += wolfssl
USEMODULE += wolfssl
USEMODULE += wolfcrypt wolfcrypt-test wolfcrypt_sha512 \
             wolfcrypt_curve25519 wolfcrypt_ed25519 wolfcrypt_chacha \
             wolfcrypt_poly1305 wolfcrypt_aes wolfcrypt_ecc \
             wolfcrypt_asn wolfcrypt_random  wolfcrypt_rsa

USEMODULE += wolfcrypt_hmac
USEMODULE += wolfcrypt_md5



#USEMODULE += wolfssl_socket

#USEMODULE += gnrc_sock_udp
#USEMODULE += wolfssl_dtls

#USEMODULE += wolfssl_psk
#USEMODULE += wolfssl_socket
#USEMODULE += wolfssl_test
#USEMODULE += wolfssl_dtls
#USEMODULE += wolfcrypt_ecc

#CFLAGS += -DWOLFSSL_USER_SETTINGS=1
#CFLAGS += -DWOLFSSL_RIOT_OS=1


# NOTE: 6LoWPAN wi
#USEMODULE += wolfcrypt_rsa wolfcrypt_dh
#USEMODULE += wolfssl_psk
#USEMODULE += netdev_default
#USEMODULE += auto_init_gnrc_netif
# Specify the mandatory networking modules for IPv6 and UDP
USEMODULE += gnrc_ipv6_default
USEMODULE += sock_udp

#USEMODULE += wolfssl_wolfio
#USEMODULE += wolfssl_ssl
USEMODULE += wolfssl_internal
#USEMODULE += wolfssl_keys
#USEMODULE += wolfssl_tls


# Uncomment the following line to enable RSA tests
# (e.g. when enough resources are available on platform)
USEMODULE += wolfcrypt_rsa wolfcrypt_dh

# Comment the following line to disable full-benchmark test
#USEMODULE += wolfcrypt-benchmark

#USEMODULE += xtimer
CFLAGS +=  -DOPENSSL_EXTRA_X509_SMALL
CFLAGS += -DOPENSSL_EXTRA
CFLAGS += -DOPENSSL_COEXIST
CFLAGS += -DCONFIG_INTERNAL_LIBTOMMATH
#CFLAGS  += -DWOLFSSL_TEST_CERT


#USEPKG += cn-cbor
#USEMODULE += embunit
#USEMODULE += fmt
#USEMODULE += memarray

ifneq ($(BOARD),native)
  CFLAGS += -DBENCH_EMBEDDED
  #CFLAGS += -DCONFIG_INTERNAL_LIBTOMMATH
endif

TEST_ON_CI_WHITELIST += native

RIOTBASE ?= $(CURDIR)/../..

include $(RIOTBASE)/Makefile.include
