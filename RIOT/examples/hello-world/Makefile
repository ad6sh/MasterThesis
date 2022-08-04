# name of your application
APPLICATION = hello-world

# If no BOARD is found in the environment, use this default:
BOARD ?= native

# This has to be the absolute path to the RIOT base directory:
RIOTBASE ?= $(CURDIR)/../..

#USEMODULE += netdev_default
#USEMODULE += auto_init_gnrc_netif
#USEMODULE += gnrc_ipv6_default
#USEMODULE += gcoap
#USEMODULE += od
#USEPKG += tinycbor
#USEMODULE += tinycbor_float	
#USEMODULE += hashes
#USEMODULE += crypto_aes_256
#USEPKG += micro-ecc
USEMODULE += lib_cryptocell
ARCHIVES += $(RIOTBASE)/cpu/nrf52/cryptocell_lib/libnrf_cc310_0.9.12.a

# Comment this out to disable code in RIOT that does safety checking
# which is not needed in a production environment but helps in the
# development process:
DEVELHELP ?= 1

# Change this to 0 show compiler invocation lines by default:
QUIET ?= 1

include $(RIOTBASE)/Makefile.include
