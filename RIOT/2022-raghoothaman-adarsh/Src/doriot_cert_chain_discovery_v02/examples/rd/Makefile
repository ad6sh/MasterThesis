APPLICATION = wot_cert_exchange_rd

RIOTBASE ?= $(CURDIR)/../../../../..

USEMODULE += doriot_wot_rd
EXTERNAL_MODULE_DIRS += $(CURDIR)/../../doriot_wot

USEMODULE += shell
USEMODULE += shell_commands
#######following modules are for evaluation##########
#USEMODULE += ps
#USEMODULE += schedstatistics
#USEMODULE += gnrc_icmpv6_echo
DEVELHELP ?= 1
#####################################################
#CFLAGS += -DTHREAD_STACKSIZE_MAIN=\(2*THREAD_STACKSIZE_LARGE\)
CFLAGS += -DGCOAP_STACK_SIZE=THREAD_STACKSIZE_LARGE

BLOBS += blob_keys/private_key blob_keys/public_key blob_keys/psk

# Increase from default for confirmable block2 follow-on requests
GCOAP_RESEND_BUFS_MAX ?= 2
CFLAGS += -DCONFIG_GCOAP_RESEND_BUFS_MAX=$(GCOAP_RESEND_BUFS_MAX)

include $(RIOTBASE)/Makefile.include
