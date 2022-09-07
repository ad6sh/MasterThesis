APPLICATION = wot_cert_exchange_rd

RIOTBASE ?= $(CURDIR)/../../../../..

USEMODULE += doriot_wot_rd
EXTERNAL_MODULE_DIRS += $(CURDIR)/../../doriot_wot

USEMODULE += shell
USEMODULE += shell_commands
DEVELHELP ?= 1
#####################################################
CFLAGS += -DTHREAD_STACKSIZE_MAIN=\(2*THREAD_STACKSIZE_LARGE\)
#Crypto Cell signing requires more stack
CFLAGS += -DGCOAP_STACK_SIZE=\(3*THREAD_STACKSIZE_LARGE\)

#USEMODULE += lib_cryptocell
#ARCHIVES += $(RIOTBASE)/cpu/nrf52/cryptocell_lib/libnrf_cc310_0.9.12.a

# Increase from default for confirmable block2 follow-on requests
GCOAP_RESEND_BUFS_MAX ?= 2
CFLAGS += -DCONFIG_GCOAP_RESEND_BUFS_MAX=$(GCOAP_RESEND_BUFS_MAX)

include $(RIOTBASE)/Makefile.include
