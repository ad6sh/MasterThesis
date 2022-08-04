APPLICATION = wot_cert_exchange_rd

RIOTBASE ?= $(CURDIR)/../../../../..

USEMODULE += doriot_wot_rd
#EXTERNAL_MODULE_DIRS += doriot_wot
EXTERNAL_MODULE_DIRS += $(CURDIR)/../../doriot_wot

CFLAGS += -DTHREAD_STACKSIZE_MAIN=\(2*THREAD_STACKSIZE_LARGE\)

include $(RIOTBASE)/Makefile.include
