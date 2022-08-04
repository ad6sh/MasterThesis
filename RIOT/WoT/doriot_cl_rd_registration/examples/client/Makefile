APPLICATION = wot_cert_exchange_cl

RIOTBASE ?= $(CURDIR)/../../../..

USEMODULE += doriot_wot_cl
#EXTERNAL_MODULE_DIRS += doriot_wot
EXTERNAL_MODULE_DIRS += $(CURDIR)/../../doriot_wot

CFLAGS += -DTHREAD_STACKSIZE_MAIN=\(2*THREAD_STACKSIZE_LARGE\)

# Increase from default for confirmable block2 follow-on requests
GCOAP_RESEND_BUFS_MAX ?= 2
CFLAGS += -DCONFIG_GCOAP_RESEND_BUFS_MAX=$(GCOAP_RESEND_BUFS_MAX)

include $(RIOTBASE)/Makefile.include
