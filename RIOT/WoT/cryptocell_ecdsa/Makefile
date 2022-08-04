# This has to be the absolute path to the RIOT base directory:
RIOTBASE ?= $(CURDIR)/../..

APPLICATION = crypto-ewsn2020_ecdsa_cryptocell

CFLAGS += -DTHREAD_STACKSIZE_MAIN=\(12*THREAD_STACKSIZE_DEFAULT\)

ifeq (1, $(TEST_ENERGY))
	CFLAGS += -DTEST_ENERGY=1
endif

ifeq (1, $(TEST_MEM))
	CFLAGS += -DTEST_MEM=1
else
	ifeq (1, $(TEST_STACK))
		CFLAGS+=-DTEST_STACK=1
		USEMODULE += ps
		CFLAGS +=-DDEVELHELP=1
	else
		USEMODULE += xtimer
		FEATURES_REQUIRED += periph_gpio
	endif
endif

USEMODULE += lib_cryptocell

ARCHIVES += $(RIOTBASE)/cpu/nrf52/cryptocell_lib/libnrf_cc310_0.9.12.a

include $(RIOTBASE)/Makefile.include
