# name of your application
APPLICATION = lorawan

# Use the ST B-L072Z-LRWAN1 board by default:
BOARD ?= b-l072z-lrwan1

# This has to be the absolute path to the RIOT base directory:
RIOTBASE ?= $(CURDIR)/../..

DEVEUI ?= 0000000000000000
APPEUI ?= 0000000000000000
APPKEY ?= 00000000000000000000000000000000

# Pass these enviroment variables to docker
DOCKER_ENV_VARS += DEVEUI
DOCKER_ENV_VARS += APPEUI
DOCKER_ENV_VARS += APPKEY

# Default radio driver is Semtech SX1276 (used by the B-L072Z-LRWAN1 board)
DRIVER ?= sx1276

# Default region is Europe and default band is 868MHz
LORA_REGION ?= EU868

# Include the Semtech-loramac package
USEPKG += semtech-loramac

USEMODULE += $(DRIVER)
USEMODULE += fmt
FEATURES_OPTIONAL += periph_rtc

# Comment this out to disable code in RIOT that does safety checking
# which is not needed in a production environment but helps in the
# development process:
DEVELHELP ?= 1

# Change this to 0 show compiler invocation lines by default:
QUIET ?= 1

# Default IotLab Config to run the test
ifneq (,$(filter iotlab%,$(MAKECMDGOALS)))
  IOTLAB_NODES ?= 1
  IOTLAB_TYPE  ?= st-lrwan1:sx1276
  IOTLAB_SITE  ?= saclay
  include $(RIOTBASE)/dist/testbed-support/Makefile.iotlab
endif

ifneq (,$(filter test,$(MAKECMDGOALS)))
  DEFAULT_MODULE += test_utils_interactive_sync
endif

include $(RIOTBASE)/Makefile.include

ifndef CONFIG_KCONFIG_USEMODULE_LORAWAN
  # OTAA compile time configuration keys
  CFLAGS += -DCONFIG_LORAMAC_APP_KEY_DEFAULT=\"$(APPKEY)\"
  CFLAGS += -DCONFIG_LORAMAC_APP_EUI_DEFAULT=\"$(APPEUI)\"
  CFLAGS += -DCONFIG_LORAMAC_DEV_EUI_DEFAULT=\"$(DEVEUI)\"
endif
