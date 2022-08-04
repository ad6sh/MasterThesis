APPLICATION = list_test

RIOTBASE ?= $(CURDIR)/../..
	USEMODULE += netdev_default
	USEMODULE += auto_init_gnrc_netif

	USEMODULE += gnrc_ipv6_default
	USEMODULE += gnrc_icmpv6_echo

	USEMODULE += shell
	USEMODULE += shell_commands
	USEMODULE += ps

include $(RIOTBASE)/Makefile.include

