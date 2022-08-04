APPLICATION = list_test

RIOTBASE ?= $(CURDIR)/../..

	USEPKG += tinycbor
	USEMODULE += tinycbor_float	

	# include sha256 (used by example blockwise handler)
	USEMODULE += hashes

	USEPKG += micro-ecc

	USEMODULE += crypto_aes_256

	USEMODULE += shell
	USEMODULE += shell_commands
	USEMODULE += ps

	USEMODULE += od

include $(RIOTBASE)/Makefile.include

