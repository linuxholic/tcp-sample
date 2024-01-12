# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

ifeq ("$(origin V)", "command line")
VERBOSE = $(V)
endif
ifndef VERBOSE
VERBOSE = 0
endif

ifeq ($(VERBOSE),0)
MAKEFLAGS += --no-print-directory
Q = @
endif

.PHONY: clean clobber distclean src

all: lib src

clean:
	@echo; echo common; $(MAKE) -C common clean
	@echo; echo lib; $(MAKE) -C lib clean
	@echo; echo src; $(MAKE) -C src clean

lib: config.mk check_submodule
	@echo; echo $@; $(MAKE) -C $@

src:
	@echo; echo $@; $(MAKE) -C $@

config.mk: configure
	@sh configure

clobber:
	@touch config.mk
	$(Q)$(MAKE) clean
	$(Q)rm -f config.mk

distclean:	clobber

check_submodule:
	@if [ -d .git ] && `git submodule status lib/libbpf | grep -q '^+'`; then \
		echo "" ;\
		echo "** WARNING **: git submodule SHA-1 out-of-sync" ;\
		echo " consider running: git submodule update"  ;\
		echo "" ;\
	fi\

