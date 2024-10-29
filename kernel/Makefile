# SPDX-License-Identifier: GPL-2.0

KDIR ?= /lib/modules/`uname -r`/build

default:
	$(MAKE) -C $(KDIR) M=$$PWD 

rust-analyzer:
	$(MAKE) -C $(KDIR) M=$$PWD rust-analyzer
