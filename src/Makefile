# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

XDP_TARGETS := xdp_sample_pkts_kern
USER_TARGETS := xdp_sample_pkts_user
LDLIBS+=-lpcap -lpthread

COMMON_DIR = ../common

include $(COMMON_DIR)/common.mk
COMMON_OBJS := $(COMMON_DIR)/common_params.o
