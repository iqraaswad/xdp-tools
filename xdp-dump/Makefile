# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
TOOL_NAME    := xdpdump
XDP_TARGETS  := xdpdump_bpf xdpdump_xdp
USER_TARGETS := xdpdump
TEST_FILE    := tests/test-xdpdump.sh

# MongoDB C Driver and BSON flags from pkg-config
MONGODB_CFLAGS := $(shell pkg-config --cflags libmongoc-1.0 libbson-1.0)
MONGODB_LIBS   := $(shell pkg-config --libs libmongoc-1.0 libbson-1.0)


# Disable warnings about VLAs not being at the end of a structure when building
# with clang. The code is fine, but clang's complaint coupled with -Werror would
# break the build. See https://github.com/xdp-project/xdp-tools/issues/304
# -Wno-gnu-variable-sized-type-not-at-end
CFLAGS 	     += "-fopenmp"
CFLAGS       += "-Wno-unused-variable"
CFLAGS       += "-Wno-unused-parameter"
CFLAGS       += "-Wno-unused-but-set-variable"
CFLAGS       += "-I."
CFLAGS       += "-Wno-gnu-variable-sized-type-not-at-end"
CFLAGS       += $(MONGODB_CFLAGS)

LIB_DIR       = ../lib
USER_LIBS     = -lpcap $(MONGODB_LIBS)
MAN_PAGE     := xdpdump.8

include $(LIB_DIR)/common.mk
