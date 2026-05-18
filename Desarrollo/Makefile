# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2010-2014 Intel Corporation

# Nombre del binario
APP := ip-lock

# Archivos fuente
SRCS-y := ip-lock.c
SNIPPET := snippet_match_ipv4_block

# Carpeta de objetos
OBJDIR = build/objects
FLOW_SK_OBJ = $(OBJDIR)/flow_skeleton.o
SNIPPET_OBJ = $(OBJDIR)/snippets/$(SNIPPET).o
IP_BLOCK_OBJ = $(OBJDIR)/ipBlocker.o

# Configuración de pkg-config para DPDK
PC_FILE := $(shell pkg-config --path libdpdk 2>/dev/null)
CFLAGS += -O3 $(shell pkg-config --cflags libdpdk)
LDFLAGS_SHARED = $(shell pkg-config --libs libdpdk)
LDFLAGS_STATIC = $(shell pkg-config --static --libs libdpdk)

# Si queremos linkado estático, descomenta la siguiente línea
# LDFLAGS = $(LDFLAGS_STATIC)
LDFLAGS = $(LDFLAGS_SHARED)

CFLAGS += -DALLOW_EXPERIMENTAL_API

build/$(APP): $(SRCS-y) $(IP_BLOCK_OBJ) $(FLOW_SK_OBJ) $(SNIPPET_OBJ) Makefile $(PC_FILE)
	@mkdir -p build
	$(CC) $(CFLAGS) $(SRCS-y) $(FLOW_SK_OBJ) $(SNIPPET_OBJ) $(IP_BLOCK_OBJ) -o $@ $(LDFLAGS) -g

$(FLOW_SK_OBJ): modules/flow_skeleton.c modules/common.h
	@mkdir -p $(OBJDIR)
	$(CC) $(CFLAGS) -c modules/flow_skeleton.c -o $@


$(SNIPPET_OBJ): modules/snippets/$(SNIPPET).c modules/snippets/$(SNIPPET).h
	@mkdir -p $(OBJDIR)/snippets
	$(CC) $(CFLAGS) -c modules/snippets/$(SNIPPET).c -o $@


$(IP_BLOCK_OBJ): modules/ipBlocker.c modules/ipBlocker.h
	@mkdir -p $(OBJDIR)
	$(CC) $(CFLAGS) -c modules/ipBlocker.c -o $@
