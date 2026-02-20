# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2010-2014 Intel Corporation

# Nombre del binario
APP = dpdk-l2fwd

# Archivos fuente
SRCS-y := sonda-dpdk.c

# Carpeta de objetos
OBJDIR = build/objects
CONN_OBJ = $(OBJDIR)/connectionTable.o

# Configuración de pkg-config para DPDK
PC_FILE := $(shell pkg-config --path libdpdk 2>/dev/null)
CFLAGS += -O3 $(shell pkg-config --cflags libdpdk)
LDFLAGS_SHARED = $(shell pkg-config --libs libdpdk)
LDFLAGS_STATIC = $(shell pkg-config --static --libs libdpdk)

# Si queremos linkado estático, descomenta la siguiente línea
# LDFLAGS = $(LDFLAGS_STATIC)
LDFLAGS = $(LDFLAGS_SHARED)

#CFLAGS += -DALLOW_EXPERIMENTAL_API

build/$(APP): $(SRCS-y) $(CONN_OBJ) Makefile $(PC_FILE)
	@mkdir -p build
	$(CC) $(CFLAGS) $(SRCS-y) $(CONN_OBJ) -o $@ $(LDFLAGS)

$(CONN_OBJ): modules/connectionTable.c modules/connectionTable.h
	@mkdir -p $(OBJDIR)
	$(CC) $(CFLAGS) -c modules/connectionTable.c -o $@
