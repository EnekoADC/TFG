# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2010-2014 Intel Corporation

# Nombre del binario
APP = l2fwd

# Archivos fuente
SRCS-y := l2fwd.c

# Configuración de pkg-config para DPDK
PC_FILE := $(shell pkg-config --path libdpdk 2>/dev/null)
CFLAGS += -O3 $(shell pkg-config --cflags libdpdk)
LDFLAGS_SHARED = $(shell pkg-config --libs libdpdk)
LDFLAGS_STATIC = $(shell pkg-config --static --libs libdpdk)

# Si queremos linkado estático, descomenta la siguiente línea
# LDFLAGS = $(LDFLAGS_STATIC)
LDFLAGS = $(LDFLAGS_SHARED)

CFLAGS += -DALLOW_EXPERIMENTAL_API

build/$(APP): $(SRCS-y) makefile $(PC_FILE)
	@mkdir -p build
	$(CC) $(CFLAGS) $(SRCS-y) -o $@ $(LDFLAGS)

.PHONY: clean
clean:
	rm -f build/$(APP)
	test -d build && rmdir -p build || true
