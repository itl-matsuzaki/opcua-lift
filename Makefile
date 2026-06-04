# Standalone Makefile for opcua-lift — OPC UA stateful corpus replay tool.
#
# No AFLNet checkout required.  Two translation units + a libc allocator shim:
#   opcua-lift.c   the stateful replay driver (handshake + framing + send)
#   opcua_state.c  extract_response_codes_opcua(), lifted from aflnet.c
#   alloc-shim.h   ck_alloc/ck_realloc/ck_free over libc malloc
#
# Build:        make
# Clean:        make clean
# Sanitizer:    make SANITIZE=1     (ASan+UBSan — handy when the *target* server
#                                    is also built with ASan, to mirror timing)

CC      ?= cc
CFLAGS  ?= -O2 -g -Wall -Wextra
LDFLAGS ?=

ifdef SANITIZE
CFLAGS  += -fsanitize=address,undefined -fno-omit-frame-pointer
LDFLAGS += -fsanitize=address,undefined
endif

OBJS = opcua-lift.o opcua_state.o

all: opcua-lift

opcua-lift: $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $@ $(LDFLAGS)

opcua-lift.o: opcua-lift.c alloc-shim.h
	$(CC) $(CFLAGS) -c opcua-lift.c -o $@

opcua_state.o: opcua_state.c alloc-shim.h
	$(CC) $(CFLAGS) -c opcua_state.c -o $@

clean:
	rm -f opcua-lift $(OBJS)

.PHONY: all clean
