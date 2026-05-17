CLANG      ?= clang
CC         ?= gcc
ARCH       := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

BUILD      := build
SRC_BPF    := src/bpf
SRC_LOADER := src/loader

BPF_CFLAGS  := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -I.
CFLAGS      := -g -Wall
LDFLAGS     := -lbpf -lelf -lz

# Try pkg-config for libbpf includes
LIBBPF_INC := $(shell pkg-config --cflags-only-I libbpf 2>/dev/null)
ifneq ($(LIBBPF_INC),)
  BPF_CFLAGS += $(LIBBPF_INC)
else
  # Fallback: search common kernel header paths
  KVER := $(shell uname -r)
  FALLBACK := /usr/src/linux-headers-$(KVER)/tools/bpf/resolve_btfids/libbpf/include
  ifneq ($(wildcard $(FALLBACK)/bpf/bpf_helpers.h),)
    BPF_CFLAGS += -I$(FALLBACK)
  endif
endif

.PHONY: all clean vmlinux test_reader

all: $(BUILD) vmlinux.h $(BUILD)/lid.bpf.o $(BUILD)/lid_loader

$(BUILD):
	@mkdir -p $(BUILD)

vmlinux.h:
	@echo "[*] Generating vmlinux.h from kernel BTF..."
	@bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

$(BUILD)/lid.bpf.o: $(SRC_BPF)/lid.bpf.c vmlinux.h | $(BUILD)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(BUILD)/lid_loader: $(SRC_LOADER)/lid_loader.c | $(BUILD)
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

test_reader: tests/test_reader.c | $(BUILD)
	$(CC) -Wall -o $(BUILD)/test_reader $<

clean:
	rm -rf $(BUILD) vmlinux.h
