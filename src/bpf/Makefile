all: build

BUILDDIR = ../../build
OBJS = reaper-log.bpf.o reaper-hist.bpf.o
build: $(OBJS)

CLANG ?= clang
LLC ?= llc
OPT ?= opt
LLVM_DIS ?= llvm-dis
LLC_FLAGS += -mattr=dwarfris

$(OBJS):  %.o:%.c
	$(CLANG) -D__KERNEL__ -D__ASM_SYSREG_H -D__BPF_TRACING__ \
		-Wno-unused-value -Wno-pointer-sign -Wno-compare-distinct-pointer-types -Wno-unknown-attributes \
		-Wno-int-to-void-pointer-cast -Wno-implicit-function-declaration -Wno-int-conversion \
		-Wno-gnu-variable-sized-type-not-at-end \
		-Wno-address-of-packed-member -Wno-tautological-compare \
		-Wno-unknown-warning-option \
		-fno-stack-protector -fno-jump-tables -fno-unwind-tables -fno-asynchronous-unwind-tables \
		-xc \
		-I ./include -I /libbpf/src/root/usr/include \
		-g -O2 \
		-target bpf -emit-llvm -Xclang -disable-llvm-passes \
		-c $< -o - | \
		$(OPT) -O2 -mtriple=bpf-pc-linux | $(LLVM_DIS) | \
		$(LLC) -march=bpf $(LLC_FLAGS) -filetype=obj -o $(BUILDDIR)/$@
	llvm-strip -g $(BUILDDIR)/$@
# workaround for: panic: program ...: load BTF: invalid argument: magic: 0xeb9f
# https://github.com/cilium/ebpf/issues/43
#	llvm-strip $(BUILDDIR)/$@ --no-strip-all -R .BTF

clean:
	@rm $(OBJS)
