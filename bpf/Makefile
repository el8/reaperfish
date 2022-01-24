all: build fix

OBJS = reaper-log.bpf.o reaper-hist.bpf.o
build: $(OBJS)

$(OBJS):  %.o:%.c
	clang -D__KERNEL__ -D__ASM_SYSREG_H \
		-Wno-unused-value -Wno-pointer-sign -Wno-compare-distinct-pointer-types -Wno-unknown-attributes \
		-Wno-int-to-void-pointer-cast -Wno-implicit-function-declaration -Wno-int-conversion \
		-Wno-gnu-variable-sized-type-not-at-end \
		-Wno-address-of-packed-member -Wno-tautological-compare \
		-Wno-unknown-warning-option \
		-I ./include -O2 -emit-llvm \
		-c -g $< -o -| llc -march=bpf -filetype=obj -o $@
	llvm-strip -g $@

# workaround for: panic: program ...: load BTF: invalid argument: magic: 0xeb9f
# https://github.com/cilium/ebpf/issues/43
fix:
	llvm-strip reaper-log.bpf.o --no-strip-all -R .BTF
	llvm-strip reaper-hist.bpf.o --no-strip-all -R .BTF

clean:
	@rm $(OBJS)
