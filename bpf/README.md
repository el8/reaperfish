# Build the Dockerfile

    docker build -t ebpf-build:latest .

# Prepare the ebpf object build to match the target kernel

## on target HV run:
   bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h-`uname -r`
## copy the resulting vmlinux file to bpf/include and symlink it as vmlinux.h

# Run the Dockerfile

## Build all the eBPF programs:

    run script/build-all.sh

## or to build a specific eBPF:

    create vmlinux.h symlink under include/
    docker run -v $(pwd)/bpf:/bpf -it ebpf-build

## To get a shell:

    docker run -v $(pwd)/bpf:/bpf -it ebpf-build /bin/bash
