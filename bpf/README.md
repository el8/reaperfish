# Build the Dockerfile

    docker build -t ebpf-build:latest .

# Run the Dockerfile

## Build all the eBPF programs:

    run script/build-all.sh

## or to build a specific eBPF:

    bpftool btf dump file /sys/kernel/btf/vmlinux format c > include/vmlinux.h-`uname -r`
    create vmlinux.h symlink under include/
    docker run -v $(pwd)/bpf:/bpf -it ebpf-build

## To get a shell:

    docker run -v $(pwd)/bpf:/bpf -it ebpf-build /bin/bash
