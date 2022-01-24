#!/bin/bash
set -e

cd ..
for i in `ls include/vmlinux.h-*-generic`
do
	VERSION=${i:18}
	echo "building bpf for kernel $VERSION"
	ln -sr $PWD/$i $PWD/include/vmlinux.h
	docker run -v $PWD:/bpf -it ebpf-build
	mv reaperfish.bpf.o reaperfish.bpf.o-$VERSION
	rm -f $PWD/include/vmlinux.h
done
