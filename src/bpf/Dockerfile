FROM ubuntu:focal
RUN apt-get update && apt-get install -y \
	build-essential \
	clang \
	llvm \
	git \
	libelf-dev \
	&& rm -rf /var/lib/apt/lists/*

RUN ln -s /usr/include/asm-generic /usr/include/asm
RUN git clone --depth 1 --branch v0.4.0 https://github.com/libbpf/libbpf.git
WORKDIR /libbpf/src
RUN mkdir build root
RUN BUILD_STATIC_ONLY=y OBJDIR=build DESTDIR=root make install
CMD make -C /bpf
