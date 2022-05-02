all: build-bpf build-go

build-bpf:
	make -C src/bpf
build-go:
	go build -o build/reaperfish src/go/reaper.go

