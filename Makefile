all: build-go

build-go:
	go build -o build/reaper src/go/reaper.go
	make -C src/bpf

