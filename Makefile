all: build subdirs

build:
	docker run --rm -v $(HOME)/src/git-trees/reaperfish/:/rf golang:1.16.5 bash /rf/bin/build.sh
