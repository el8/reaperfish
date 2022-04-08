all: build subdirs

SHELL=/bin/bash

UID := $(shell id -u)
GID := $(shell id -g)

SOURCE="src/git-trees/reaperfish/src/reaper"
SCRIPT="src/git-trees/reaperfish/script"

build:
	docker run --rm --user $(UID):$(GID) --network=host -v $(HOME)/$(SOURCE):/rf -v $(HOME)/$(SCRIPT):/script golang:latest bash /script/build.sh

shell:
	docker run --rm -it --user $(UID):$(GID) --network=host -e "PS1=DEBUG$(pwd)# " -v $(HOME)/$(SOURCE):/rf -v $(HOME)/$(SCRIPT):/script golang:latest /bin/bash
