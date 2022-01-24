all: build subdirs

# was: awesome-go-container, not needed if I don't need modifications (for bpf)
build:
	docker run --rm -v $(HOME)/src/git-trees/cthulhu:/cthulhu -v $(HOME)/.cthulhu_bash_history:/root/.bash_history --network=host golang:1.16.5 bash /cthulhu/docode/bin/build.sh

SUBDIRS = bpf
subdirs:
	@for dir in $(SUBDIRS); do \
        	$(MAKE) -C $$dir; \
	done
