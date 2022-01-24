all: build subdirs

USER=jglauber
#TARGETS=s2r5node53.s2r5.internal.digitalocean.com s2r8node74.s2r8.internal.digitalocean.com
TARGETS=s2r5node68.s2r5.internal.digitalocean.com

# was: awesome-go-container, not needed if I don't need modifications (for bpf)
# dead: --dns 10.254.0.3
build:
	docker run --rm -v $(HOME)/src/git-trees/cthulhu:/cthulhu -v $(HOME)/.cthulhu_bash_history:/root/.bash_history --network=host golang:1.16.5 bash /cthulhu/docode/bin/build.sh

install:
	@for target in $(TARGETS); do \
		scp -o "ProxyCommand ssh $(USER)@s2-jump -W %h:%p" $(HOME)/src/git-trees/cthulhu/reaper $(USER)@$$target:;\
	done

SUBDIRS = bpf
subdirs:
	@for dir in $(SUBDIRS); do \
        	$(MAKE) -C $$dir; \
	done
