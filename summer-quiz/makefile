INCONTAINER:=$(shell test -f /.dockerenv && echo 1 || echo 0)
IMAGE=gcc-debian:latest

ifeq ($(INCONTAINER), 0)
	DOCKERIT=docker run --rm -it --ulimit core=-1 --privileged -v $(shell pwd):/usr/src/myapp -w /usr/src/myapp $(IMAGE)
	DOCKER=docker run --rm -v $(shell pwd):/usr/src/myapp -w /usr/src/myapp $(IMAGE)
endif


clean:
	find . -type f -executable -exec rm -rf '{}' \;
	rm -rf core

04-concurrent: 04-concurrent.c
	$(DOCKER) gcc -g -O0 -Wall -std=c11 -o $@ $< -lpthread

04-run: 04-concurrent
	$(DOCKER) ./04-concurrent

valgrind: 04-concurrent
	valgrind --leak-check=yes ./$<

console:
	$(DOCKERIT) /bin/bash

gcc-debian: Dockerfile
	docker build -t $@:latest .

05-memory-pool: 05-memory-pool.c 
	gcc -g -ggdb3 -O0 -Wall -o $@ $<

06-proxy: 06-proxy.c
	gcc -g -ggdb3 -O0 -Wall -o $@ $<

01-bitwise-rotation: 01-bitwise-rotation.c
	gcc -g -ggdb3 -std=c11 -O0 -Wall -o $@ $<
