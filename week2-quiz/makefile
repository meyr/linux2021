INCONTAINER:=$(shell test -f /.dockerenv && echo 1 || echo 0)
IMAGE=gcc-debian:latest

ifeq ($(INCONTAINER), 0)
        DOCKERIT=docker run --rm -it -u $(id -u):$(id -g) \
                        -v ${shell pwd}:/usr/src/myapp \
                        -v /etc/passwd:/etc/passwd \
                        -v /etc/group:/etc/group \
                        -w /usr/src/myapp \
						--ulimit core=-1 --privileged \
                        ${IMAGE}

        DOCKER=docker run --rm -u $(id -u):$(id -g) \
                        -v ${shell pwd}:/usr/src/myapp \
                        -v /etc/passwd:/etc/passwd \
                        -v /etc/group:/etc/group \
                        -w /usr/src/myapp \
                        ${IMAGE}

endif


clean:
	find . -type f -executable -exec rm -rf '{}' \;
	rm -rf core

list: list.c
	$(DOCKER) gcc -Wall -o $@ $^ -lpthread -g -fsanitize=thread 
