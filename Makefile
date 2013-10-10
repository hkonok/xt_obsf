MODULES_DIR := /lib/modules/$(shell uname -r)
KERNEL_DIR := ${MODULES_DIR}/build
EXTRA_CFLAGS = -g -O2 -Wall

obj-m += xt_OBSF.o

all:
	make -C ${KERNEL_DIR} M=$$PWD;

modules:
	make -C ${KERNEL_DIR} M=$$PWD $@;

modules_install:
	make -C ${KERNEL_DIR} M=$$PWD $@;
clean:
	make -C ${KERNEL_DIR} M=$$PWD $@;
#build script for userspace plugin

lib%.so:lib%.o
	gcc -shared -fPIC -o $@ $^;
lib%.o:lib%.c
	gcc ${EXTRA_CFLAGS} -DINIT=lib$*_init -fPIC -c -o $@ $<;
