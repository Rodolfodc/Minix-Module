obj-$(CONFIG_MINIX_FS) += test.o

test-objs := bitmap.o dir.o file.o inode.o itree_v1.o itree_v2.o namei.o itree_commom.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) clean




