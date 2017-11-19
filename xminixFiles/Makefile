#Lucas Bonin                RA: 13809082

#Hyago Hirai                RA: 13212980

#Rodolfo Dalla Costa        RA: 13210919

#Robson Quero               RA: 15124423

#Rubens Canivezo Soares     RA: 12649190

#Samuel Biazotto            RA: 13809199




obj-m += minix.o

minix-objs := bitmap.o dir.o file.o inode.o itree_v1.o itree_v2.o namei.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) clean

