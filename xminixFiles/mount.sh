#!/bin/bash
echo "criar arquivo de sistemas"
dd if=/dev/zero of=file.img bs=1k count=10000
echo "transformar file.img em um arquivo de bloco"
losetup /dev/loop0 file.img
echo "montando sistema de arquivo minix no arquivo file.img"
mkfs.minix -c /dev/loop0 10000

