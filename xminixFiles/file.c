/*
Lucas Bonin                RA: 13809082

Hyago Hirai                RA: 13212980

Rodolfo Dalla Costa        RA: 13210919

Robson Quero               RA: 15124423

Rubens Canivezo Soares     RA: 12649190

Samuel Biazotto            RA: 13809199  
*/


/*
 *  linux/fs/minix/file.c
 *
 *  Copyright (C) 1991, 1992 Linus Torvalds
 *
 *  minix regular file handling primitives
 */

#include "minix.h"

// Custom Libs

#include <linux/slab.h> 
#include <linux/stat.h>
#include <linux/fcntl.h>
#include <linux/file.h>
#include <linux/uio.h>
#include <linux/fsnotify.h>
#include <linux/security.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/pagemap.h>
#include <linux/splice.h>
#include <asm/uaccess.h>
#include <asm/unistd.h>
#include <linux/crypto.h>
#include <linux/err.h>
#include <linux/scatterlist.h>
#include <linux/string.h>
#include <linux/init.h>           // Mark up functions e.g. __init __exit
#include <linux/module.h>         // Core header for loading LKMs into the kernel
#include <linux/device.h>         // Header to support the kernel Driver Model
#include <linux/kernel.h>         // Contains types, macros, functions for the kernel
#include <linux/fs.h>             // Header for the Linux file system support
#include <asm/uaccess.h>          // Required for the copy to user function
#include <linux/mutex.h>          // Required for the mutex functionality
#include <linux/stat.h>

#define  CRYPTO_BUFFER_SIZE 32

static char  *cryptoKey = "key_default";
module_param(cryptoKey, charp, S_IRUGO);
u8 dest[CRYPTO_BUFFER_SIZE];

//Prototype
ssize_t do_read(struct file *filp, char __user *buf, size_t len, loff_t *ppos);
ssize_t do_write(struct file *filp, char __user *buf, size_t len, loff_t *ppos);


/*
 * We have mostly NULLs here: the current defaults are OK for
 * the minix filesystem.
 */
const struct file_operations minix_file_operations = {
	.llseek		= generic_file_llseek,
	.read		= do_read, // Changed
	.aio_read	= generic_file_aio_read,
	.write		= do_write, // Changed
	.aio_write	= generic_file_aio_write,
	.mmap		= generic_file_mmap,
	.fsync		= generic_file_fsync,
	.splice_read	= generic_file_splice_read,
};

static int minix_setattr(struct dentry *dentry, struct iattr *attr)
{
	struct inode *inode = dentry->d_inode;
	int error;

	error = inode_change_ok(inode, attr);
	if (error)
		return error;

	if ((attr->ia_valid & ATTR_SIZE) &&
	    attr->ia_size != i_size_read(inode)) {
		error = vmtruncate(inode, attr->ia_size);
		if (error)
			return error;
	}

	setattr_copy(inode, attr);
	mark_inode_dirty(inode);
	return 0;
}

const struct inode_operations minix_file_inode_operations = {
	.truncate	= minix_truncate,
	.setattr	= minix_setattr,
	.getattr	= minix_getattr,
};

// Custom Functions
static void wait_on_retry_sync_kiocb(struct kiocb *iocb)
{
	set_current_state(TASK_UNINTERRUPTIBLE);
	if (!kiocbIsKicked(iocb))
		schedule();
	else
		kiocbClearKicked(iocb);
	__set_current_state(TASK_RUNNING);
}

ssize_t do_read(struct file *filp, char __user *buf, size_t len, loff_t *ppos)
{
	printk(KERN_ALERT "Teste - Lendo o filesystem\n");

	struct iovec iov = { .iov_base = buf, .iov_len = len };
	struct kiocb kiocb;
	ssize_t ret;
    	int i;

	init_sync_kiocb(&kiocb, filp);
	kiocb.ki_pos = *ppos;
	kiocb.ki_left = len;
	kiocb.ki_nbytes = len;

	for (;;) {
		ret = filp->f_op->aio_read(&kiocb, &iov, 1, kiocb.ki_pos);
		if (ret != -EIOCBRETRY)
			break;
		wait_on_retry_sync_kiocb(&kiocb);
	}

	if (-EIOCBQUEUED == ret)
		ret = wait_on_sync_kiocb(&kiocb);
	*ppos = kiocb.ki_pos;

	printk(KERN_INFO "Valor do ppos: %lld", *ppos);
    
	/*Begin Decrypto */

    	u8 key[CRYPTO_BUFFER_SIZE]; 
    	memcpy(key, cryptoKey, sizeof(cryptoKey));

    	struct crypto_cipher *tmf;
    	u8 dest2[CRYPTO_BUFFER_SIZE];

    	tmf = crypto_alloc_cipher("aes", 4, 32);
    	crypto_cipher_setkey(tmf, key, 32);

    	crypto_cipher_decrypt_one(tmf, dest2, dest); 
    	crypto_cipher_decrypt_one(tmf, &dest2[16], &dest[16]);

    	crypto_free_cipher(tmf); 
	
	/* End Decrypto */
    	
	for(i = 0; i < strlen(dest2) ; i++) {
		printk(KERN_INFO "DECRYPT: %c\n", dest2[i] ); // Print conteudo decriptado criado
    	}
    
	return ret;
}

ssize_t do_write(struct file *filp, char __user *buf, size_t len, loff_t *ppos)
{
    u8 key[CRYPTO_BUFFER_SIZE];
    struct crypto_cipher *tmf;
    u8 dest2[CRYPTO_BUFFER_SIZE];
    char src[CRYPTO_BUFFER_SIZE];
    int i;
    
    // Setup key
    printk(KERN_INFO "%s", cryptoKey);
    memcpy(key, cryptoKey, sizeof(cryptoKey));
    
    /* Begin Crypto */
    sprintf(src, "%s", buf); // Change message text
    tmf = crypto_alloc_cipher("aes", 4, 32);
    crypto_cipher_setkey(tmf, key, 32);
    
    crypto_cipher_encrypt_one(tmf, dest, src);
    crypto_cipher_encrypt_one(tmf, &dest[16], &src[16]);
    
    for(i = 0; i < 32 ; i++) {
        printk(KERN_INFO "CRYPT: %02x\n", dest[i]); // Print cripto created
    }
    
    crypto_cipher_decrypt_one(tmf, dest2, dest);
    crypto_cipher_decrypt_one(tmf, &dest2[16], &dest[16]);

    for(i = 0; i < strlen(dest2) ; i++) {
        printk(KERN_INFO "DECRYPT: %c\n", dest2[i]); // Print msg decripted
    }
    
    crypto_free_cipher(tmf);

    /* End Cryppto */

    memcpy(buf, dest, sizeof(dest));
    
    printk(KERN_INFO "Valor do len: %d", len);
    printk(KERN_INFO "Valor do ppos: %lld", *ppos);
    
    // Write
    struct iovec iov = { .iov_base = (void __user *)buf, .iov_len = len };
    struct kiocb kiocb;
    ssize_t ret;
    
    init_sync_kiocb(&kiocb, filp);
    kiocb.ki_pos = *ppos;
    kiocb.ki_left = len;
    kiocb.ki_nbytes = len;

    for (;;) {
	ret = filp->f_op->aio_write(&kiocb, &iov, 1, kiocb.ki_pos);
	if (ret != -EIOCBRETRY)
	    break;
	wait_on_retry_sync_kiocb(&kiocb);
    }

    if (-EIOCBQUEUED == ret)
	ret = wait_on_sync_kiocb(&kiocb);
    *ppos = kiocb.ki_pos;
    
    return ret;
}


