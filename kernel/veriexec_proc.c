#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <asm/uaccess.h>
#include <linux/errno.h>

#include "veriexec.h"

#define CMDSIZE 4096

MODULE_LICENSE("LSD");
MODULE_AUTHOR("ElfMaster");

static struct proc_dir_entry *ent;

static ssize_t
recv_veriexec_cmd(struct file *file, const char __user *ubuf,
    size_t count, loff_t *ppos)
{

	return -1;
}

static ssize_t
proc_read(struct file *file, char __user *ubuf, size_t count, loff_t *ppos)
{

	return -ENOTSUPP;
}

static struct file_operations fops = {
	.owner = THIS_MODULE,
	.read = proc_read,
	.write = recv_veriexec_cmd
};

static int 
veriexec_init(void)
{

	ent = proc_create("veriexec", 0600, NULL, &fops);
	return 0;
}

static void
veriexec_deinit(void)
{

	proc_remove(ent);
}

module_init(veriexec_init);
module_exit(veriexec_deinit);
