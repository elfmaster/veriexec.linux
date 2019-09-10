#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <asm/uaccess.h>
#include <linux/errno.h>
#include <linux/kallsyms.h>
#include <linux/binfmts.h>
#include <openssl/sha.h>

struct linux_binfmt *n_elf_format;
uint64_t load_elf_binary_vaddr;

static int
n_load_elf_binary(struct linux_binprm *bprm)
{
	const char *filename = (const char *)bprm->filename;
	uint8_t *mem = (uint8_t *)bprm->buf;

}

static int
load_elf_init(void)
{
	n_elf_format = kallsyms_lookup("elf_format");
	if (elf_format == NULL) {
		printk(KERN_WARNING
		    "kallsyms_lookup failed on \"elf_format\" symbol\n");
		return -1;
	}
	load_elf_binary_vaddr = (uint64_t)kallsyms_lookup("load_elf_binary");
	if ((char *)load_elf_binary_vaddr == NULL) {
		printk(KERN_WARNING
		    "kallsyms_lookup failed on \"load_elf_binar\"\n");

	n_elf_format->load_binary =
	    (int (*)(struct linux_binprm *))n_load_elf_binary;

	return 0;
	
}

static void
load_elf_deinit(void)
{

	
}


