#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <asm/uaccess.h>
#include <linux/errno.h>

#include "veriexec.h"

#define CMDSIZE 4096

#define DEFINE_HASHTABLE(sigTable, 32) //32 might be big as it makes the amount of buckets 2^32


//this is the hashtable we are using to store signatures
//this isnt defined correctly, I will figure out how to do that, it its literally the amount of bits we can use 
//like if I have 3 bits I can have 8 buckets as 2^3 or 2^n


MODULE_LICENSE("LSD");
MODULE_AUTHOR("ElfMaster and TrevorG");

key = 0;//this is temporary and will not be used, I am just using it to test hashtable
		//til I find a better way to derive a key
static struct proc_dir_entry *ent;

static ssize_t
recv_veriexec_cmd(struct file *file, const char __user *ubuf,
    size_t count, loff_t *ppos)
{
	fp = filp_open(file->filepath, O_RDONLY, 0); // lets open file
	procfs_buffer_size = count;//dont know if I need this for sure, will delete if necessary
	hlnSize = kmalloc(sizeof(struct hlist_node *), GFP_KERNEL); //hashlistnodeSize


	if(fp == NULL) {	//and then check to see if its there
     	printk("was not able to open signature file\n"); 
    	return -1;
    }else{
    	
    }
    if (procfs_buffer_size > PROCFS_MAX_SIZE ) { //verify size is correct
		procfs_buffer_size = PROCFS_MAX_SIZE;
	}

	char *p = strchr(buf, ' ')
    *p = 0;
	//strchr for first space and then putt a null byte and then 
	
    if (strcmp(buf, "EXEC")==0) {
    	type = VERIEXEC_OBJ_EXEC;
   	}else if (strcmp(buf, "SO")==0){
 		type = VERIEXEC_OBJ_SO;
    }else if (strcmp(buf, "FILE")==0){
		type = VERIEXEC_OBJ_FILE;
    }else if (strcmp(buf, "EXTERNAL")==0){
 		type = VERIEXEC_OBJ_EXTERNAL;
    }else if (strcmp(buf, "SCRIPT")==0){//turn these to n functions for SECURITY
 		type = VERIEXEC_OBJ_SCRIPT;
 	}else{
 		printk("Type is incorrect");
 		return -1;
 	}
 	p++;
 	

	//this is similar to procwrite
	//similar to doing  aproc entry
	//like echo "FILE" /path/filename sha256hash indirect/direct(one of these)
 		//direct vs indirect is flag
	//return 0 for success
	// look at other proc return modules
	//instead of file, program
	//parse whatever string from ubuf, need size and maybe position
	//copy userbuf(ubuf) to kernel memory with copy from user into a char buf or whatever
	//path_max 4096+64 bytes for indirect for direct, this isbuffer size
	//return error if its not file
	//look for white spaces and other shit that we dont want
	//while dereference pointer =  space space
	//checkk veriexec.h
	//take this in and store in hashtable in kernel 
	//parse info and set flags in struct
	char *p = ubuf;
	//while (*p != 0x20)
	while (*p){}
		if(*p != 0x20)
			file->key = key;//this will be removed
			hash_add(sigTable, hlnSize, &file->hash_table, file->key/*we need a way to derive a key*/);
			key++;//this will be removed
			p++;
		}
	//global hash table
	//proc_create("signaturesVE",0,NULL,&proc_fops);
	//msg=kmalloc(10*sizeof(char).GFP_KERNEL);

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
