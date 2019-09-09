#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <asm/uaccess.h>
#include <linux/errno.h>

#include "veriexec.h"

#define CMDSIZE 4096
#define SIGSIZE 16

static DEFINE_HASHTABLE(sigTable, SIGSIZE); //32 might be big as it makes the amount of buckets 2^32


//this is the hashtable we are using to store signatures
//this isnt defined correctly, I will figure out how to do that, it its literally the amount of bits we can use 
//like if I have 3 bits I can have 8 buckets as 2^3 or 2^n


MODULE_LICENSE("LSD");
MODULE_AUTHOR("ElfMaster and TrevorG");


		//til I find a better way to derive a key
static struct proc_dir_entry *ent;

static ssize_t
recv_veriexec_cmd(struct veriexec_object *file, const char __user *ubuf,
    size_t count, loff_t *ppos)
{

	char *p = strchr(ubuf, ' ');//when calculating position of spaces, there will be an edge
	//case where a path can have a space, account for that after it works with spaceless paths
    *p = 0;
	//strchr for first space and then putt a null byte and then 
	
    if (strcmp(ubuf, "EXEC")==0) {
    	file->type = VERIEXEC_OBJ_EXEC;
   	}else if (strcmp(ubuf, "SO")==0){
 		file->type = VERIEXEC_OBJ_SO;
    }else if (strcmp(ubuf, "FILE")==0){
		file->type = VERIEXEC_OBJ_FILE;
    }else if (strcmp(ubuf, "EXTERNAL")==0){
 		file->type = VERIEXEC_OBJ_EXTERNAL;
    }else if (strcmp(ubuf, "SCRIPT")==0){//turn these to n functions for SECURITY
 		file->type = VERIEXEC_OBJ_SCRIPT;
 	}else{
 		printk("Type is incorrect");
 		return -1;
 	}
 	p++;//this is incorrect but will compile for now, need ignore everything after stirng found and see if there is 1 or 2 spaces
 	if((*p+1)==' '){
 		printk("there was an extra space");//this is debug and will remove later
 		p++;
 	}
 	*p = strchr(ubuf, ' ');
 	int *prev = p;
 	*p = strchr(ubuf, ' ');
 	if(sizeof(prev) > 4096 && sizeof(prev) <1){
 		printk("path size is either to long or to short");
 	} else{
 		file->filepath=prev;//we verify this later
 	}
 	
 	
 	int *prev = p;
 	*p = strchr(ubuf, ' ');
 	file->hash_sum = prev;

 	if(strcmp(ubuf, "DIRECT")==0){
 		file->flag = DIRECT;//I dont know if we created flags for this yet so ill leave as is but this wont compile
 	} else if(strcmp(ubuf, "INDIRECT")==0){
 		file->flag = INDIRECT;
 	}
 	int *prev = p;
 	*p = strchr(ubuf, ' ');

 	//eventually we'll have the path set and see if its there
 	fp = filp_open(file->filepath, O_RDONLY, 0); // lets open file
	procfs_buffer_size = count;//dont know if I need this for sure, will delete if necessary
	hlnSize = kmalloc(sizeof(struct hlist_node *), GFP_KERNEL); //hashlistnodeSize


	if(fp == NULL) {	//and then check to see if its there
     	printk("was not able to open signature file\n"); 
    	return -1;
    }else{
    	file->filepath=prev;//we verify this later
    }


    if (procfs_buffer_size > PROCFS_MAX_SIZE ) { //verify size is correct
		procfs_buffer_size = PROCFS_MAX_SIZE;
	}
 	hash_add(sigTable, hlnSize, &file->hash_table, file->hash_sum/*we need a way to derive a key*/);//actually key is gonna be the signature

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
	//char *p = ubuf;
	//while (*p != 0x20)
	//while (*p){
	//	if(*p != 0x20)
	//		file->key = key;//this will be removed
	//		hash_add(sigTable, hlnSize, &file->hash_table, file->key/*we need a way to derive a key*/);
	//		key++;//this will be removed
	//		p++;
	//	}
	//
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
