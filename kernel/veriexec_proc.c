#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <asm/uaccess.h>
#include <linux/errno.h>
#include <linux/types.h> 

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
recv_veriexec_cmd(struct file *file, const char __user *ubuf,
    size_t count, loff_t *ppos)
{
	struct veriexec_object * vobj;
	char *p = ubuf;
	char *prev;
	size_t dist;
	int flag = 0; //bad way of doing this, will fix later
	while(p){
	flag++;
	if(*p==0x20){//will eventually throw out other shit we dont need besides spaces
		*prev = *p;
		dist = *prev-*p-1;//nick would kill me
		printk("%zu is diff of ptrs", dist);
		while((*p+1)==0x20){//looks for extra spaces, make sure you copy stings based off of prev not p
			printk("there was an extra space");
			*p=*p+1;
		}
	}
	if(flag == 1){
		if (strncmp(p, "EXEC", dist)==0) {
    		vobj->type = VERIEXEC_OBJ_EXEC;
   		}else if (strncmp(prev, "SO", dist)==0){
 			vobj->type = VERIEXEC_OBJ_SO;
    	}else if (strncmp(prev, "FILE", dist)==0){
			vobj->type = VERIEXEC_OBJ_FILE;
	    }else if (strncmp(prev, "EXTERNAL", dist)==0){
 			vobj->type = VERIEXEC_OBJ_EXTERNAL;
    	}else if (strncmp(prev, "SCRIPT", dist)==0){//turn these to n functions for SECURITY
 			vobj->type = VERIEXEC_OBJ_SCRIPT;
 		}else{
 			printk("Type is incorrect");
 			return -1;
 		}
	} else if(flag == 2){
		if(dist > 4096 && dist <1){
 			printk("path size is either to long or to short");
 			return -1;
 		} else{
 			strncpy(prev,vobj->filepath,dist);
 			//we verify this later
 		}
 	} else if(flag==3){
 		//need to handle signature
 		//will add things in to verify signature size later
 		strncpy(prev,vobj->hash_sum,dist);

	} else if(flag==4){
		if(strncmp(p, "DIRECT",dist)==0){
 			vobj->flag = DIRECT;//I dont know if we created flags for this yet so ill leave as is but this wont compile
 		} else if(strncmp(p, "INDIRECT",dist)==0){
 			vobj->flag = INDIRECT;
 		} else {
 			printk("incorrect flag");
 			return -1;
 		}

	} else if(flag==5){
		file = filp_open(vobj->filepath, O_RDONLY, 0); // lets open file
		hlnSize = kmalloc(sizeof(struct hlist_node *), GFP_KERNEL); //hashlistnodeSize


		if(file == NULL) {	//and then check to see if its there
     		printk("was not able to open signature file\n"); 
    		return -1;
    	}else{
    		vobj->filepath=prev;//we verify this later
    	}

 		hash_add(sigTable, hlnSize, &vobj->hash_table, vobj->hash_sum);//actually key is gonna be the signature
		return 0;
	}
	
}
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
