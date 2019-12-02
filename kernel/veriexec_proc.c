#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <linux/types.h> //dont think I need this anymore
#include <linux/hashtable.h>//some stuff here might not be needed will comb through later

#include "veriexec.h"
#define SHA256_HASH_LEN 64
//#define CMDSIZE 4096
//#define SIGSIZE (16)

DEFINE_HASHTABLE(sigTable, 8); //32 might be big as it makes the amount of buckets 2^32

//hash_init(sigTable);
//this is the hashtable we are using to store signatures
//this isnt defined correctly, I will figure out how to do that, it its literally the amount of bits we can use 
//like if I have 3 bits I can have 8 buckets as 2^3 or 2^n


MODULE_LICENSE("LSD");
MODULE_AUTHOR("ElfMaster and TrevorG");

static struct proc_dir_entry *ent;

static ssize_t
recv_veriexec_cmd(struct file *file, const char *ubuf,
    size_t count, loff_t *off)//ubuf used to be a const however i do manipulations to it so i changed it away might add it back
{
	struct veriexec_object * vobj;
	vobj =(struct veriexec_object*)kmalloc(sizeof(struct veriexec_object),GFP_KERNEL);
	char *p = ubuf;
	char *prev;
	size_t dist = 0;//ill fix this when i fix the flags but I forgetto set a vlaue before the heck therefore the first strncpy is size undefined
	int flag = 0; //bad way of doing this, will fix later
	while(*p != '\0'){
	//while(flag<6){//i will change this had to change for debug reasons
		flag++;
		printk(KERN_DEBUG "the flag is %d",flag);
		printk(KERN_DEBUG "inside the fuqin function bitch where p is %s and dist = %zu\n",p,dist);

		if(*p==' '){//will eventually throw out other shit we dont need besides spaces
			*prev = p;
			dist = p-prev;//nick would kill me
			//dist = *p-*prev-1;//i am sure it the one above just check vals
			printk("%zu is 2diff of ptrs", dist);//this is debug, remove later
			while(*p++ == ' '){//looks for extra spaces, make sure you copy stings based off of prev not p
				printk("there was an extra space");
				*p++;
				printk(KERN_DEBUG "pointer value p is = %d", *p);
			}
		}
		printk(KERN_DEBUG "checkin dist b4 flag sit = %zu",dist);
		if(flag == 1){
			printk(KERN_DEBUG "flag 1 precompare where p = %s and dist is %ld",p, dist);
			if (strncmp(p, "EXEC", dist)==0) {
				printk(KERN_DEBUG "flag 1 post compare strncmp success");
    			vobj->type = VERIEXEC_OBJ_EXEC;
				printk(KERN_DEBUG "is it even hitting this");
				printk(KERN_DEBUG "vobj is %lld ",vobj->type);
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
			printk(KERN_DEBUG "flag 2 is set");
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
 			if(dist == SHA256_HASH_LEN){
 				strncpy(prev,vobj->hash_sum,dist);
 			} else {
 				printk("the signature size is incorrect");
 				return -1;
 			}

		} else if(flag==4){
			if(strncmp(p, "DIRECT",dist)==0){
 				vobj->flag = VERIEXEC_OBJ_DIRECT;//I dont know if we created flags for this yet so ill leave as is but this wont compile
 			} else if(strncmp(p, "INDIRECT",dist)==0){
 				vobj->flag = VERIEXEC_OBJ_INDIRECT;
 			} else {
 				printk("incorrect flag");
 				return -1;
 			}

		} else if(flag==5){
			file = filp_open(vobj->filepath, O_RDONLY, 0); // lets open file
		//int * hlnSize = kmalloc(sizeof(struct hlist_node), GFP_KERNEL); //hashlistnodeSize


			if(file == NULL) {	//and then check to see if its there
     			printk("was not able to open signature file\n"); 
    		return -1;
    		}else{
    			vobj->filepath=prev;//we verify this later
    		}

 		//hash_add(sigTable, hlnSize, &vobj->hash_table, vobj->hash_sum);//actually key is gonna be the signature
			hash_add(sigTable, &vobj->hash_table, *vobj->hash_sum);//seen it used with bits but when I looked at code doesnt use bits?
			return 0;
		}
	
	}
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
	hash_init(sigTable);
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
