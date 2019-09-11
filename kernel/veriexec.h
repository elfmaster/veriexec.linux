#define VERIEXEC_STATE_INACTIVE (1UL << 0)
#define VERIEXEC_STATE_ACTIVE	(1UL << 1)
#define VERIEXEC_STATE_LOCKED	(1UL << 2)
#define VERIEXEC_STATE_ENFORCE	(1UL << 3)

#define VERIEXEC_F_DIRECT	(1ULL << 0)
#define VERIEXEC_F_INDIRECT	(1ULL << 1)

#define SHA256_HASH_LEN 64


typedef enum vobj_type {
	VERIEXEC_OBJ_EXEC = 0,
	VERIEXEC_OBJ_SCRIPT,
	VERIEXEC_OBJ_SO,
	VERIEXEC_OBJ_FILE,
	VERIEXEC_OBJ_EXTERNAL /* For external execution launching */
} vobj_type_t;

typedef enum vobj_flag {
	VERIEXEC_OBJ_DIRECT = 0,
	VERIEXEC_OBJ_INDIRECT /* For external execution launching */
} vobj_flag_t;
//need stucture for
typedef struct veriexec_object {
	char hash_sum[SHA256_HASH_LEN];
	uint64_t flag; //set to direct of indirect
	char *filepath;
	uint64_t type;
	struct rhash_head linkage; //this is for rhash, dont know whether I want to keep it or not, leaving for testing
	struct hlist_node hash_table; //im leaving this but this is a bad variable name
									//confusing calling a node a table
} veriexec_object_t;

static inline
char *veriexec_obj_filepath(veriexec_object_t *obj)
{

	return obj->filepath;
}
// 
/*parse first entry is it shared external exec or whatever,
set the type value to the struct member

*/
