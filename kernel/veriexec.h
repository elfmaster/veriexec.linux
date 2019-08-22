#define VERIEXEC_STATE_INACTIVE (1UL << 0)
#define VERIEXEC_STATE_ACTIVE	(1UL << 1)
#define VERIEXEC_STATE_LOCKED	(1UL << 2)
#define VERIEXEC_STATE_ENFORCE	(1UL << 3)

#define VERIEXEC_F_DIRECT	(1ULL << 0)
#define VERIEXEC_F_INDIRECT	(1ULL << 1)

#define SHA256_HASH_LEN 64

typedef struct veriexec_object {
	char hash_sum[SHA256_HASH_LEN];
	uint64_t flag;
	char *filepath;
	struct hlist_node hash_table;
} veriexec_object_t;

static inline
char *veriexec_obj_filepath(veriexec_object_t *obj)
{

	return obj->filepath;
}

