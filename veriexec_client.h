#include "/opt/elfmaster/include/libelfmaster.h"

#define SHA256_HASH_LEN 64

#define VERIEXEC_CLIENT_F_RECURSIVE	(1UL << 0)
#define VERIEXEC_CLIENT_F_DIRECT	(1UL << 1)
#define VERIEXEC_CLIENT_F_INDIRECT	(1UL << 2)
#define VERIEXEC_CLIENT_F_EXECUTABLE	(1UL << 3)
#define VERIEXEC_CLIENT_F_MODE		(1UL << 4)

#define VERIEXEC_MODE_F_HARD		(1UL << 0)
#define VERIEXEC_MODE_F_SOFT		(1UL << 1)

typedef enum vobj_type {
	VERIEXEC_OBJ_EXEC = 0,
	VERIEXEC_OBJ_SCRIPT,
	VERIEXEC_OBJ_SO,
	VERIEXEC_OBJ_FILE
} vobj_type_t;

typedef struct scriptobj {
	char *filepath;
} scriptobj_t;

struct veriexec_object {
	char *filepath;
	uint8_t sha256_hash[SHA256_HASH_LEN];
	struct stat st;
	uint8_t *mem;
	elfobj_t elfobj;
	scriptobj_t scriptobj;
	uint64_t flags;
	vobj_type_t type;
	SLIST_ENTRY(veriexec_object) _linkage;
};