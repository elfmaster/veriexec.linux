#include "/opt/elfmaster/include/libelfmaster.h"

#define SHA256_HASH_LEN 64

#define VERIEXEC_CLIENT_F_RECURSIVE	(1UL << 0)
#define VERIEXEC_CLIENT_F_DIRECT	(1UL << 1)
#define VERIEXEC_CLIENT_F_INDIRECT	(1UL << 2)
#define VERIEXEC_CLIENT_F_EXECUTABLE	(1UL << 3)

struct veriexec_linux {
	char *filepath;
	uint8_t sha256_hash[SHA256_HASH_LEN];
	struct stat st;
	uint8_t *mem;
	elfobj_t *elfobj;
	uint64_t flags;
	SLIST_ENTRY(veriexec_linux) _linkage;
};
