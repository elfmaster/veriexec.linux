#define _GNU_SOURCE

#include <assert.h>
#include <fcntl.h>
#include <limits.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/queue.h>
#include <sys/stat.h>
#include <unistd.h>

#include "veriexec_client.h"

#define MAX_CACHE_SIZE 64000

/*
 * Userland application to send formatted parameters to /proc/veriexec
 * Examples:
 * For ELF shared libraries and interpreted scripts
 * FILE /path/to/file INDIRECT
 *
 * For ELF executable binaries
 * FILE /path/to/file DIRECT
 */

SLIST_HEAD(vobj_list, veriexec_object) vobj_list;
struct hsearch_data path_cache;

bool
vexec_process_indirect(char *filename, elfobj_t *elfobj, scriptobj_t *scriptobj,
    vobj_type_t *vobj)
{

	return true;
}

bool
vexec_client_apply_file(char *filename, uint64_t flags)
{
	struct veriexec_object *vobj = NULL;
	struct stat st;
	elfobj_t elfobj;
	elf_error_t error;
	scriptobj_t scriptobj;
	int fd;
	ENTRY e, *ep;
	char realpath[PATH_MAX + 1];
	SHA256_CTX ctx;

	if (readlink(filename, realpath, PATH_MAX) < 0) {
		perror("readlink");
		return false;
	}

	e.key = realpath;
	e.data = (char *)realpath;

	/*
	 * If hsearch_r returns non zero during our
	 * FIND lookup then we know that it found
	 * the path. If a path is already memoized we
	 * don't want to duplicate it.
	 */
	if (hsearch_r(e, FIND, &ep, &path_cache) != 0)
		return true;

	/*
	 * Let's memoize this path.
	 */
	if (hsearch_r(e, ENTER, &ep, &path_cache) == 0) {
		perror("hsearch_r");
		return false;
	}

	/*
	 * Lets fill in the parts of the vexec_obj
	 * that we are able too initially.
	 */
	vobj = calloc(1, sizeof(*vobj));
	if (vobj == NULL) {
		perror("calloc");
		return false;
	}
	vobj->filepath = strdup(realpath);
	if (vobj->filepath == NULL) {
		perror("strdup");
		return false;
	}
	fd = open(realpath, O_RDONLY);
	if (fd < 0) {
		perror("open");
		return false;
	}
	if (fstat(fd, &vobj->st) < 0) {
		perror("fstat");
		return false;
	}
	vobj->flags = flags;

	if (flags & VERIEXEC_CLIENT_F_INDIRECT) {
		bool res;

		vobj = calloc(1, sizeof(*vobj));
		if (vobj == NULL) {
			perror("calloc");
			return false;
		}
		res = vexec_process_indirect(filename, &elfobj,
		    &scriptobj, &vobj->type);
		if (res == false) {
			fprintf(stderr, "Failed to process indirect file: %s\n",
			    filename);
			return false;
		}
		memcpy(&vobj->scriptobj, &scriptobj, sizeof(scriptobj));

		SHA256_Init(&ctx);
		SHA256_Update(&ctx, vobj->mem, vobj->st.st_size);
		SLIST_INSERT_HEAD(&vobj_list, vobj, _linkage);
	}
	/*
	 * If VERIEXEC_CLIENT_F_INDIRECT is not set then we should have
	 * VERIEXEC_CLIENT_F_DIRECT set, and thus never evaluate this
	 * assert as true.
	 */
	assert(flags & VERIEXEC_CLIENT_F_DIRECT);

	if (elf_open_object(filename, &elfobj, ELF_LOAD_F_STRICT,
	    &error) == false) {
		perror("elf_open_object");
		return false;
	}
	memcpy(&vobj->elfobj, &elfobj, sizeof(elfobj));
	SHA256_Init(&ctx);
	/*
	 * XXX not suppose to access opaque type elfobj_t
	 * directly, must add accessor function to libelfmaster.
	 */
	SHA256_Update(&ctx, elfobj.mem, elf_size(&elfobj));
	SLIST_INSERT_HEAD(&vobj_list, vobj, _linkage);
fail:
	free(vobj);
	return false;
}

int
main(int argc, char **argv)
{
	struct veriexec_object obj;
	char *filename, *filedir;
	uint64_t action = 0, mode = 0;
	int c;

	if (argc < 3) {
		fprintf(stderr, "Usage: %s [-merdi] <dir|executable>\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	memset(&obj, 0, sizeof(obj));

	while ((c = getopt(argc, argv, "m:e:r:di")) != -1) {
		switch(c) {
		case 'r':
			/*
			 * Tells this application to apply to files
			 * in a directory recurisvely. NOTE: This flag
			 * is not passed into /proc/veriexec
			 */
			action |= VERIEXEC_CLIENT_F_RECURSIVE;
			filedir = strdup(optarg);
			if (filedir == NULL) {
				perror("strdup");
				exit(EXIT_FAILURE);
			}
			break;
		case 'd':
			action |= VERIEXEC_CLIENT_F_DIRECT;
			filename = strdup(optarg);
			if (filename == NULL) {
				perror("strdup");
				exit(EXIT_FAILURE);
			}
			break;
		case 'i':
			action |= VERIEXEC_CLIENT_F_INDIRECT;
			filename = strdup(optarg);
			if (filename == NULL) {
				perror("strdup");
				exit(EXIT_FAILURE);
			}
			break;
		case 'm':
			if (strcmp(optarg, "hard") == 0) {
				mode = VERIEXEC_MODE_F_HARD;
			} else if (strcmp(optarg, "soft") == 0) {
				mode = VERIEXEC_MODE_F_SOFT;
			} else {
				printf("mode '%s' unknown, use hard or soft\n", optarg);
			}
			action |= VERIEXEC_CLIENT_F_MODE;
			break;
		default:
			fprintf(stderr, "Unknown option: -%c\n", c);
			break;
		}
	}
	if ((action & VERIEXEC_CLIENT_F_DIRECT) && (action & VERIEXEC_CLIENT_F_INDIRECT)) {
		fprintf(stderr, "Cannot use the -d and -i option simultaneously\n");
		exit(EXIT_FAILURE);
	}
	
	if (hcreate_r(MAX_CACHE_SIZE, &path_cache) == 0) {
		perror("hcreate_r");
		exit(EXIT_FAILURE);
	}

}
