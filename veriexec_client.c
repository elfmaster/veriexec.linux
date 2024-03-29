/*
 * Authors: 2019
 * elfmaster - ryan@bitlackeys.org
 * trevor gould
 * Userland application to send formatted parameters to /proc/veriexec
 * Examples:
 * For ELF shared libraries and interpreted scripts
 * SHARED /path/to/file <sha256> INDIRECT
 * SCRIPT /path/to/file <sha256> INDIRECT
 * EXTERNAL /path/to/file <sha256> /path/to/application <sha256> DIRECT/INDIRECT
 *
 * For ELF executable binaries
 * EXEC /path/to/file <sha256> DIRECT
 */

#define _GNU_SOURCE

#include <assert.h>
#include <ctype.h>
#include <dirent.h>
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
#define CMD_SIZE 8192

#define PROC_ENTRY "/proc/veriexec"

SLIST_HEAD(vobj_list, veriexec_object) vobj_list;
struct hsearch_data path_cache;

bool
vexec_is_binary(uint8_t *mem, size_t len)
{
	int i;

	for (i = 0; i < len; i++) {
		if (!isprint(mem[i]))
			return true;
	}
	return false;
}

void
vexec_sha256hash_format(uint8_t *input, uint8_t *output)
{
	int i;

	for (i = 0; i < SHA256_DIGEST_LENGTH; i++) {
		sprintf(&output[i * 2], "%02x", input[i]);
	}
	return;
}

bool
vexec_write_vobj(struct veriexec_object *obj)
{
	int fd;
	char buf[CMD_SIZE];
	size_t len;
	ssize_t bytes;
	bool res = true;

	fd = open(PROC_ENTRY, O_WRONLY);
	if (fd < 0) {
		perror("open");
		exit(-1);
	}
	switch(obj->type) {
	case VERIEXEC_OBJ_EXEC:
		strcpy(buf, "EXEC ");
		if (strlen(obj->filepath) > PATH_MAX) {
			fprintf(stderr, "Invalid path length: %zu\n",
			    strlen(obj->filepath));
			close(fd);
			return false;
		}
		strcat(buf, obj->filepath);
		strcat(buf, " ");
		len = strlen("EXEC ") + strlen(obj->filepath) + strlen(" ");
		memcpy(&buf[len], obj->sha256_output, SHA256_HASH_LEN);
		buf[len + 1 + SHA256_HASH_LEN] = '\0';
		len = len + 1 + SHA256_HASH_LEN;
		len += strlen(" DIRECT");
		if (obj->flags & VERIEXEC_CLIENT_F_DIRECT) {
			strcat(buf, " DIRECT");
		} else {
			fprintf(stderr,
			    "INDIRECT flag is not compatible with executables\n");
			return false;
		}
		VEXEC_DEBUG("%s\n", buf);
		break;
	case VERIEXEC_OBJ_SCRIPT:
		strcpy(buf, "SCRIPT ");
		if (strlen(obj->filepath) > PATH_MAX) {
			fprintf(stderr, "Invalid path length: %zu\n",
			    strlen(obj->filepath));
			close(fd);
			return false;
		}
		strcat(buf, obj->filepath);
		strcat(buf, " ");
		len = strlen("SCRIPT ") + strlen(obj->filepath) + strlen(" ");
		memcpy(&buf[len], obj->sha256_output, SHA256_HASH_LEN);
		buf[len + 1 + SHA256_HASH_LEN] = '\0';
		len = len + 1 + SHA256_HASH_LEN;
		len += strlen(" INDIRECT");
		if (obj->flags & VERIEXEC_CLIENT_F_INDIRECT) {
			strcat(buf, " INDIRECT");
		} else {
			fprintf(stderr,
			    "DIRECT flag is not compatible with scripts\n");
			return false;
		}
		VEXEC_DEBUG("%s\n", buf);
		break;
	case VERIEXEC_OBJ_SO:
	case VERIEXEC_OBJ_FILE:
	case VERIEXEC_OBJ_EXTERNAL:
	default:
		break;
	}
	bytes = write(fd, buf, len);
	if (bytes < 0) {
		perror("write");
		res = false;
	}
	close(fd);
	return res;
}

size_t
vexec_build_path_string(char *filename, char *dirname, char *buf, size_t len)
{
	char *p, *q;

	size_t dlen = strlen(dirname);

	memset(buf, 0, len);
	if (dlen > len)
		return 0;
	memcpy(buf, dirname, dlen);
	p = strrchr(buf, '/');
	if (p == &buf[0]) {
		buf[dlen] = '/';
		dlen += 1;
	}
	if (strlen(filename) > len - (dlen + 1))
		return 0;
	memcpy(&buf[dlen], filename, strlen(filename));
	return strlen(buf);
}

void
print_hash(uint8_t *hash)
{
	int i = 0;

	for (i = 0; i < SHA256_DIGEST_LENGTH; i++) {
		printf("%02x", hash[i]);
	}
	printf("\n");
	return;
}

bool
vexec_process_indirect(char *filename, elfobj_t *elfobj, scriptobj_t *scriptobj,
    vobj_type_t *vobj)
{

	return true;
}

bool
vexec_client_apply_file(char *filename, uint64_t flags, uint64_t type)
{
	struct veriexec_object *vobj = NULL;
	struct stat st;
	elfobj_t elfobj;
	elf_error_t error;
	scriptobj_t scriptobj;
	int fd;
	ENTRY e, *ep;
	char path[PATH_MAX] = {0};
	SHA256_CTX ctx;

	printf("Filename for readlink: %s\n", filename);

	(void) lstat(filename, &st);

	if ((st.st_mode & S_IFMT) == S_IFLNK) {
		if (realpath(filename, path) == NULL) {
			perror("realpath");
			return false;
		}
		printf("readlinked: %s\n", path);
	} else {
		strncpy(path, filename, PATH_MAX);
		path[PATH_MAX - 1] = '\0';
	}
	(void) lstat(path, &st);

	e.key = path;
	e.data = (char *)path;

	printf("path: %s\n", path);
	/*
	 * If hsearch_r returns non zero during our
	 * FIND lookup then we know that it found
	 * the path. If a path is already memoized we
	 * don't want to duplicate it.
	 */
	if (hsearch_r(e, FIND, &ep, &path_cache) != 0) {
		printf("Entry for %s already exists\n", path);
		return true;
	}

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
	vobj->filepath = strdup(path);
	if (vobj->filepath == NULL) {
		perror("strdup");
		return false;
	}
	vobj->st = st;
	vobj->flags = flags;
	vobj->type = type;

	if (flags & VERIEXEC_CLIENT_F_INDIRECT) {
		bool res;
		int fd;

		res = vexec_process_indirect(path, &elfobj,
		    &scriptobj, &vobj->type);
		if (res == false) {
			fprintf(stderr, "Failed to process indirect file: %s\n",
			    filename);
			return false;
		}
		memcpy(&vobj->scriptobj, &scriptobj, sizeof(scriptobj));
		fd = open(path, O_RDONLY);
		if (fd < 0) {
			perror("open");
			return false;
		}
		vobj->mem = mmap(NULL, vobj->st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
		if (vobj->mem == MAP_FAILED) {
			perror("mmap");
			return false;
		}
		if (vexec_is_binary(vobj->mem, vobj->st.st_size) == true) {
			fprintf(stderr, "script file '%s' must be a text file\n", path);
			free(vobj);
			return false;
		}
		SHA256_Init(&ctx);
		SHA256_Update(&ctx, vobj->mem, vobj->st.st_size);
		SHA256_Final(vobj->sha256_hash, &ctx);
		vexec_sha256hash_format(vobj->sha256_hash, vobj->sha256_output);
		SLIST_INSERT_HEAD(&vobj_list, vobj, _linkage);
		munmap(vobj->mem, vobj->st.st_size);
		close(fd);
		return true;
	}
	/*
	 * If VERIEXEC_CLIENT_F_INDIRECT is not set then we should have
	 * VERIEXEC_CLIENT_F_DIRECT set, and thus never evaluate this
	 * assert as true.
	 */
	assert(flags & VERIEXEC_CLIENT_F_DIRECT);

	if (elf_open_object(path, &elfobj, ELF_LOAD_F_STRICT,
	    &error) == false) {
		/*
		 * It should only fail on rare cases like when it fails to
		 * notice a binary is statically linked (An occasional issue
		 * with libelfmaster. Or when it has invalid file magic
		 */
		return true;
	}
	SHA256_Init(&ctx);
	/*
	 * XXX not suppose to access opaque type elfobj_t
	 * directly, must add accessor function to libelfmaster.
	 */
	SHA256_Update(&ctx, elfobj.mem, elf_size(&elfobj));
	SHA256_Final(vobj->sha256_hash, &ctx);
	vexec_sha256hash_format(vobj->sha256_hash, vobj->sha256_output);
	SLIST_INSERT_HEAD(&vobj_list, vobj, _linkage);
	elf_close_object(&elfobj);
	print_hash(vobj->sha256_hash);
	return true;
fail:
	free(vobj);
	return false;
}

int
main(int argc, char **argv)
{
	struct veriexec_object obj;
	char *filepath = NULL;
	uint64_t action = 0, mode = 0, type = 0;
	DIR *dirp;
	struct dirent *entry;
	int c;
	bool res;
	struct veriexec_object *vobj;

	if (argc < 3) {
		fprintf(stderr, "Usage: %s [-merdi][-f executable || directory]\n",
		    argv[0]);
		exit(EXIT_FAILURE);
	}

	memset(&obj, 0, sizeof(obj));

	while ((c = getopt(argc, argv, "Ssm:e:r:dif:")) != -1) {
		switch(c) {
		case 's':
			type = VERIEXEC_OBJ_SCRIPT;
			break;
		case 'l': /* shared library */
			type = VERIEXEC_OBJ_SO;
			break;
		case 'r':
			/*
			 * Tells this application to apply to files
			 * in a directory recurisvely. NOTE: This flag
			 * is not passed into /proc/veriexec
			 */
			action |= VERIEXEC_CLIENT_F_RECURSIVE;
			break;
		case 'd':
			action |= VERIEXEC_CLIENT_F_DIRECT;
			break;
		case 'i':
			action |= VERIEXEC_CLIENT_F_INDIRECT;
			break;
		case 'm':
			if (strcmp(optarg, "hard") == 0) {
				mode = VERIEXEC_MODE_F_HARD;
			} else if (strcmp(optarg, "soft") == 0) {
				mode = VERIEXEC_MODE_F_SOFT;
			} else {
				printf("mode '%s' unknown."
				    " use hard or soft\n", optarg);
			}
			action |= VERIEXEC_CLIENT_F_MODE;
			break;
		case 'f':
			filepath = strdup(optarg);
			if (filepath == NULL) {
				perror("strdup");
				exit(EXIT_FAILURE);
			}
			break;
		default:
			fprintf(stderr, "Unknown option: -%c\n", c);
			break;
		}
	}
	if (filepath == NULL) {
		fprintf(stderr, "Use -f to specify a file or directory path\n");
		exit(EXIT_FAILURE);
	}

	if ((action & VERIEXEC_CLIENT_F_DIRECT) &&
	    (action & VERIEXEC_CLIENT_F_INDIRECT)) {
		fprintf(stderr,
		    "Cannot use the -d and -i option simultaneously\n");
		exit(EXIT_FAILURE);
	}

	if (hcreate_r(MAX_CACHE_SIZE, &path_cache) == 0) {
		perror("hcreate_r");
		exit(EXIT_FAILURE);
	}

	if ((action & VERIEXEC_CLIENT_F_RECURSIVE) == 0) {
		res = vexec_client_apply_file(filepath, action, type);
		goto done;
	}

	printf("Opening: %s\n", filepath);
	dirp = opendir(filepath);
	if (dirp == NULL) {
		perror("opendir");
		exit(EXIT_FAILURE);
	}
	for (;;) {
		char path[PATH_MAX + 1];

		entry = readdir(dirp);
		if (entry == NULL)
			break;

		if (strcmp(entry->d_name, ".") == 0 ||
		    strcmp(entry->d_name, "..") == 0)
			continue;
		if (vexec_build_path_string(entry->d_name, filepath, path,
		    PATH_MAX) == 0) {
			fprintf(stderr, "Failed to build path name\n");
			exit(EXIT_FAILURE);
		}
		res = vexec_client_apply_file(path, action, type);
		if (res == false) {
			fprintf(stderr, "vexec_client_apply failed\n");
			exit(EXIT_FAILURE);
		}
	}
done:

	SLIST_FOREACH(vobj, &vobj_list, _linkage) {
		vexec_write_vobj(vobj);
	}
	exit(EXIT_SUCCESS);
}
