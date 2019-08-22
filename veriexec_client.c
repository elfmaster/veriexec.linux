#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>

int main(int argc, char **argv)
{
	struct veriexec_object obj;
	uint64_t action = 0;
	int c;

	if (argc < 3) {
		fprintf(stderr, "Usage: %s [-erdi] <dir|executable>\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	memset(&ac, 0, sizeof(obj));

	while ((c = getopt(argc, argv "e:r:di")) != -1) {
		switch(c) {
		case 'r':
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
		default:
			fprintf(stderr, "Unknown option: -%c\n", c);
			break;
		}
	}

	if ((action & VERIEXEC_CLIENT_F_DIRECT) && (action & VERIEXEC_CLIENT_F_INDIRECT)) {
		fprintf(stderr, "Cannot use the -d and -i option simultaneously\n");
		exit(EXIT_FAILURE);
	}
}
