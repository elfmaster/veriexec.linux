#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include "veriexec_client.h"

int main(int argc, char **argv)
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
	
}
